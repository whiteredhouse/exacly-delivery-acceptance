"""Fixed, read-only owner-selection relay for the one PR5 hosted native trial.

This module cannot post comments or grant native authority. A human must paste
the exact command, and the same relay instance retains the complete read budget
through host validation and both independent owner selections.
"""
from __future__ import annotations

import copy
import datetime as dt
import enum
import hashlib
import hmac
import importlib.util
import json
import math
import re
import time
import urllib.error
import urllib.request
from pathlib import Path


API = "https://api.github.com"
REPOSITORY = "whiteredhouse/exacly-delivery-acceptance"
REPOSITORY_ID = 1442278205
OWNER_ID, OWNER_LOGIN = 1679024, "p1c2u"
PREFIX = "/repos/" + REPOSITORY
WORKFLOW = ".github/workflows/app-bootstrap.yml"
REF = "refs/heads/codex/preflight-diagnostics"
JOB = "native-positive-trial"
TITLE = "canary-bootstrap:native-positive-trial:pr-5"
COMMENTS = PREFIX + "/issues/5/comments?per_page=100"
MAX_READS, MAX_POLLS, MAX_SECONDS, POLL_SECONDS = 64, 25, 600, 20
MAX_HISTORY, MAX_BODY = 499, 1024 * 1024
UTC = dt.timezone.utc
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class RelayStopCode(enum.Enum):
    PERMANENT_STOP = "permanent_stop"
    CLOCK_INVALID = "clock_invalid"
    SUBMISSION_EXPIRED = "submission_expired"
    VERIFICATION_EXPIRED = "verification_expired"
    JOB_LIFETIME_EXPIRED = "job_lifetime_expired"
    CREDENTIAL_EXPIRED = "credential_expired"
    READ_BUDGET_EXHAUSTED = "read_budget_exhausted"
    READ_BUDGET_INSUFFICIENT = "read_budget_insufficient"
    POLL_BUDGET_EXHAUSTED = "poll_budget_exhausted"
    PROVIDER_READ_FAILED = "provider_read_failed"
    PROVIDER_RESPONSE_INVALID = "provider_response_invalid"
    INVENTORY_INVALID = "inventory_invalid"
    CHECKPOINT_INVALID = "checkpoint_invalid"
    PHASE_REUSED = "phase_reused"
    OWNER_DENIED = "owner_denied"
    SELECTION_AMBIGUOUS = "selection_ambiguous"
    SELECTION_CHANGED = "selection_changed"
    SELECTION_INVALID = "selection_invalid"
    HOST_VERIFICATION_FAILED = "host_verification_failed"


class RelayStopped(Exception):
    """A fixed safe reason; transport exception text is never forwarded."""

    def __init__(self, message, *, code=None):
        super().__init__(message)
        self.code = code


def safe_diagnostic(error):
    """Project only this module's exact owned exception and closed reason enum."""
    if type(error) is RelayStopped and type(error.code) is RelayStopCode:
        return {"component": "relay", "code": error.code.value}
    return {"component": "unknown", "code": "unclassified_failure"}


def _require(value, reason="invalid relay data", *, code=None):
    if not value:
        raise RelayStopped(reason, code=code)


def _positive(value):
    return type(value) is int and 0 < value < 2**63


def _utc(value):
    _require(isinstance(value, dt.datetime) and value.tzinfo is not None
             and value.utcoffset() == dt.timedelta(0), "invalid UTC deadline", code=RelayStopCode.CLOCK_INVALID)
    return value


def _stamp(value):
    return _utc(value).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _full_stamp(value):
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _full_date(value):
    _require(isinstance(value, str), "invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        _require(_full_stamp(parsed) == value, "invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID)
        return parsed
    except (ValueError, TypeError):
        raise RelayStopped("invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID) from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _date(value):
    _require(isinstance(value, str) and TIMESTAMP.fullmatch(value), "invalid server timestamp",
             code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise RelayStopped("invalid server timestamp", code=RelayStopCode.PROVIDER_RESPONSE_INVALID) from None


def _selection(value):
    _require(isinstance(value, dict), "invalid owner selection", code=RelayStopCode.SELECTION_INVALID)
    keys = {"phase", "run_id", "run_attempt", "challenge", "packet_digest",
            "issuer", "approval_id", "approval_digest"}
    if value.get("phase") == "merge":
        keys.add("identity_digest")
    _require(set(value) == keys and value.get("phase") in ("merge", "observe"),
             "invalid owner selection", code=RelayStopCode.SELECTION_INVALID)
    _require(_positive(value["run_id"]) and type(value["run_attempt"]) is int
             and value["run_attempt"] == 1 and value["issuer"] == OWNER_LOGIN,
             "invalid owner selection", code=RelayStopCode.SELECTION_INVALID)
    for name, pattern in (("challenge", HEX), ("packet_digest", DIGEST),
                          ("approval_digest", DIGEST), ("approval_id", WORD)):
        _require(isinstance(value[name], str) and pattern.fullmatch(value[name]),
                 "invalid owner selection", code=RelayStopCode.SELECTION_INVALID)
    if "identity_digest" in value:
        _require(isinstance(value["identity_digest"], str)
                 and DIGEST.fullmatch(value["identity_digest"]), "invalid owner selection",
                 code=RelayStopCode.SELECTION_INVALID)
    return copy.deepcopy(value)


def _selection_digest(selection):
    return "sha256:" + hashlib.sha256(_canonical(_selection(selection))).hexdigest()


def _command(selection, verb):
    value = _selection(selection)
    fields = [("phase", value["phase"]), ("run", value["run_id"]),
              ("attempt", value["run_attempt"]), ("challenge", value["challenge"]),
              ("packet", value["packet_digest"])]
    if value["phase"] == "merge":
        fields.append(("identity", value["identity_digest"]))
    fields.extend((("issuer", value["issuer"]), ("approval", value["approval_id"]),
                   ("approval-digest", value["approval_digest"])))
    return "/exacly-native-trial " + verb + " " + " ".join(key + "=" + str(item) for key, item in fields)


def approval_command(selection):
    """The exact one-line owner command; the assistant must never post it."""
    return _command(selection, "approve")


def deny_command(selection):
    """The exact same pinned selection with the abort-only deny verb."""
    return _command(selection, "deny")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def transport(method, url, headers, payload, timeout):
    """One bounded HTTPS GET, preserving the environment's proxy/CA support."""
    _require(method == "GET" and payload is None and url.startswith(API + PREFIX + "/"),
             "request outside fixed relay scope", code=RelayStopCode.PROVIDER_READ_FAILED)
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            _require(response.geturl() == url, "redirects are forbidden",
                     code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
            return response.status, response.read(MAX_BODY + 1), dict(response.headers)
    except Exception:
        raise RelayStopped("GitHub read failed", code=RelayStopCode.PROVIDER_READ_FAILED) from None


def _decode(body):
    def pairs(values):
        result = {}
        for key, value in values:
            _require(key not in result, "invalid bounded JSON", code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
            result[key] = value
        return result

    def constant(_):
        raise RelayStopped("invalid bounded JSON", code=RelayStopCode.PROVIDER_RESPONSE_INVALID)

    _require(type(body) is bytes and len(body) <= MAX_BODY, "invalid bounded JSON",
             code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except Exception:
        raise RelayStopped("invalid bounded JSON", code=RelayStopCode.PROVIDER_RESPONSE_INVALID) from None


def _protocol_module():
    path = Path(__file__).resolve().with_name("native_trial_protocol.py")
    _require(path.resolve() == path, "supplemental protocol source differs", code=RelayStopCode.HOST_VERIFICATION_FAILED)
    spec = importlib.util.spec_from_file_location("native_trial_protocol", path)
    _require(spec is not None and spec.loader is not None, "supplemental protocol source differs", code=RelayStopCode.HOST_VERIFICATION_FAILED)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Relay:
    def __init__(self, token, context, *, protocol=None, sender=None, clock=None, monotonic=None, sleep=None):
        _require(isinstance(token, str) and 0 < len(token) <= 4096
                 and not any(ord(character) < 33 or ord(character) > 126 for character in token),
                 "invalid relay credential", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        _require(isinstance(context, dict), "invalid hosted context", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        self.context = copy.deepcopy(context)
        _require(set(context) == {"repository", "repository_id", "source", "run_id", "run_attempt",
                                  "workflow_ref", "ref", "job"}
                 and context.get("repository") == REPOSITORY
                 and type(context.get("repository_id")) is int
                 and context["repository_id"] == REPOSITORY_ID
                 and isinstance(context.get("source"), str) and SHA.fullmatch(context["source"])
                 and _positive(context.get("run_id"))
                 and type(context.get("run_attempt")) is int and context["run_attempt"] == 1
                 and context.get("workflow_ref") == REPOSITORY + "/" + WORKFLOW + "@" + REF
                 and context.get("ref") == REF and context.get("job") == JOB,
                 "invalid hosted context", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        self._protocol_module = _protocol_module() if protocol is not None else None
        try:
            self.protocol = self._protocol_module.validate_protocol(protocol) if protocol is not None else None
        except (ValueError, TypeError, KeyError):
            raise RelayStopped("invalid supplemental protocol", code=RelayStopCode.HOST_VERIFICATION_FAILED) from None
        self._allocation = None
        self._token, self._sender = token, sender or transport
        self._clock = clock or (lambda: dt.datetime.now(UTC))
        self._monotonic, self._sleep = monotonic or time.monotonic, sleep or time.sleep
        self.reads = 0
        self._host_checked, self._failed = False, False
        self._phases = []
        self._phase_active = False
        self._created_monotonic = self._monotonic()
        self._created_at = _utc(self._clock())
        _require(type(self._created_monotonic) in (int, float)
                 and math.isfinite(self._created_monotonic) and self._created_monotonic >= 0,
                 "invalid relay clock", code=RelayStopCode.CLOCK_INVALID)
        self._last_monotonic, self._last_at = self._created_monotonic, self._created_at
        self._deadline = self._created_monotonic + MAX_SECONDS
        self._expires = self._created_at + dt.timedelta(seconds=MAX_SECONDS)
        self._pending_wait = None

    approval_command = staticmethod(approval_command)
    deny_command = staticmethod(deny_command)

    def export_state(self):
        """Checkpoint this relay between steps in the same continuously alive job.

        The coordinator must protect and consume each checkpoint once: replay of
        an older authentic checkpoint cannot be detected by a stateless process.
        The MAC prevents editing counters/context or moving to a different job
        token. Neither the ordinary token nor native authority is serialized.
        """
        _require(not self._failed and not self._phase_active and self._host_checked,
                 "stopped or incomplete relay cannot be checkpointed", code=RelayStopCode.CHECKPOINT_INVALID)
        self._job_live()
        if self._pending_wait is not None:
            self._live()
        payload = {"schema_version": "0.2.0", "kind": "fixed-native-relay-checkpoint",
                   "context": copy.deepcopy(self.context), "reads": self.reads,
                   "host_checked": self._host_checked, "phases": list(self._phases),
                   "created_at": _full_stamp(self._created_at),
                   "created_monotonic": self._created_monotonic,
                   "deadline_monotonic": self._deadline, "expires_at": _full_stamp(self._expires),
                   "last_at": _full_stamp(self._last_at), "last_monotonic": self._last_monotonic,
                   "pending_wait": copy.deepcopy(self._pending_wait)}
        if self.protocol is not None:
            _require(self._allocation is not None, "supplemental allocation must be selected first", code=RelayStopCode.CHECKPOINT_INVALID)
            payload.update(protocol=copy.deepcopy(self.protocol), allocation=copy.deepcopy(self._allocation))
        return {"payload": payload,
                "mac": hmac.new(self._token.encode("ascii"), _canonical(payload), hashlib.sha256).hexdigest()}

    @classmethod
    def restore(cls, token, context, state, *, protocol=None, sender=None, clock=None, monotonic=None, sleep=None):
        """Restore a protected one-shot checkpoint without resetting the budget."""
        client = cls(token, context, protocol=protocol, sender=sender, clock=clock, monotonic=monotonic, sleep=sleep)
        try:
            _require(isinstance(state, dict) and set(state) == {"payload", "mac"}
                     and isinstance(state["payload"], dict) and isinstance(state["mac"], str),
                     "invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID)
            value = state["payload"]
            expected = hmac.new(token.encode("ascii"), _canonical(value), hashlib.sha256).hexdigest()
            _require(hmac.compare_digest(expected, state["mac"]), "relay checkpoint integrity differs", code=RelayStopCode.CHECKPOINT_INVALID)
            keys = {"schema_version", "kind", "context", "reads", "host_checked", "phases",
                    "created_at", "created_monotonic", "deadline_monotonic", "expires_at",
                    "last_at", "last_monotonic", "pending_wait"}
            if protocol is not None:
                keys.update(("protocol", "allocation"))
            _require(set(value) == keys
                     and value["schema_version"] == "0.2.0" and value["kind"] == "fixed-native-relay-checkpoint"
                     and value["context"] == context and type(value["host_checked"]) is bool
                     and value["host_checked"] is True and type(value["reads"]) is int
                     and 4 <= value["reads"] <= MAX_READS
                     and value["phases"] in ([], ["merge"], ["merge", "observe"])
                     and value["reads"] >= 4 + 2 * len(value["phases"]), "invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID)
            if protocol is not None:
                _require(value["protocol"] == client.protocol and value["reads"] >= 5,
                         "supplemental relay checkpoint differs", code=RelayStopCode.CHECKPOINT_INVALID)
                try:
                    client._allocation = client._protocol_module.validate_allocation(
                        value["allocation"], profile=client.protocol["profile"],
                        spec=client.protocol["spec"], context=context)
                except (ValueError, TypeError, KeyError):
                    raise RelayStopped("supplemental relay checkpoint differs", code=RelayStopCode.CHECKPOINT_INVALID) from None
            created, expires = _full_date(value["created_at"]), _full_date(value["expires_at"])
            born, deadline = value["created_monotonic"], value["deadline_monotonic"]
            _require(type(born) in (int, float) and type(deadline) in (int, float)
                     and math.isfinite(born) and math.isfinite(deadline)
                     and 0 <= born <= client._monotonic() and born < deadline <= born + 3 * MAX_SECONDS
                     and created <= _utc(client._clock()) < created + dt.timedelta(seconds=3 * MAX_SECONDS)
                     and created < expires <= created + dt.timedelta(seconds=3 * MAX_SECONDS),
                     "relay checkpoint lifetime differs", code=RelayStopCode.CHECKPOINT_INVALID)
            client.reads, client._host_checked = value["reads"], True
            client._phases = list(value["phases"])
            client._created_at, client._created_monotonic = created, born
            client._deadline, client._expires = deadline, expires
            client._last_at, client._last_monotonic = _full_date(value["last_at"]), value["last_monotonic"]
            _require(type(client._last_monotonic) in (int, float)
                     and math.isfinite(client._last_monotonic)
                     and born <= client._last_monotonic
                     and created <= client._last_at,
                     "relay checkpoint lifetime differs", code=RelayStopCode.CHECKPOINT_INVALID)
            pending = value["pending_wait"]
            if pending is not None:
                client._validate_pending(pending)
                _require(pending["reads"] == client.reads
                         and pending["plan"]["phase"] == ("merge" if not client._phases else "observe")
                         and len(client._phases) < 2
                         and pending["verify_monotonic"] == deadline
                         and _full_date(pending["plan"]["verify_by"]) == expires,
                         "invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID)
                client._pending_wait = copy.deepcopy(pending)
            client._job_live()
            if pending is not None:
                client._pending_live()
            return client
        except Exception as error:
            if type(error) is RelayStopped:
                raise
            raise RelayStopped("invalid relay checkpoint", code=RelayStopCode.CHECKPOINT_INVALID) from None

    def _times(self):
        mono, now = self._monotonic(), _utc(self._clock())
        _require(type(mono) in (int, float) and math.isfinite(mono)
                 and mono >= self._last_monotonic and now >= self._last_at
                 and abs((now - self._created_at).total_seconds()
                         - (mono - self._created_monotonic)) <= 1,
                 "relay clocks differ", code=RelayStopCode.CLOCK_INVALID)
        self._last_monotonic, self._last_at = mono, now
        return mono, now

    def _job_live(self):
        _require(not self._failed, "relay is permanently stopped", code=RelayStopCode.PERMANENT_STOP)
        mono, now = self._times()
        _require(mono < self._created_monotonic + 3 * MAX_SECONDS
                 and now < self._created_at + dt.timedelta(seconds=3 * MAX_SECONDS),
                 "relay job lifetime expired", code=RelayStopCode.JOB_LIFETIME_EXPIRED)
        return mono, now

    def _live(self):
        mono, now = self._job_live()
        _require(mono < self._deadline and now < self._expires,
                 "owner selection deadline expired", code=RelayStopCode.VERIFICATION_EXPIRED)

    def _pending_live(self):
        self._live()
        pending = self._pending_wait
        _require(pending is not None, "owner wait plan is absent", code=RelayStopCode.CHECKPOINT_INVALID)
        mono, now = self._times()
        _require(mono < pending["submit_monotonic"] and now < _full_date(pending["plan"]["submit_by"]),
                 "owner selection submission deadline expired", code=RelayStopCode.SUBMISSION_EXPIRED)

    def _wait_costs(self, phase):
        history_pages = ((len(self.protocol["spec"]["accounting"]["history_baseline"]) + 100) // 100
                         if self.protocol is not None else 0)
        post_reads = 1 + (4 + history_pages if self.protocol is not None else 0)
        return post_reads, post_reads + 2 if phase == "merge" else 0

    def _validate_pending(self, pending):
        code = RelayStopCode.CHECKPOINT_INVALID
        _require(type(pending) is dict and set(pending) == {
            "plan", "issued_monotonic", "submit_monotonic", "verify_monotonic", "reads"},
            "invalid relay wait plan", code=code)
        plan = pending["plan"]
        _require(type(plan) is dict and set(plan) == {
            "phase", "selection_digest", "issued_at", "submit_by", "verify_by", "allowed_polls",
            "post_selection_reads", "future_phase_reads", "verification_reserve_seconds"},
            "invalid relay wait plan", code=code)
        _require(plan["phase"] in ("merge", "observe")
                 and type(plan["selection_digest"]) is str and DIGEST.fullmatch(plan["selection_digest"])
                 and type(plan["allowed_polls"]) is int and 2 <= plan["allowed_polls"] <= MAX_POLLS
                 and type(plan["post_selection_reads"]) is int and 1 <= plan["post_selection_reads"] <= 10
                 and type(plan["future_phase_reads"]) is int and 0 <= plan["future_phase_reads"] <= 12
                 and type(plan["verification_reserve_seconds"]) is int
                 and plan["verification_reserve_seconds"] == (plan["post_selection_reads"] + 1) * 10 + 1
                 and type(pending["reads"]) is int and 4 <= pending["reads"] <= MAX_READS,
                 "invalid relay wait plan", code=code)
        issued, submit, verify = (_full_date(plan[key]) for key in ("issued_at", "submit_by", "verify_by"))
        mono, end, limit = (pending[key] for key in (
            "issued_monotonic", "submit_monotonic", "verify_monotonic"))
        post_reads, future_reads = self._wait_costs(plan["phase"])
        _require(all(type(value) in (int, float) and math.isfinite(value)
                     for value in (mono, end, limit))
                 and self._created_monotonic <= mono < end < limit
                 <= self._created_monotonic + 3 * MAX_SECONDS
                 and self._created_at <= issued < submit < verify
                 <= self._created_at + dt.timedelta(seconds=3 * MAX_SECONDS)
                 and plan["post_selection_reads"] == post_reads
                 and plan["future_phase_reads"] == future_reads
                 and (submit - issued).total_seconds() == end - mono
                 and (verify - issued).total_seconds() == limit - mono
                 and end - mono == (plan["allowed_polls"] - 1) * POLL_SECONDS
                 and limit - end == plan["verification_reserve_seconds"]
                 and limit - mono <= MAX_SECONDS
                 and pending["reads"] + plan["allowed_polls"] + plan["post_selection_reads"]
                 + plan["future_phase_reads"] <= MAX_READS,
                 "invalid relay wait plan", code=code)

    def plan_wait(self, selection, *, credential_expires_at):
        """Seal the actual human window before publishing/uploading its packet.

        The final scheduled inventory scan occurs at submit_by. Its response,
        exact comment reread and fixed host recheck must finish before verify_by.
        No pending plan may be renewed, including after checkpoint restoration.
        """
        try:
            _require(self._host_checked and not self._failed, "host must be verified first",
                     code=RelayStopCode.HOST_VERIFICATION_FAILED)
            _require(not self._phase_active and self._pending_wait is None,
                     "owner phase cannot restart", code=RelayStopCode.PHASE_REUSED)
            selection = _selection(selection)
            phase = "merge" if not self._phases else "observe"
            _require(len(self._phases) < 2 and selection["phase"] == phase,
                     "owner phase cannot restart", code=RelayStopCode.PHASE_REUSED)
            _require(selection["run_id"] == self.context["run_id"]
                     and selection["run_attempt"] == self.context["run_attempt"],
                     "selection belongs to another run", code=RelayStopCode.SELECTION_INVALID)
            if not self._phases:
                self._live()
            mono, now = self._job_live()
            lease = _utc(credential_expires_at)
            _require(now < lease, "owner credential deadline expired", code=RelayStopCode.CREDENTIAL_EXPIRED)
            post_reads, future_reads = self._wait_costs(phase)
            polls = min(MAX_POLLS, MAX_READS - self.reads - post_reads - future_reads)
            _require(polls >= 2, "relay GET budget cannot fund owner verification",
                     code=RelayStopCode.READ_BUDGET_INSUFFICIENT)
            reserve = (post_reads + 1) * 10 + 1
            cap = min(float(MAX_SECONDS), (lease - now).total_seconds(),
                      self._created_monotonic + 3 * MAX_SECONDS - mono,
                      (self._created_at + dt.timedelta(seconds=3 * MAX_SECONDS) - now).total_seconds())
            slots = min(polls - 1, math.floor((cap - reserve) / POLL_SECONDS))
            _require(slots >= 1, "owner credential deadline cannot fund verification",
                     code=(RelayStopCode.CREDENTIAL_EXPIRED if (lease - now).total_seconds() <= cap
                           else RelayStopCode.JOB_LIFETIME_EXPIRED))
            submit_seconds = slots * POLL_SECONDS
            plan = {"phase": phase, "selection_digest": _selection_digest(selection),
                    "issued_at": _full_stamp(now),
                    "submit_by": _full_stamp(now + dt.timedelta(seconds=submit_seconds)),
                    "verify_by": _full_stamp(now + dt.timedelta(seconds=submit_seconds + reserve)),
                    "allowed_polls": slots + 1, "post_selection_reads": post_reads,
                    "future_phase_reads": future_reads, "verification_reserve_seconds": reserve}
            self._pending_wait = {"plan": plan, "issued_monotonic": mono,
                                  "submit_monotonic": mono + submit_seconds,
                                  "verify_monotonic": mono + submit_seconds + reserve,
                                  "reads": self.reads}
            self._validate_pending(self._pending_wait)
            self._deadline = self._pending_wait["verify_monotonic"]
            self._expires = _full_date(plan["verify_by"])
            return copy.deepcopy(plan)
        except Exception as error:
            self._failed = True
            if type(error) is RelayStopped:
                raise
            raise RelayStopped("owner wait planning failed", code=RelayStopCode.SELECTION_INVALID) from None

    def _get(self, path):
        self._live()
        _require(self.reads < MAX_READS, "relay GET budget exhausted", code=RelayStopCode.READ_BUDGET_EXHAUSTED)
        approvals = PREFIX + "/actions/runs/" + str(self.context["run_id"]) + "/approvals"
        allowed_approval = self.protocol is not None and path == approvals
        _require(isinstance(path, str) and (allowed_approval or re.fullmatch(
            re.escape(PREFIX) + r"/(?:actions/workflows/app-bootstrap\.yml|actions/runs/[1-9][0-9]*(?:/attempts/1/jobs\?per_page=100)?|actions/workflows/[1-9][0-9]*/runs\?per_page=100&page=[1-5]|issues/5/comments\?per_page=100|issues/comments/[1-9][0-9]*)", path)),
            "request outside fixed relay scope", code=RelayStopCode.PROVIDER_READ_FAILED)
        self.reads += 1
        timeout = min(10.0, self._deadline - self._monotonic(),
                      (self._expires - _utc(self._clock())).total_seconds())
        _require(timeout > 0, "owner selection deadline expired", code=RelayStopCode.VERIFICATION_EXPIRED)
        try:
            response = self._sender("GET", API + path,
                                    {"Accept": "application/vnd.github+json",
                                     "Authorization": "Bearer " + self._token,
                                     "X-GitHub-Api-Version": "2022-11-28"}, None, timeout)
        except Exception:
            raise RelayStopped("GitHub read failed", code=RelayStopCode.PROVIDER_READ_FAILED) from None
        self._live()
        _require(type(response) is tuple and len(response) == 3, "invalid GitHub response",
                 code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
        status, body, headers = response
        _require(type(status) is int and status == 200 and isinstance(headers, dict),
                 "GitHub read failed", code=RelayStopCode.PROVIDER_READ_FAILED)
        _require(all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()),
                 "invalid GitHub headers", code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
        lowered = {key.lower(): value for key, value in headers.items()}
        _require(len(lowered) == len(headers) and "location" not in lowered,
                 "redirects are forbidden", code=RelayStopCode.PROVIDER_RESPONSE_INVALID)
        return _decode(body), lowered

    @staticmethod
    def _repo(value):
        return (isinstance(value, dict) and type(value.get("id")) is int
                and value["id"] == REPOSITORY_ID and value.get("full_name") == REPOSITORY)

    def _run(self, value, workflow_id, *, current=False):
        _require(isinstance(value, dict) and _positive(value.get("id"))
                 and _positive(value.get("run_number")) and _positive(value.get("run_attempt"))
                 and type(value.get("workflow_id")) is int and value["workflow_id"] == workflow_id
                 and value.get("path") == WORKFLOW and self._repo(value.get("repository"))
                 and isinstance(value.get("head_sha"), str) and SHA.fullmatch(value["head_sha"])
                 and isinstance(value.get("display_title"), str)
                 and 0 < len(value["display_title"]) <= 256
                 and value.get("status") in ("queued", "requested", "pending", "waiting", "in_progress", "completed")
                 and value.get("conclusion") in (None, "success", "failure", "cancelled", "timed_out",
                                                  "action_required", "neutral", "skipped", "stale", "startup_failure"),
                 "workflow run identity is unavailable", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        if current:
            _require(value["id"] == self.context["run_id"] and value["run_attempt"] == 1
                     and value.get("event") == "workflow_dispatch"
                     and value.get("head_branch") == REF.removeprefix("refs/heads/")
                     and value["head_sha"] == self.context["source"]
                     and value["display_title"] == TITLE and value["status"] == "in_progress"
                     and value.get("conclusion") is None
                     and self._repo(value.get("head_repository")), "current hosted run differs", code=RelayStopCode.HOST_VERIFICATION_FAILED)

    @staticmethod
    def _history_links(headers, path, page, pages):
        expected = {}
        if page > 1:
            expected.update(prev=page - 1, first=1)
        if page < pages:
            expected.update(next=page + 1, last=pages)
        raw = headers.get("link", "")
        actual = {}
        for part in raw.split(",") if raw else []:
            match = re.fullmatch(r'\s*<([^<>]+)>; rel="(next|last|first|prev)"\s*', part)
            _require(match is not None and match[2] not in actual, "incomplete workflow history", code=RelayStopCode.INVENTORY_INVALID)
            actual[match[2]] = match[1]
        _require(actual == {rel: API + path + "?per_page=100&page=" + str(number)
                            for rel, number in expected.items()}, "incomplete workflow history", code=RelayStopCode.INVENTORY_INVALID)

    def check_host(self):
        """Validate initial history; the old allocation remains permanently charged."""
        return self._verify_host(recheck=False)

    def recheck_host(self):
        """Recheck history and the retained allocation without resetting any clock or count."""
        result = self._verify_host(recheck=True)
        try:
            self._review_allowance()
            self._live()
            result["reads"] = self.reads
        except Exception as error:
            self._failed = True
            if type(error) is RelayStopped:
                raise
            raise RelayStopped("supplemental allowance review differs", code=RelayStopCode.HOST_VERIFICATION_FAILED) from None
        return result

    @staticmethod
    def _owner(value):
        return (isinstance(value, dict) and type(value.get("id")) is int
                and value["id"] == OWNER_ID and value.get("login") == OWNER_LOGIN
                and value.get("type") == "User")

    def _supplemental_history(self, history, current):
        accounting = self.protocol["spec"]["accounting"]
        baseline = accounting["history_baseline"]
        _require(isinstance(baseline, list) and len(baseline) == 11
                 and len(history) == len(baseline) + 1
                 and current["run_number"] == len(baseline) + 1,
                 "supplemental dispatch allowance differs", code=RelayStopCode.INVENTORY_INVALID)
        indexed = {item["run_id"]: (number, item) for number, item in enumerate(baseline, 1)}
        _require(len(indexed) == len(baseline) and self.context["run_id"] not in indexed,
                 "supplemental history differs", code=RelayStopCode.INVENTORY_INVALID)
        found = set()
        for item in history:
            if item["id"] == current["id"]:
                _require(self._owner(item.get("actor")) and self._owner(item.get("triggering_actor")),
                         "supplemental dispatcher differs", code=RelayStopCode.INVENTORY_INVALID)
                continue
            _require(item["id"] in indexed, "unexpected supplemental workflow history", code=RelayStopCode.INVENTORY_INVALID)
            number, expected = indexed[item["id"]]
            actual = {"run_id": item["id"], "run_attempt": item["run_attempt"],
                      "source": item["head_sha"], "title": item["display_title"],
                      "status": item["status"], "conclusion": item["conclusion"],
                      "workflow_id": item["workflow_id"]}
            _require(actual == expected and item["run_number"] == number,
                     "reviewed historical attempt differs", code=RelayStopCode.INVENTORY_INVALID)
            found.add(item["id"])
        _require(found == set(indexed), "reviewed historical attempt is missing", code=RelayStopCode.INVENTORY_INVALID)
        predecessor = accounting["predecessor"]
        prior = next(item for item in history if item["id"] == predecessor["run_id"])
        _require(prior.get("event") == "workflow_dispatch"
                 and prior.get("head_branch") == REF.removeprefix("refs/heads/")
                 and self._repo(prior.get("head_repository"))
                 and self._owner(prior.get("actor")) and self._owner(prior.get("triggering_actor")),
                 "consumed native predecessor differs", code=RelayStopCode.INVENTORY_INVALID)

    def _verify_host(self, *, recheck):
        try:
            _require(not self._failed and not self._phase_active
                     and ((recheck and self.protocol is not None and self._host_checked
                           and self._allocation is not None)
                          or (not recheck and not self._host_checked and not self._phases)),
                     "host check cannot restart", code=RelayStopCode.INVENTORY_INVALID)
            workflow, headers = self._get(PREFIX + "/actions/workflows/app-bootstrap.yml")
            _require(isinstance(workflow, dict) and _positive(workflow.get("id"))
                     and workflow.get("path") == WORKFLOW and workflow.get("state") == "active"
                     and not headers.get("link"), "workflow identity is unavailable", code=RelayStopCode.INVENTORY_INVALID)
            if self.protocol is not None:
                _require(workflow["id"] == self.protocol["spec"]["accounting"]["predecessor"]["workflow_id"],
                         "supplemental workflow differs", code=RelayStopCode.INVENTORY_INVALID)
            run, headers = self._get(PREFIX + "/actions/runs/" + str(self.context["run_id"]))
            _require(not headers.get("link"), "current hosted run differs", code=RelayStopCode.INVENTORY_INVALID)
            self._run(run, workflow["id"], current=True)
            history_path = PREFIX + "/actions/workflows/" + str(workflow["id"]) + "/runs"
            history, total, page = [], None, 1
            while total is None or len(history) < total:
                value, headers = self._get(history_path + "?per_page=100&page=" + str(page))
                _require(isinstance(value, dict) and type(value.get("total_count")) is int
                         and 0 < value["total_count"] <= MAX_HISTORY
                         and isinstance(value.get("workflow_runs"), list), "incomplete workflow history", code=RelayStopCode.INVENTORY_INVALID)
                if total is None:
                    total = value["total_count"]
                _require(value["total_count"] == total, "workflow history changed during inventory", code=RelayStopCode.INVENTORY_INVALID)
                pages = (total + 99) // 100
                _require(page <= pages and len(value["workflow_runs"]) == min(100, total - len(history)),
                         "incomplete workflow history", code=RelayStopCode.INVENTORY_INVALID)
                self._history_links(headers, history_path, page, pages)
                history.extend(value["workflow_runs"])
                page += 1
            ids, numbers, current = set(), set(), []
            for item in history:
                self._run(item, workflow["id"])
                _require(item["id"] not in ids and item["run_number"] not in numbers,
                         "duplicate workflow history", code=RelayStopCode.INVENTORY_INVALID)
                ids.add(item["id"])
                numbers.add(item["run_number"])
                if item["id"] == run["id"]:
                    self._run(item, workflow["id"], current=True)
                    _require(item["run_number"] == run["run_number"], "current workflow history changed", code=RelayStopCode.INVENTORY_INVALID)
                    current.append(item)
                elif self.protocol is None:
                    _require(item["display_title"] != TITLE, "a native PR5 trial already exists", code=RelayStopCode.INVENTORY_INVALID)
            _require(len(current) == 1, "current run is absent from workflow history", code=RelayStopCode.INVENTORY_INVALID)
            if self.protocol is not None:
                _require(self._owner(run.get("actor")) and self._owner(run.get("triggering_actor")),
                         "supplemental dispatcher differs", code=RelayStopCode.INVENTORY_INVALID)
                self._supplemental_history(history, run)
            jobs, headers = self._get(PREFIX + "/actions/runs/" + str(run["id"])
                                      + "/attempts/1/jobs?per_page=100")
            _require(isinstance(jobs, dict) and type(jobs.get("total_count")) is int
                     and isinstance(jobs.get("jobs"), list) and 0 < len(jobs["jobs"]) < 100
                     and jobs["total_count"] == len(jobs["jobs"]) and not headers.get("link"),
                     "incomplete workflow job inventory", code=RelayStopCode.INVENTORY_INVALID)
            _require(all(isinstance(job, dict) and _positive(job.get("id")) for job in jobs["jobs"])
                     and len({job["id"] for job in jobs["jobs"]}) == len(jobs["jobs"]),
                     "invalid workflow job inventory", code=RelayStopCode.INVENTORY_INVALID)
            selected = [job for job in jobs["jobs"] if job.get("name") == JOB]
            _require(len(selected) == 1 and selected[0].get("run_id") == run["id"]
                     and type(selected[0].get("run_id")) is int
                     and selected[0].get("run_attempt") == 1
                     and type(selected[0].get("run_attempt")) is int
                     and selected[0].get("head_sha") == self.context["source"]
                     and selected[0].get("status") == "in_progress"
                     and selected[0].get("conclusion") is None, "current hosted job differs", code=RelayStopCode.INVENTORY_INVALID)
            self._host_checked = True
            return {"status": "ready", "run_id": run["id"], "run_attempt": 1,
                    "workflow_id": workflow["id"], "job_id": selected[0]["id"],
                    "history_count": total, "reads": self.reads}
        except Exception as error:
            self._failed = True
            if type(error) is RelayStopped:
                raise
            raise RelayStopped("host verification failed", code=RelayStopCode.HOST_VERIFICATION_FAILED) from None

    def _review_allowance(self):
        _require(self.protocol is not None and self._host_checked and not self._failed,
                 "supplemental host must be verified first", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        reviews, headers = self._get(PREFIX + "/actions/runs/" + str(self.context["run_id"]) + "/approvals")
        _require(isinstance(reviews, list) and len(reviews) == 1 and not headers.get("link"),
                 "supplemental approval inventory differs", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        review = reviews[0]
        _require(isinstance(review, dict) and review.get("state") == "approved"
                 and self._owner(review.get("user")), "supplemental allocation is not owner approved", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        environments = review.get("environments")
        _require(isinstance(environments, list) and len(environments) == 1
                 and isinstance(environments[0], dict)
                 and type(environments[0].get("id")) is int and environments[0]["id"] == 26032127012
                 and environments[0].get("name") == "canary-merger-diagnostic",
                 "supplemental approval environment differs", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        command = self._protocol_module.allowance_command(self.protocol, self.context)
        _require(isinstance(review.get("comment"), str) and review["comment"].strip(" \t\r\n") == command, "exact supplemental approval comment is required", code=RelayStopCode.HOST_VERIFICATION_FAILED)
        return command

    def check_supplemental_allowance(self):
        """Observe the owner's explicit added allocation before creating native state."""
        try:
            _require(self.protocol is not None and self._allocation is None and not self._phases,
                     "supplemental allocation cannot restart", code=RelayStopCode.PHASE_REUSED)
            command = self._review_allowance()
            receipt = {"schema_version": "0.1.0", "kind": "owner-approved-supplemental-native-allocation",
                       "status": "approved", "context": copy.deepcopy(self.context),
                       "accounting": copy.deepcopy(self.protocol["spec"]["accounting"]),
                       "accounting_digest": self.protocol["profile"]["accounting_digest"],
                       "reviewer_id": OWNER_ID, "environment_id": 26032127012,
                       "command": command,
                       "command_digest": "sha256:" + hashlib.sha256(command.encode("ascii")).hexdigest(),
                       "observed_at": _full_stamp(self._clock())}
            self._allocation = self._protocol_module.validate_allocation(
                receipt, profile=self.protocol["profile"], spec=self.protocol["spec"], context=self.context)
            return copy.deepcopy(self._allocation)
        except Exception as error:
            self._failed = True
            if type(error) is RelayStopped:
                raise
            raise RelayStopped("supplemental allowance verification failed", code=RelayStopCode.HOST_VERIFICATION_FAILED) from None

    def _comment(self, value, body, start, submit_by):
        _require(isinstance(value, dict) and _positive(value.get("id")), "invalid selected comment",
                 code=RelayStopCode.SELECTION_INVALID)
        identifier = str(value["id"])
        owner = value.get("user")
        _require(isinstance(owner, dict) and type(owner.get("id")) is int
                 and owner["id"] == OWNER_ID and owner.get("login") == OWNER_LOGIN
                 and owner.get("type") == "User", "selected comment is not from the fixed owner",
                 code=RelayStopCode.SELECTION_INVALID)
        _require(value.get("body") == body and value.get("url") == API + PREFIX + "/issues/comments/" + identifier
                 and value.get("html_url") == "https://github.com/" + REPOSITORY + "/pull/5#issuecomment-" + identifier
                 and value.get("issue_url") == API + PREFIX + "/issues/5", "selected comment identity differs",
                 code=RelayStopCode.SELECTION_INVALID)
        created, updated = _date(value.get("created_at")), _date(value.get("updated_at"))
        _require(created == updated and start <= created <= _utc(self._clock())
                 and created < submit_by, "selected comment is stale or edited",
                 code=RelayStopCode.SELECTION_CHANGED)
        return {"id": value["id"], "body": value["body"], "user": copy.deepcopy(owner),
                **{name: value[name] for name in ("url", "html_url", "issue_url", "created_at", "updated_at")}}

    def wait(self, selection, *, plan=None, expires_at=None):
        """Consume the prepublished plan once, retaining its original schedule.

        expires_at supports older local callers by planning exactly once here;
        the hosted coordinator always supplies the previously published plan.
        """
        try:
            _require(self._host_checked and not self._failed, "host must be verified first",
                     code=RelayStopCode.HOST_VERIFICATION_FAILED)
            selection = _selection(selection)
            _require(selection["run_id"] == self.context["run_id"]
                     and selection["run_attempt"] == self.context["run_attempt"], "selection belongs to another run",
                     code=RelayStopCode.SELECTION_INVALID)
            phase = "merge" if not self._phases else "observe"
            _require(len(self._phases) < 2 and selection["phase"] == phase and not self._phase_active,
                     "owner phase cannot restart", code=RelayStopCode.PHASE_REUSED)
            _require((plan is None) != (expires_at is None), "exactly one owner wait plan is required",
                     code=RelayStopCode.CHECKPOINT_INVALID)
            legacy = plan is None
            if legacy:
                plan = self.plan_wait(selection, credential_expires_at=expires_at)
            pending = self._pending_wait
            _require(pending is not None and type(plan) is dict and plan == pending["plan"]
                     and plan["selection_digest"] == _selection_digest(selection)
                     and plan["phase"] == phase and self.reads == pending["reads"],
                     "owner wait plan differs", code=RelayStopCode.CHECKPOINT_INVALID)
            self._pending_live()
            self._phases.append(phase)
            start = (self._created_at if legacy else _full_date(plan["issued_at"])).replace(microsecond=0)
            submit_by = _full_date(plan["submit_by"])
            self._phase_active = True
            self._live()
            approve, deny = approval_command(selection), deny_command(selection)
            for poll in range(plan["allowed_polls"]):
                scan_at, _ = self._times()
                if 0 < pending["submit_monotonic"] - scan_at < POLL_SECONDS:
                    # A late wake must not shorten the final polling interval.
                    self._sleep(pending["submit_monotonic"] - scan_at)
                    scan_at, _ = self._times()
                terminal = scan_at >= pending["submit_monotonic"]
                comments, headers = self._get(COMMENTS)
                _require(isinstance(comments, list) and len(comments) < 100 and not headers.get("link"),
                         "incomplete PR5 comment inventory", code=RelayStopCode.INVENTORY_INVALID)
                seen, matches = set(), []
                for item in comments:
                    _require(isinstance(item, dict) and _positive(item.get("id"))
                             and item["id"] not in seen, "invalid PR5 comment inventory",
                             code=RelayStopCode.INVENTORY_INVALID)
                    seen.add(item["id"])
                    if item.get("body") in (approve, deny):
                        candidate = self._comment(item, item["body"], start, submit_by)
                        _require(item["body"] != deny, "owner denied the selected operation",
                                 code=RelayStopCode.OWNER_DENIED)
                        matches.append(candidate)
                _require(len(matches) <= 1, "multiple owner selections match",
                         code=RelayStopCode.SELECTION_AMBIGUOUS)
                if matches:
                    candidate = matches[0]
                    final, headers = self._get(PREFIX + "/issues/comments/" + str(candidate["id"]))
                    _require(not headers.get("link") and self._comment(final, approve, start, submit_by) == candidate,
                             "selected comment changed before use", code=RelayStopCode.SELECTION_CHANGED)
                    self._live()
                    self._phase_active = False
                    self._pending_wait = None
                    return {"schema_version": "0.1.0", "kind": "fixed-pr-owner-selection",
                            "selection": selection, "repository_id": REPOSITORY_ID, "pull_request": 5,
                            "comment_id": candidate["id"], "owner_id": OWNER_ID, "owner_login": OWNER_LOGIN,
                            "created_at": candidate["created_at"], "updated_at": candidate["updated_at"],
                            "verified_at": _stamp(self._clock()),
                            "command_digest": "sha256:" + hashlib.sha256(approve.encode("ascii")).hexdigest()}
                if poll + 1 >= plan["allowed_polls"]:
                    raise RelayStopped("owner selection poll budget exhausted",
                                       code=RelayStopCode.POLL_BUDGET_EXHAUSTED)
                _require(not terminal, "owner selection submission deadline expired",
                         code=RelayStopCode.SUBMISSION_EXPIRED)
                self._live()
                mono, _ = self._times()
                # Missed publication-anchored slots are skipped, never caught up.
                earliest = max(mono, scan_at + POLL_SECONDS)
                slot = math.ceil((earliest - pending["issued_monotonic"]) / POLL_SECONDS)
                next_scan = min(pending["issued_monotonic"] + slot * POLL_SECONDS,
                                pending["submit_monotonic"])
                if next_scan > mono:
                    self._sleep(next_scan - mono)
            raise RelayStopped("owner selection poll budget exhausted", code=RelayStopCode.POLL_BUDGET_EXHAUSTED)
        except Exception as error:
            self._failed = True
            if type(error) is RelayStopped:
                raise
            raise RelayStopped("owner selection failed", code=RelayStopCode.SELECTION_INVALID) from None
