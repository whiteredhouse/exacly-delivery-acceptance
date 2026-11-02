"""Fixed, read-only owner-selection relay for the one PR5 hosted native trial.

This module cannot post comments or grant native authority. A human must paste
the exact command, and the same relay instance retains the complete read budget
through host validation and both independent owner selections.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import hmac
import json
import math
import re
import time
import urllib.error
import urllib.request


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


class RelayStopped(Exception):
    """A fixed safe reason; transport exception text is never forwarded."""


def _require(value, reason="invalid relay data"):
    if not value:
        raise RelayStopped(reason)


def _positive(value):
    return type(value) is int and 0 < value < 2**63


def _utc(value):
    _require(isinstance(value, dt.datetime) and value.tzinfo is not None
             and value.utcoffset() == dt.timedelta(0), "invalid UTC deadline")
    return value


def _stamp(value):
    return _utc(value).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _full_stamp(value):
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _full_date(value):
    _require(isinstance(value, str), "invalid relay checkpoint")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        _require(_full_stamp(parsed) == value, "invalid relay checkpoint")
        return parsed
    except (ValueError, TypeError):
        raise RelayStopped("invalid relay checkpoint") from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _date(value):
    _require(isinstance(value, str) and TIMESTAMP.fullmatch(value), "invalid server timestamp")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise RelayStopped("invalid server timestamp") from None


def _selection(value):
    _require(isinstance(value, dict), "invalid owner selection")
    keys = {"phase", "run_id", "run_attempt", "challenge", "packet_digest",
            "issuer", "approval_id", "approval_digest"}
    if value.get("phase") == "merge":
        keys.add("identity_digest")
    _require(set(value) == keys and value.get("phase") in ("merge", "observe"),
             "invalid owner selection")
    _require(_positive(value["run_id"]) and type(value["run_attempt"]) is int
             and value["run_attempt"] == 1 and value["issuer"] == OWNER_LOGIN,
             "invalid owner selection")
    for name, pattern in (("challenge", HEX), ("packet_digest", DIGEST),
                          ("approval_digest", DIGEST), ("approval_id", WORD)):
        _require(isinstance(value[name], str) and pattern.fullmatch(value[name]),
                 "invalid owner selection")
    if "identity_digest" in value:
        _require(isinstance(value["identity_digest"], str)
                 and DIGEST.fullmatch(value["identity_digest"]), "invalid owner selection")
    return copy.deepcopy(value)


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
             "request outside fixed relay scope")
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            _require(response.geturl() == url, "redirects are forbidden")
            return response.status, response.read(MAX_BODY + 1), dict(response.headers)
    except Exception:
        raise RelayStopped("GitHub read failed") from None


def _decode(body):
    def pairs(values):
        result = {}
        for key, value in values:
            _require(key not in result, "invalid bounded JSON")
            result[key] = value
        return result

    def constant(_):
        raise RelayStopped("invalid bounded JSON")

    _require(type(body) is bytes and len(body) <= MAX_BODY, "invalid bounded JSON")
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except Exception:
        raise RelayStopped("invalid bounded JSON") from None


class Relay:
    def __init__(self, token, context, *, sender=None, clock=None, monotonic=None, sleep=None):
        _require(isinstance(token, str) and 0 < len(token) <= 4096
                 and not any(ord(character) < 33 or ord(character) > 126 for character in token),
                 "invalid relay credential")
        _require(isinstance(context, dict), "invalid hosted context")
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
                 "invalid hosted context")
        self._token, self._sender = token, sender or transport
        self._clock = clock or (lambda: dt.datetime.now(UTC))
        self._monotonic, self._sleep = monotonic or time.monotonic, sleep or time.sleep
        self.reads = 0
        self._host_checked, self._failed = False, False
        self._phases = []
        self._phase_active = False
        self._created_monotonic = self._monotonic()
        self._created_at = _utc(self._clock())
        self._deadline = self._created_monotonic + MAX_SECONDS
        self._expires = self._created_at + dt.timedelta(seconds=MAX_SECONDS)

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
                 "stopped or incomplete relay cannot be checkpointed")
        payload = {"schema_version": "0.1.0", "kind": "fixed-native-relay-checkpoint",
                   "context": copy.deepcopy(self.context), "reads": self.reads,
                   "host_checked": self._host_checked, "phases": list(self._phases),
                   "created_at": _full_stamp(self._created_at),
                   "created_monotonic": self._created_monotonic,
                   "deadline_monotonic": self._deadline, "expires_at": _full_stamp(self._expires)}
        return {"payload": payload,
                "mac": hmac.new(self._token.encode("ascii"), _canonical(payload), hashlib.sha256).hexdigest()}

    @classmethod
    def restore(cls, token, context, state, *, sender=None, clock=None, monotonic=None, sleep=None):
        """Restore a protected one-shot checkpoint without resetting the budget."""
        client = cls(token, context, sender=sender, clock=clock, monotonic=monotonic, sleep=sleep)
        try:
            _require(isinstance(state, dict) and set(state) == {"payload", "mac"}
                     and isinstance(state["payload"], dict) and isinstance(state["mac"], str),
                     "invalid relay checkpoint")
            value = state["payload"]
            expected = hmac.new(token.encode("ascii"), _canonical(value), hashlib.sha256).hexdigest()
            _require(hmac.compare_digest(expected, state["mac"]), "relay checkpoint integrity differs")
            _require(set(value) == {"schema_version", "kind", "context", "reads", "host_checked", "phases",
                                    "created_at", "created_monotonic", "deadline_monotonic", "expires_at"}
                     and value["schema_version"] == "0.1.0" and value["kind"] == "fixed-native-relay-checkpoint"
                     and value["context"] == context and type(value["host_checked"]) is bool
                     and value["host_checked"] is True and type(value["reads"]) is int
                     and 4 <= value["reads"] <= MAX_READS
                     and value["phases"] in ([], ["merge"], ["merge", "observe"])
                     and value["reads"] >= 4 + 2 * len(value["phases"]), "invalid relay checkpoint")
            created, expires = _full_date(value["created_at"]), _full_date(value["expires_at"])
            born, deadline = value["created_monotonic"], value["deadline_monotonic"]
            _require(type(born) in (int, float) and type(deadline) in (int, float)
                     and math.isfinite(born) and math.isfinite(deadline)
                     and 0 <= born <= client._monotonic() and born < deadline <= born + 3 * MAX_SECONDS
                     and created <= _utc(client._clock()) < created + dt.timedelta(seconds=3 * MAX_SECONDS)
                     and created < expires <= created + dt.timedelta(seconds=3 * MAX_SECONDS),
                     "relay checkpoint lifetime differs")
            client.reads, client._host_checked = value["reads"], True
            client._phases = list(value["phases"])
            client._created_at, client._created_monotonic = created, born
            client._deadline, client._expires = deadline, expires
            return client
        except Exception as error:
            if isinstance(error, RelayStopped):
                raise
            raise RelayStopped("invalid relay checkpoint") from None

    def _live(self):
        _require(not self._failed, "relay is permanently stopped")
        _require(self._monotonic() < self._deadline and _utc(self._clock()) < self._expires,
                 "owner selection deadline expired")
        _require(self._monotonic() < self._created_monotonic + 3 * MAX_SECONDS
                 and _utc(self._clock()) < self._created_at + dt.timedelta(seconds=3 * MAX_SECONDS),
                 "relay job lifetime expired")

    def _get(self, path):
        self._live()
        _require(self.reads < MAX_READS, "relay GET budget exhausted")
        _require(isinstance(path, str) and re.fullmatch(
            re.escape(PREFIX) + r"/(?:actions/workflows/app-bootstrap\.yml|actions/runs/[1-9][0-9]*(?:/attempts/1/jobs\?per_page=100)?|actions/workflows/[1-9][0-9]*/runs\?per_page=100&page=[1-5]|issues/5/comments\?per_page=100|issues/comments/[1-9][0-9]*)", path),
            "request outside fixed relay scope")
        self.reads += 1
        timeout = min(10.0, self._deadline - self._monotonic(),
                      (self._expires - _utc(self._clock())).total_seconds())
        _require(timeout > 0, "owner selection deadline expired")
        try:
            response = self._sender("GET", API + path,
                                    {"Accept": "application/vnd.github+json",
                                     "Authorization": "Bearer " + self._token,
                                     "X-GitHub-Api-Version": "2022-11-28"}, None, timeout)
        except Exception:
            raise RelayStopped("GitHub read failed") from None
        self._live()
        _require(type(response) is tuple and len(response) == 3, "invalid GitHub response")
        status, body, headers = response
        _require(type(status) is int and status == 200 and isinstance(headers, dict),
                 "GitHub read failed")
        _require(all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()),
                 "invalid GitHub headers")
        lowered = {key.lower(): value for key, value in headers.items()}
        _require(len(lowered) == len(headers) and "location" not in lowered,
                 "redirects are forbidden")
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
                 "workflow run identity is unavailable")
        if current:
            _require(value["id"] == self.context["run_id"] and value["run_attempt"] == 1
                     and value.get("event") == "workflow_dispatch"
                     and value.get("head_branch") == REF.removeprefix("refs/heads/")
                     and value["head_sha"] == self.context["source"]
                     and value["display_title"] == TITLE and value["status"] == "in_progress"
                     and value.get("conclusion") is None
                     and self._repo(value.get("head_repository")), "current hosted run differs")

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
            _require(match is not None and match[2] not in actual, "incomplete workflow history")
            actual[match[2]] = match[1]
        _require(actual == {rel: API + path + "?per_page=100&page=" + str(number)
                            for rel, number in expected.items()}, "incomplete workflow history")

    def check_host(self):
        """Reject any prior PR5 native trial; no new journal can reset history."""
        try:
            _require(not self._host_checked and not self._phases, "host check cannot restart")
            workflow, headers = self._get(PREFIX + "/actions/workflows/app-bootstrap.yml")
            _require(isinstance(workflow, dict) and _positive(workflow.get("id"))
                     and workflow.get("path") == WORKFLOW and workflow.get("state") == "active"
                     and not headers.get("link"), "workflow identity is unavailable")
            run, headers = self._get(PREFIX + "/actions/runs/" + str(self.context["run_id"]))
            _require(not headers.get("link"), "current hosted run differs")
            self._run(run, workflow["id"], current=True)
            history_path = PREFIX + "/actions/workflows/" + str(workflow["id"]) + "/runs"
            history, total, page = [], None, 1
            while total is None or len(history) < total:
                value, headers = self._get(history_path + "?per_page=100&page=" + str(page))
                _require(isinstance(value, dict) and type(value.get("total_count")) is int
                         and 0 < value["total_count"] <= MAX_HISTORY
                         and isinstance(value.get("workflow_runs"), list), "incomplete workflow history")
                if total is None:
                    total = value["total_count"]
                _require(value["total_count"] == total, "workflow history changed during inventory")
                pages = (total + 99) // 100
                _require(page <= pages and len(value["workflow_runs"]) == min(100, total - len(history)),
                         "incomplete workflow history")
                self._history_links(headers, history_path, page, pages)
                history.extend(value["workflow_runs"])
                page += 1
            ids, numbers, current = set(), set(), []
            for item in history:
                self._run(item, workflow["id"])
                _require(item["id"] not in ids and item["run_number"] not in numbers,
                         "duplicate workflow history")
                ids.add(item["id"])
                numbers.add(item["run_number"])
                if item["id"] == run["id"]:
                    self._run(item, workflow["id"], current=True)
                    _require(item["run_number"] == run["run_number"], "current workflow history changed")
                    current.append(item)
                else:
                    _require(item["display_title"] != TITLE, "a native PR5 trial already exists")
            _require(len(current) == 1, "current run is absent from workflow history")
            jobs, headers = self._get(PREFIX + "/actions/runs/" + str(run["id"])
                                      + "/attempts/1/jobs?per_page=100")
            _require(isinstance(jobs, dict) and type(jobs.get("total_count")) is int
                     and isinstance(jobs.get("jobs"), list) and 0 < len(jobs["jobs"]) < 100
                     and jobs["total_count"] == len(jobs["jobs"]) and not headers.get("link"),
                     "incomplete workflow job inventory")
            _require(all(isinstance(job, dict) and _positive(job.get("id")) for job in jobs["jobs"])
                     and len({job["id"] for job in jobs["jobs"]}) == len(jobs["jobs"]),
                     "invalid workflow job inventory")
            selected = [job for job in jobs["jobs"] if job.get("name") == JOB]
            _require(len(selected) == 1 and selected[0].get("run_id") == run["id"]
                     and type(selected[0].get("run_id")) is int
                     and selected[0].get("run_attempt") == 1
                     and type(selected[0].get("run_attempt")) is int
                     and selected[0].get("head_sha") == self.context["source"]
                     and selected[0].get("status") == "in_progress"
                     and selected[0].get("conclusion") is None, "current hosted job differs")
            self._host_checked = True
            return {"status": "ready", "run_id": run["id"], "run_attempt": 1,
                    "workflow_id": workflow["id"], "job_id": selected[0]["id"],
                    "history_count": total, "reads": self.reads}
        except Exception as error:
            self._failed = True
            if isinstance(error, RelayStopped):
                raise
            raise RelayStopped("host verification failed") from None

    def _comment(self, value, body, start):
        _require(isinstance(value, dict) and _positive(value.get("id")), "invalid selected comment")
        identifier = str(value["id"])
        owner = value.get("user")
        _require(isinstance(owner, dict) and type(owner.get("id")) is int
                 and owner["id"] == OWNER_ID and owner.get("login") == OWNER_LOGIN
                 and owner.get("type") == "User", "selected comment is not from the fixed owner")
        _require(value.get("body") == body and value.get("url") == API + PREFIX + "/issues/comments/" + identifier
                 and value.get("html_url") == "https://github.com/" + REPOSITORY + "/pull/5#issuecomment-" + identifier
                 and value.get("issue_url") == API + PREFIX + "/issues/5", "selected comment identity differs")
        created, updated = _date(value.get("created_at")), _date(value.get("updated_at"))
        _require(created == updated and start <= created <= _utc(self._clock())
                 and created < self._expires, "selected comment is stale or edited")
        return {"id": value["id"], "body": value["body"], "user": copy.deepcopy(owner),
                **{name: value[name] for name in ("url", "html_url", "issue_url", "created_at", "updated_at")}}

    def wait(self, selection, *, expires_at):
        """Wait once per phase for a fresh exact owner command, then re-read it."""
        try:
            _require(self._host_checked and not self._failed, "host must be verified first")
            selection = _selection(selection)
            _require(selection["run_id"] == self.context["run_id"]
                     and selection["run_attempt"] == self.context["run_attempt"], "selection belongs to another run")
            phase = "merge" if not self._phases else "observe"
            _require(len(self._phases) < 2 and selection["phase"] == phase, "owner phase cannot restart")
            self._phases.append(phase)
            now = _utc(self._clock())
            start = self._created_at.replace(microsecond=0)
            self._phase_active = True
            self._deadline = self._monotonic() + MAX_SECONDS
            self._expires = min(_utc(expires_at), now + dt.timedelta(seconds=MAX_SECONDS))
            self._live()
            approve, deny = approval_command(selection), deny_command(selection)
            for poll in range(MAX_POLLS):
                comments, headers = self._get(COMMENTS)
                _require(isinstance(comments, list) and len(comments) < 100 and not headers.get("link"),
                         "incomplete PR5 comment inventory")
                seen, matches = set(), []
                for item in comments:
                    _require(isinstance(item, dict) and _positive(item.get("id"))
                             and item["id"] not in seen, "invalid PR5 comment inventory")
                    seen.add(item["id"])
                    if item.get("body") in (approve, deny):
                        candidate = self._comment(item, item["body"], start)
                        _require(item["body"] != deny, "owner denied the selected operation")
                        matches.append(candidate)
                _require(len(matches) <= 1, "multiple owner selections match")
                if matches:
                    candidate = matches[0]
                    final, headers = self._get(PREFIX + "/issues/comments/" + str(candidate["id"]))
                    _require(not headers.get("link") and self._comment(final, approve, start) == candidate,
                             "selected comment changed before use")
                    self._live()
                    self._phase_active = False
                    return {"schema_version": "0.1.0", "kind": "fixed-pr-owner-selection",
                            "selection": selection, "repository_id": REPOSITORY_ID, "pull_request": 5,
                            "comment_id": candidate["id"], "owner_id": OWNER_ID, "owner_login": OWNER_LOGIN,
                            "created_at": candidate["created_at"], "updated_at": candidate["updated_at"],
                            "verified_at": _stamp(self._clock()),
                            "command_digest": "sha256:" + hashlib.sha256(approve.encode("ascii")).hexdigest()}
                if poll + 1 < MAX_POLLS:
                    self._live()
                    remaining = min(self._deadline - self._monotonic(),
                                    (self._expires - _utc(self._clock())).total_seconds())
                    _require(remaining > POLL_SECONDS, "owner selection deadline expired")
                    self._sleep(POLL_SECONDS)
            raise RelayStopped("owner selection poll budget exhausted")
        except Exception as error:
            self._failed = True
            if isinstance(error, RelayStopped):
                raise
            raise RelayStopped("owner selection failed") from None
