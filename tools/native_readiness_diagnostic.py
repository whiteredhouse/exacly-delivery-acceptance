"""Inspect the fixed canary once; publish only bounded, advisory diagnostics.

This job never creates a delivery journal, approval or marker. Its disposable
local key satisfies the read-only native profile and cannot recover the key or
journal lost with the previous hosted runner.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
CORE_REVISION = "9ef4b0adc5f61310154544c636693123fd225737"
NATIVE_PINS = {
    "automatic_merge.py": "d8dce24220ba7ad8bb74c6b8bfab8996401c8973744754ae858a25eecfbb706f",
    "github_merge.py": "14b098888937221d3198f0804a5e3812a13f5bc31a99056d882a984c35e292ab",
}
SPEC_DIGEST = "sha256:7fe9884fe053ab7804e0f53ce0c121d36a8860d9ffd8f13ca8f284ecd5c88905"
API = "https://api.github.com"
PREFIX = "/repos/whiteredhouse/exacly-delivery-acceptance"
REPOSITORY = {"id": 1442278205, "full_name": "whiteredhouse/exacly-delivery-acceptance", "node_id": "R_kgDOVfdrPQ"}
REF = "refs/heads/codex/preflight-diagnostics"
JOB = "native-readiness-diagnostic"
ACTION = "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
PERMISSIONS = {"contents": "write", "administration": "read", "checks": "read",
               "metadata": "read", "pull_requests": "read", "statuses": "read"}
SAFE_NAMES = {"mint-attestation.json", "actor-candidate.json", "native-readiness-diagnostic.json"}
MAX_DOCUMENT = 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
WORK_SECONDS = 120
LEASE_SECONDS = 900
MAX_READS = 64
NATIVE_STAGES = {"key", "credential", "repository", "installation_scope", "protection", "signatures", "rules",
                 "pull_request", "review", "legacy_head_status", "legacy_merge_status", "branch_conditions",
                 "ancestry", "checks", "merge_commit", "contract_trees", "references", "ready_facts", "unknown",
                 "unstable_capability", "legacy_status_facts", "required_condition_facts"}
NATIVE_CODES = {"http_error", "transport_error", "invalid_response", "deadline_or_storage", "local_io_error",
                "malformed_facts", "validation_failed"}
SAFE_ERROR_CODES = {"diagnostic_validation_failed", "transport_refused", "native_source_unverified",
                    "diagnostic_context_invalid", "diagnostic_source_unverified", "private_output_invalid",
                    "unsafe_diagnostic_output", "diagnostic_credential_invalid", "diagnostic_target_changed",
                    "native_result_invalid"}


class Stopped(ValueError):
    """Only fixed codes cross the public boundary."""


def require(value, code="diagnostic_validation_failed"):
    if not value:
        raise Stopped(code)


def error_code(error):
    if type(error) is Stopped and str(error) in SAFE_ERROR_CODES:
        return str(error)
    return "native_diagnostic_stopped"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


def unique(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, "transport_refused")
        value[name] = item
    return value


def native_diagnostic(reason):
    """Recognize only the installed core's closed, credential-free formatter."""
    if not isinstance(reason, str):
        return None
    match = re.fullmatch(r"GitHub merge readiness blocked: stage=([a-z_]+); code=([a-z_]+)"
                         r"(?:; http_status=([1-5][0-9]{2}))?\.", reason)
    if match is None:
        return None
    stage, code, status = match.groups()
    if stage not in NATIVE_STAGES or code not in NATIVE_CODES or status is not None and code != "http_error":
        return None
    value = {"stage": stage, "code": code}
    if status is not None:
        value["http_status"] = int(status)
    return value


def timestamp(value):
    require(type(value) is dt.datetime and value.utcoffset() == dt.timedelta(0))
    return value.isoformat().replace("+00:00", "Z")


def clock():
    return dt.datetime.now(dt.UTC)


def _git(source, *arguments):
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull}
    result = subprocess.run(["git", "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull,
                             "-c", "core.fsmonitor=false", "-C", str(source), *arguments],
                            env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 4 * MAX_DOCUMENT, "native_source_unverified")
    return result.stdout


def _bytes(path):
    require(path.resolve() == path, "native_source_unverified")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_DOCUMENT, "native_source_unverified")
        data = os.read(descriptor, MAX_DOCUMENT + 1)
        after = os.fstat(descriptor)
        require(len(data) == info.st_size and (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns), "native_source_unverified")
        return data
    finally:
        os.close(descriptor)


def load_native(source):
    require(source.is_absolute() and source.resolve() == source, "native_source_unverified")
    require(_git(source, "rev-parse", "--verify", "HEAD").strip().decode("ascii") == CORE_REVISION,
            "native_source_unverified")
    package = source / "python/src/exacly"
    paths = set()
    for line in _git(source, "ls-tree", "-r", "--full-tree", CORE_REVISION, "--", "python/src/exacly").decode().splitlines():
        metadata, relative = line.split("\t", 1)
        mode, kind, oid = metadata.split()
        require(kind == "blob" and mode in ("100644", "100755"), "native_source_unverified")
        path = source / relative
        data = _bytes(path)
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == oid,
                "native_source_unverified")
        paths.add(path)
    actual = {path for path in package.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
    require(paths and actual == paths, "native_source_unverified")
    for name, expected in NATIVE_PINS.items():
        require(hashlib.sha256(_bytes(package / name)).hexdigest() == expected, "native_source_unverified")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "python/src"))
    # Match the frozen producer's preload before calculating native ELF fingerprints.
    importlib.import_module("pytest")
    for name in importlib.import_module("_pytest.config").default_plugins:
        importlib.import_module("_pytest." + name)
    for name in ("_pytest.junitxml", "xml.etree.ElementTree", "exacly.cli", "exacly.automatic_merge_live"):
        importlib.import_module(name)
    modules = {}
    for name in ("automatic_merge", "delivery_automation", "delivery_key", "github_merge", "execution_store"):
        module = importlib.import_module("exacly." + name)
        require(Path(module.__file__).resolve() == package / (name + ".py"), "native_source_unverified")
        modules[name] = module
    return SimpleNamespace(**modules)


def context():
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REPOSITORY": REPOSITORY["full_name"], "GITHUB_REPOSITORY_ID": str(REPOSITORY["id"]),
                "GITHUB_REF": REF, "GITHUB_JOB": JOB, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTOR_ID": "1679024",
                "GITHUB_WORKFLOW_REF": REPOSITORY["full_name"] + "/.github/workflows/app-bootstrap.yml@" + REF}
    require(all(os.environ.get(name) == value for name, value in expected.items()), "diagnostic_context_invalid")
    source, run = os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[1-9][0-9]*", run), "diagnostic_context_invalid")
    require(_git(ROOT, "rev-parse", "--verify", "HEAD").strip().decode("ascii") == source,
            "diagnostic_source_unverified")
    require(_git(ROOT, "show", source + ":tools/native_readiness_diagnostic.py") == _bytes(Path(__file__).resolve()),
            "diagnostic_source_unverified")
    return {"repository": REPOSITORY["full_name"], "repository_id": REPOSITORY["id"], "source": source,
            "run_id": int(run), "run_attempt": 1, "ref": REF, "job": JOB, "workflow_ref": expected["GITHUB_WORKFLOW_REF"]}


class PrivateOutput:
    def __init__(self, path, token):
        parent = Path(os.environ.get("RUNNER_TEMP", ""))
        require(path.is_absolute() and ".." not in path.parts and parent.is_absolute()
                and parent.resolve() == parent and path.parent == parent, "private_output_invalid")
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            self.fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.fchmod(self.fd, 0o700)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.path, self.token = path, token.encode()

    def write(self, name, value):
        require(name in SAFE_NAMES, "private_output_invalid")
        data = encoded(value)
        require(len(data) <= MAX_DOCUMENT and self.token not in data, "unsafe_diagnostic_output")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(data):
                count = os.write(fd, data[offset:])
                require(count > 0, "private_output_invalid")
                offset += count
            os.fsync(fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def allowed_requests(spec, github):
    base, head, merge = (spec[name] for name in ("base_revision", "head_revision", "merge_revision"))
    paths = {
        PREFIX: "repository",
        "/installation/repositories?per_page=100": "installation_scope",
        PREFIX + "/branches/main/protection": "protection",
        PREFIX + "/branches/main/protection/required_signatures": "signatures",
        PREFIX + "/rules/branches/main": "effective_rules",
        PREFIX + "/pulls/5": "pull_request",
        PREFIX + "/commits/" + head + "/status?per_page=100": "head_statuses",
        PREFIX + "/commits/" + merge + "/status?per_page=100": "merge_statuses",
        PREFIX + "/compare/" + base + "..." + head + "?per_page=100": "ancestry",
        PREFIX + "/commits/" + merge + "/check-runs?filter=latest&per_page=100": "merge_checks",
        PREFIX + "/git/commits/" + merge: "merge_commit",
        PREFIX + "/git/trees/" + base + "?recursive=1": "base_tree",
        PREFIX + "/git/trees/" + head + "?recursive=1": "head_tree",
        PREFIX + "/git/ref/heads/main": "base_ref",
        PREFIX + "/git/ref/heads/" + spec["head_ref"].removeprefix("refs/heads/"): "head_ref",
        PREFIX + "/git/ref/tags/exacly-delivery-operations/" + spec["operation_key"].removeprefix("sha256:"): "marker_ref",
    }
    variables = {"owner": "whiteredhouse", "name": "exacly-delivery-acceptance", "number": 5}
    return {(API + path, "GET", None): label for path, label in paths.items()} | {
        (API + "/graphql", "POST", encoded({"query": github.READ_QUERY, "variables": variables})): "review",
        (API + "/graphql", "POST", encoded({"query": github.UNSTABLE_QUERY,
                                           "variables": {**variables, "base": "refs/heads/main"}})): "required_conditions",
    }


class ReadOnlyOpener:
    """A second independent write barrier around the real native HTTP adapter."""
    def __init__(self, spec, github, token, *, inner=None, monotonic=time.monotonic):
        self.allowed, self.token = allowed_requests(spec, github), token
        self.inner = inner or urllib.request.build_opener(NoRedirect())
        self.monotonic, self.deadline = monotonic, monotonic() + WORK_SECONDS
        self.attempts, self.seen, self.denied = [], set(), 0

    def open(self, request, timeout):
        body = None
        if request.data is not None:
            require(len(request.data) <= MAX_DOCUMENT, "transport_refused")
            try:
                body = encoded(json.loads(request.data, object_pairs_hook=unique))
            except (ValueError, TypeError):
                raise Stopped("transport_refused") from None
        key = (request.full_url, request.get_method(), body)
        if (key not in self.allowed or key in self.seen or len(self.attempts) >= MAX_READS
                or self.monotonic() >= self.deadline):
            self.denied += 1
            raise Stopped("transport_refused")
        headers = {name.lower(): value for name, value in request.header_items()}
        expected = {"authorization": "Bearer " + self.token, "accept": "application/vnd.github+json",
                    "x-github-api-version": "2026-03-10"}
        if body is not None:
            expected["content-type"] = "application/json"
        require(headers == expected, "transport_refused")
        require(0 < timeout <= WORK_SECONDS, "transport_refused")
        remaining = self.deadline - self.monotonic()
        require(remaining > 0, "transport_refused")
        self.seen.add(key)
        item = {"endpoint": self.allowed[key], "status": None}
        self.attempts.append(item)
        try:
            response = self.inner.open(request, timeout=min(timeout, remaining))
            status = getattr(response, "status", None)
            require(status is None or type(status) is int and 100 <= status <= 599, "transport_refused")
            item["status"] = status
            return BoundedResponse(response, self)
        except urllib.error.HTTPError as error:
            item["status"] = error.code if type(error.code) is int and 100 <= error.code <= 599 else None
            raise


class BoundedResponse:
    def __init__(self, response, opener):
        self.response, self.opener, self.received = response, opener, 0
        self.headers = response.headers

    def __enter__(self):
        self.response.__enter__()
        return self

    def __exit__(self, *args):
        return self.response.__exit__(*args)

    def read(self, size):
        require(type(size) is int and 0 <= size <= MAX_RESPONSE + 1
                and self.opener.monotonic() < self.opener.deadline, "transport_refused")
        data = self.response.read(min(size, MAX_RESPONSE + 1 - self.received))
        require(isinstance(data, bytes), "transport_refused")
        self.received += len(data)
        require(self.received <= MAX_RESPONSE and self.opener.monotonic() < self.opener.deadline,
                "transport_refused")
        return data


def drafts(spec, selected_context, token, installation_id, native, files, now):
    require(installation_id == 177653055 and re.fullmatch(r"[A-Za-z0-9_.-]{20,1024}", token),
            "diagnostic_credential_invalid")
    end = now + dt.timedelta(seconds=LEASE_SECONDS)
    mint = {"schema_version": "0.1.0", "kind": "trusted-github-actions-mint-run-attestation",
            "basis": "reviewed official action inputs and installation-id output; not a retained mint API response",
            "context": selected_context, "repository": REPOSITORY, "exacly_source_commit": CORE_REVISION,
            "mint_action": ACTION, "app_id": 5572362, "installation_id": installation_id,
            "requested_repository_ids": [REPOSITORY["id"]], "requested_permissions": PERMISSIONS,
            "token_digest": "sha256:" + hashlib.sha256(token.encode()).hexdigest(), "attested_at": timestamp(now),
            "local_use_lease_seconds": LEASE_SECONDS, "provider_mint_response_retained": False,
            "provider_expiry_verified": False, "independent_mint_approval": False, "merge_authority": False}
    candidate = {"app_id": 5572362, "installation_id": installation_id, "token_digest": mint["token_digest"],
                 "credential_kind": "github-app-installation-grant-v1",
                 "grant": {"schema_version": "0.2.0", "repository_ids": [REPOSITORY["id"]],
                           "permissions": PERMISSIONS, "not_before": timestamp(now), "not_after": timestamp(end),
                           "mint_provenance_digest": digest(mint)}}
    identity = {"schema_version": "0.1.0", "kind": "proposed-read-only-diagnostic-identity",
                "context": selected_context, "actor_candidate": candidate,
                "independent_approval_verified": False, "merge_authority": False}
    native.automatic_merge.validate_installation_grant_time(candidate, now=now)
    key = files.path / "diagnostic-only.key"
    key_id = native.delivery_key.initialize(key)
    configuration = {"schema_version": "0.1.0", "profile": "github-atomic-merge-v1", "repository": REPOSITORY,
                     "token_environment": "EXACLY_DELIVERY_MERGE_TOKEN",
                     "actor": {**candidate, "identity_approval_digest": digest(identity)},
                     "key": {"path": str(key), "id": key_id}, "call_limits": copy.deepcopy(spec["call_limits"])}
    configuration = native.automatic_merge.validate_configuration(configuration)
    policy = native.automatic_merge.validate_policy(spec["policy"])
    payload = {"schema_version": "0.1.0", "profile": "github-atomic-merge-v1", "head_ref": spec["head_ref"],
               "merge_revision": spec["merge_revision"], "merge_tree": spec["merge_tree"],
               "marker_ref": "refs/tags/exacly-delivery-operations/" + spec["operation_key"].removeprefix("sha256:"),
               "operation_profile_digest": native.automatic_merge.operation_profile_digest(configuration, policy),
               "contract_files": {name: copy.deepcopy(spec["protected_files"]) for name in policy["contract"]}}
    repository = {name: REPOSITORY[name] for name in ("id", "full_name")}
    request = {"schema_version": "0.1.0", "profile": "product-delivery-v1", "kind": "delivery-request",
               "objective": spec["objective"], "operation_key": spec["operation_key"], "stage": "merge",
               "subject": {"repository": repository, "head_repository": repository, "pull_request": 5,
                           "head_revision": spec["head_revision"], "base_revision": spec["base_revision"],
                           "base_ref": spec["base_ref"], "method": "merge"}, "native_payload_digest": digest(payload)}
    request = native.delivery_automation.validate_request(request)
    native.automatic_merge.validate_payload(request, payload, configuration, policy)
    files.write("mint-attestation.json", mint)
    files.write("actor-candidate.json", candidate)
    return configuration, policy, request, payload


def run_diagnostic(out, *, core_source, native=None, inner=None, selected_context=None, now=None):
    """One authentic read-only inspection; injected modules/transports are offline test seams."""
    report = {"schema_version": "0.1.0", "kind": "advisory-native-readiness-diagnostic",
              "status": "stopped", "stage": "context", "merge_authority": False,
              "independent_mint_approval": False, "delivery_journal_created": False,
              "original_journal_accessed": False, "original_trial_replayed": False,
              "provider_writes": 0, "provider_reads": 0, "inspect_calls": 0, "ready": False,
              "provider_count_scope": "native_readiness_inspection",
              "provider_write_count_basis": "native_inspect_zero_write_ceiling_and_fixed_request_firewall",
              "provider_read_count_basis": "request_attempts_counted_before_dispatch"}
    files = opener = None
    token = ""
    previous = os.environ.pop("EXACLY_DELIVERY_MERGE_TOKEN", None)
    try:
        selected_context, now = selected_context or context(), now or clock()
        spec = json.loads((ROOT / "config/native-positive-trial.json").read_bytes())
        require(digest(spec) == SPEC_DIGEST, "diagnostic_target_changed")
        token = os.environ.get("CANARY_APP_TOKEN", "")
        installation = os.environ.get("CANARY_INSTALLATION_ID", "")
        require(re.fullmatch(r"[1-9][0-9]*", installation) and int(installation) == 177653055,
                "diagnostic_credential_invalid")
        require(re.fullmatch(r"[A-Za-z0-9_.-]{20,1024}", token), "diagnostic_credential_invalid")
        report.update(context=selected_context, core_revision=CORE_REVISION, native_pins=NATIVE_PINS,
                      observed_at=timestamp(now), target={name: spec[name] for name in
                          ("pull_request", "base_revision", "head_revision", "merge_revision", "merge_tree")})
        report["stage"] = "native_runtime"
        native = native or load_native(core_source)
        report["stage"] = "private_diagnostic_inputs"
        files = PrivateOutput(out, token)
        configuration, policy, request, payload = drafts(spec, selected_context, token, int(installation), native, files, now)
        report["digests"] = {name: digest(value) for name, value in
                             (("configuration", configuration), ("policy", policy), ("request", request), ("payload", payload))}
        opener = ReadOnlyOpener(spec, native.github_merge, token, inner=inner)
        adapter = native.github_merge.GitHubMergeAdapter(configuration, policy, opener=opener)
        report["stage"] = "native_inspect"
        os.environ["EXACLY_DELIVERY_MERGE_TOKEN"] = token
        report["inspect_calls"] = 1
        result = adapter.inspect(request, payload, deadline=native.execution_store.Deadline(WORK_SECONDS))
        result = adapter.validate_result("inspect", request, payload, result)
        require(type(result["ready"]) is bool, "native_result_invalid")
        report.update(status="ready" if result["ready"] else "blocked", ready=result["ready"],
                      stage="complete", native_result_digest=digest(result), native_reason_digest=digest(result["reason"]))
        # Only the closed native formatter becomes public; arbitrary reason text stays hashed.
        if not result["ready"]:
            report["error_code"] = "native_readiness_blocked"
            selected = native_diagnostic(result["reason"])
            if selected is not None:
                report["native_diagnostic"] = selected
            else:
                report["native_diagnostic"] = {"code": "metadata_unavailable"}
    except Exception as error:  # noqa: BLE001 -- never echo provider, storage or credential exceptions
        report["error_code"] = error_code(error)
    finally:
        os.environ.pop("EXACLY_DELIVERY_MERGE_TOKEN", None)
        if previous is not None:
            os.environ["EXACLY_DELIVERY_MERGE_TOKEN"] = previous
        if opener is not None:
            report.update(provider_reads=len(opener.attempts), endpoint_attempts=opener.attempts,
                          transport_denied=opener.denied)
        if files is not None:
            try:
                files.write("native-readiness-diagnostic.json", report)
            except (OSError, ValueError, TypeError):
                report.update(status="stopped", ready=False, error_code="private_receipt_unavailable")
            finally:
                os.close(files.fd)
    if token and token.encode() in encoded(report):
        # The longest token-alphabet word in this fixed fallback is below the
        # credential's minimum length, so even synthetic tokens cannot be echoed.
        return {"status": "stopped"}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = run_diagnostic(args.out, core_source=args.core_source)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
