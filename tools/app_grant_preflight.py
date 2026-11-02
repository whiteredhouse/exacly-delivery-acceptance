"""Package advisory App mint metadata and check credentials/protection with native Exacly.

The pinned workflow mints/revokes the token. This program performs ten fixed reads,
never installs an actor configuration or supplies independent mint approval.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.error
import urllib.request

REPOSITORY = {"id": 1442278205, "full_name": "whiteredhouse/exacly-delivery-acceptance", "node_id": "R_kgDOVfdrPQ"}
APP_ID, INSTALLATION_ID = 5572362, 177653055
MAIN = "723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8"
HEAD = "7e5f04446bd7eb2bd69132f27e8d20c9a967a156"
MERGE = "3196bd964e77c0963d2f00ff20c71408a345b54c"
CORE_REVISION = "9a5cd90b8d3c3b2acc2a00e7e68e175558025432"
NATIVE_PINS = {
    "automatic_merge.py": "d8dce24220ba7ad8bb74c6b8bfab8996401c8973744754ae858a25eecfbb706f",
    "github_merge.py": "4108698fedad4c57f6362481f2f271c1aadc0b17e69d7b07abeaefbde6d944b9",
}
ACTION = "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
WORKFLOW_REF = REPOSITORY["full_name"] + "/.github/workflows/app-bootstrap.yml@refs/heads/codex/preflight-diagnostics"
API = "https://api.github.com"
API_VERSION = "2026-03-10"
PREFIX = "/repos/" + REPOSITORY["full_name"]
PERMISSIONS = {"contents": "write", "pull_requests": "read", "checks": "read", "administration": "read", "metadata": "read", "statuses": "read"}
READS = (PREFIX, "/installation/repositories?per_page=100", PREFIX + "/git/ref/heads/main",
         PREFIX + "/branches/main/protection", PREFIX + "/branches/main/protection/required_signatures",
         PREFIX + "/rules/branches/main")
STATUS_READS = tuple(PREFIX + "/commits/" + revision + "/status?per_page=100" for revision in (HEAD, MERGE))
COMPARE_READ = PREFIX + "/compare/" + MAIN + "..." + HEAD + "?per_page=100"
QUERY_VARIABLES = {"owner": "whiteredhouse", "name": "exacly-delivery-acceptance", "number": 5, "base": "refs/heads/main"}
EXPECTED_PROTECTION = {
    "checks": [{"context": "exacly-generated-merge", "app_id": 5572341}],
    "strict": True, "approvals": 1, "last_push_approval": True,
    "dismiss_stale_reviews": True, "code_owners": False, "enforce_admins": True,
    "required_linear_history": False, "allow_force_pushes": False, "allow_deletions": False,
    "required_conversation_resolution": True, "lock_branch": False, "required_signatures": False,
}
MAX_RESPONSE, WORK_SECONDS, LEASE_SECONDS = 1024 * 1024, 75, 900


class Stopped(Exception):
    """Details are deliberately excluded from public diagnostics."""


def require(value):
    if not value:
        raise Stopped()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value):
    require(type(value) is dt.datetime and value.utcoffset() == dt.timedelta(0))
    return value.isoformat().replace("+00:00", "Z")


def build_mint_attestation(token, installation_id, now):
    require(type(installation_id) is int and installation_id == INSTALLATION_ID)
    require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_.-]{20,1024}", token))
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REPOSITORY": REPOSITORY["full_name"], "GITHUB_REPOSITORY_ID": str(REPOSITORY["id"]),
                "GITHUB_REF": "refs/heads/codex/preflight-diagnostics", "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
                "GITHUB_JOB": "app-grant-preflight", "GITHUB_RUN_ATTEMPT": "1"}
    require(all(os.environ.get(name) == value for name, value in expected.items()))
    source, run = os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[1-9][0-9]*", run))
    return {
        "schema_version": "0.1.0", "kind": "trusted-github-actions-mint-run-attestation",
        "basis": "reviewed workflow/action inputs and observed installation-id output; not a retained mint API response",
        "repository": dict(REPOSITORY), "workflow_ref": WORKFLOW_REF,
        "workflow_source_commit": source, "exacly_source_commit": CORE_REVISION,
        "run_id": int(run), "run_attempt": 1,
        "run_url": "https://github.com/" + REPOSITORY["full_name"] + "/actions/runs/" + run,
        "job": "app-grant-preflight", "mint_action": ACTION, "fact_read_api_version": API_VERSION,
        "app_id": APP_ID, "installation_id": installation_id,
        "requested_repository_ids": [REPOSITORY["id"]], "requested_permissions": dict(PERMISSIONS),
        "token_digest": "sha256:" + hashlib.sha256(token.encode()).hexdigest(),
        "attested_at": timestamp(now), "local_use_lease_seconds": LEASE_SECONDS,
        "provider_mint_response_retained": False, "provider_expiry_verified": False,
        "independent_mint_approval": False, "merge_authority": False,
    }


def build_candidate(attestation, now):
    require(isinstance(attestation, dict) and attestation.get("attested_at") == timestamp(now))
    require(attestation.get("schema_version") == "0.1.0"
            and attestation.get("kind") == "trusted-github-actions-mint-run-attestation")
    require(type(attestation.get("app_id")) is int and attestation["app_id"] == APP_ID
            and type(attestation.get("installation_id")) is int and attestation["installation_id"] == INSTALLATION_ID)
    require(encoded(attestation.get("repository")) == encoded(REPOSITORY)
            and encoded(attestation.get("requested_repository_ids")) == encoded([REPOSITORY["id"]])
            and encoded(attestation.get("requested_permissions")) == encoded(PERMISSIONS))
    require(type(attestation.get("local_use_lease_seconds")) is int
            and attestation["local_use_lease_seconds"] == LEASE_SECONDS)
    require(attestation.get("workflow_ref") == WORKFLOW_REF and attestation.get("mint_action") == ACTION
            and attestation.get("exacly_source_commit") == CORE_REVISION)
    require(attestation.get("fact_read_api_version") == API_VERSION)
    require(type(attestation.get("run_id")) is int and attestation["run_id"] > 0
            and type(attestation.get("run_attempt")) is int and attestation["run_attempt"] == 1
            and attestation.get("job") == "app-grant-preflight")
    require(isinstance(attestation.get("workflow_source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", attestation["workflow_source_commit"])
            and attestation.get("run_url") == "https://github.com/" + REPOSITORY["full_name"]
            + "/actions/runs/" + str(attestation["run_id"]))
    require(attestation.get("provider_mint_response_retained") is False
            and attestation.get("provider_expiry_verified") is False
            and attestation.get("independent_mint_approval") is False and attestation.get("merge_authority") is False)
    require(isinstance(attestation.get("token_digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", attestation["token_digest"]))
    return {
        "app_id": APP_ID, "installation_id": INSTALLATION_ID,
        "token_digest": attestation["token_digest"], "credential_kind": "github-app-installation-grant-v1",
        "grant": {"schema_version": "0.2.0", "repository_ids": [REPOSITORY["id"]],
                  "permissions": dict(PERMISSIONS), "not_before": timestamp(now),
                  "not_after": timestamp(now + dt.timedelta(seconds=LEASE_SECONDS)),
                  "mint_provenance_digest": digest(attestation)},
    }


def load_native(source):
    require(source.is_absolute() and source.resolve() == source and re.fullmatch(r"[0-9a-f]{40}", CORE_REVISION))
    env = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull}
    result = subprocess.run(["git", "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull,
                             "-c", "core.fsmonitor=false", "-C", str(source), "rev-parse", "--verify", "HEAD"],
                            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=5, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 128 and result.stdout.strip().decode("ascii") == CORE_REVISION)
    for name, expected in NATIVE_PINS.items():
        path = source / "python/src/exacly" / name
        require(path.resolve() == path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode))
            data = os.read(fd, MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE and hashlib.sha256(data).hexdigest() == expected)
        finally:
            os.close(fd)
    from exacly import automatic_merge, github_merge
    require(Path(automatic_merge.__file__).resolve() == source / "python/src/exacly/automatic_merge.py")
    require(Path(github_merge.__file__).resolve() == source / "python/src/exacly/github_merge.py")
    return automatic_merge, github_merge


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def probes(query):
    require(isinstance(query, str) and query.startswith("query("))
    return (*(("GET", path, None) for path in (*READS, *STATUS_READS)),
            ("POST", "/graphql", {"query": query, "variables": dict(QUERY_VARIABLES)}),
            ("GET", COMPARE_READ, None))


def transport(method, url, headers, payload, timeout, *, query):
    require(any(method == verb and url == API + path and encoded(payload) == encoded(body)
                for verb, path, body in probes(query)))
    request = urllib.request.Request(url, data=None if payload is None else encoded(payload), headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise Stopped() from None


def unique_object(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value)
        value[name] = item
    return value


class FixedReads:
    def __init__(self, token, candidate, native, query, *, sender=None, clock=utcnow):
        self.token, self.candidate, self.native = token, candidate, native
        self.sender = sender or (lambda *args: transport(*args, query=query))
        self.clock, self.probes = clock, probes(query)
        self.deadline, self.seen, self.failed = time.monotonic() + WORK_SECONDS, set(), False

    def request(self, method, path, payload=None):
        require(not self.failed and len(self.seen) < len(self.probes) and path not in self.seen)
        verb, target, body = self.probes[len(self.seen)]
        require(method == verb and path == target and encoded(payload) == encoded(body))
        require(time.monotonic() < self.deadline)
        require("sha256:" + hashlib.sha256(self.token.encode()).hexdigest() == self.candidate["token_digest"])
        self.native.validate_installation_grant_time(self.candidate, now=self.clock())
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        self.seen.add(path)
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": API_VERSION, "User-Agent": "exacly-app-grant-preflight"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        self.failed = True
        status, body = self.sender(method, API + path, headers, payload, min(10, remaining))
        require(status == 200 and isinstance(body, bytes) and len(body) <= MAX_RESPONSE and time.monotonic() < self.deadline)
        value = json.loads(body, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(Stopped()))
        self.failed = False
        return value


def public_text(value, limit=255):
    require(isinstance(value, str) and 0 < len(value) <= limit
            and not any(ord(character) < 32 or ord(character) == 127 for character in value))
    return value


def bounded_count(value):
    require(type(value) is int and 0 <= value < 100)
    return value


def revision(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value))
    return value


def status_facts(value, expected):
    require(isinstance(value, dict) and value.get("sha") == expected)
    statuses, total = value.get("statuses"), bounded_count(value.get("total_count"))
    require(isinstance(statuses, list) and len(statuses) == total)
    selected = []
    for status in statuses:
        require(isinstance(status, dict) and status.get("state") in ("success", "pending", "failure", "error"))
        selected.append({"context": public_text(status.get("context")), "state": status["state"]})
    return {"sha": expected, "total_count": total, "statuses": selected}


def graphql_facts(value):
    require(isinstance(value, dict) and ("errors" not in value or value["errors"] == []))
    data = value.get("data")
    require(isinstance(data, dict) and isinstance(data.get("repository"), dict))
    repository = data["repository"]
    identity = {"id": repository.get("databaseId"), "full_name": repository.get("nameWithOwner"),
                "node_id": repository.get("id")}
    require(encoded(identity) == encoded(REPOSITORY))
    ref, pr = repository.get("ref"), repository.get("pullRequest")
    require(isinstance(ref, dict) and ref.get("prefix") == "refs/heads/" and ref.get("name") == "main"
            and isinstance(ref.get("target"), dict) and ref["target"].get("oid") == MAIN)
    require(isinstance(pr, dict) and type(pr.get("number")) is int and pr["number"] == 5
            and pr.get("headRefOid") == HEAD and pr.get("baseRefOid") == MAIN
            and isinstance(pr.get("potentialMergeCommit"), dict) and pr["potentialMergeCommit"].get("oid") == MERGE)
    policy = ref.get("branchProtectionRule")
    require(isinstance(policy, dict))
    flags = {name: policy.get(name) for name in
             ("requiresDeployments", "requiresConversationResolution", "restrictsPushes")}
    require(all(type(flag) is bool for flag in flags.values()))
    environments = policy.get("requiredDeploymentEnvironments")
    require(isinstance(environments, list) and len(environments) < 100)
    environments = [public_text(environment) for environment in environments]
    threads = pr.get("reviewThreads")
    require(isinstance(threads, dict))
    total, nodes, page = bounded_count(threads.get("totalCount")), threads.get("nodes"), threads.get("pageInfo")
    require(isinstance(nodes, list) and len(nodes) == total and isinstance(page, dict) and page.get("hasNextPage") is False)
    selected = []
    for node in nodes:
        require(isinstance(node, dict) and type(node.get("isResolved")) is bool)
        selected.append({"id": public_text(node.get("id")), "is_resolved": node["isResolved"]})
    require(len({node["id"] for node in selected}) == len(selected))
    return {
        "branch_policy": {"id": public_text(policy.get("id")), "pattern": public_text(policy.get("pattern")),
                          "requires_deployments": flags["requiresDeployments"],
                          "required_deployment_environments": environments,
                          "requires_conversation_resolution": flags["requiresConversationResolution"],
                          "restricts_pushes": flags["restrictsPushes"]},
        "review_threads": {"total_count": total, "has_next_page": False, "threads": selected},
    }


def comparison_facts(value):
    require(isinstance(value, dict) and isinstance(value.get("base_commit"), dict)
            and value["base_commit"].get("sha") == MAIN and isinstance(value.get("merge_base_commit"), dict))
    merge_base = revision(value["merge_base_commit"].get("sha"))
    require(value.get("status") in ("ahead", "behind", "diverged", "identical"))
    ahead, behind, total = (bounded_count(value.get(name)) for name in ("ahead_by", "behind_by", "total_commits"))
    commits = value.get("commits")
    require(isinstance(commits, list) and 0 < len(commits) == total == ahead)
    require(all(isinstance(commit, dict) for commit in commits))
    revisions = [revision(commit.get("sha")) for commit in commits]
    require(revisions[-1] == HEAD and len(set(revisions)) == len(revisions))
    return {"base_revision": MAIN, "head_revision": HEAD, "merge_base_revision": merge_base,
            "status": value["status"], "ahead_by": ahead, "behind_by": behind,
            "total_commits": total, "commit_revisions": revisions}


class PrivateOutput:
    def __init__(self, path, token):
        require(path.is_absolute() and ".." not in path.parts)
        parent = Path(os.environ.get("RUNNER_TEMP", ""))
        workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
        require(parent.is_absolute() and parent.resolve() == parent and path.parent == parent)
        require(workspace.is_absolute() and path != workspace and workspace not in path.parents)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            self.fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.fchmod(self.fd, 0o700)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.token = token.encode()

    def write(self, name, value):
        require(name in ("mint-attestation.json", "actor-candidate.json", "preflight.json", "readiness-endpoint-facts.json"))
        data = encoded(value) + b"\n"
        require(len(data) <= MAX_RESPONSE and self.token not in data)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                require(written > 0)
                offset += written
            os.fsync(fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)


def run_preflight(out, native=None, sender=None, clock=utcnow, core_source=None):
    report = {"credential_and_protection_candidate_checks_passed": False,
              "endpoint_access_checks_passed": False,
              "independent_mint_approval": False, "pr_readiness_verified": False, "merge_authority": False,
              "provider_writes": 0, "provider_reads": 0, "stage": "mint_context"}
    files = reader = None
    token = ""
    try:
        now = clock()
        token = os.environ.get("CANARY_APP_TOKEN", "")
        installation = os.environ.get("CANARY_INSTALLATION_ID", "")
        require(re.fullmatch(r"[1-9][0-9]*", installation) and int(installation) == INSTALLATION_ID)
        attestation = build_mint_attestation(token, int(installation), now)
        candidate = build_candidate(attestation, now)
        report["stage"] = "native_runtime"
        native, github = native or load_native(core_source)
        native.validate_installation_grant_time(candidate, now=clock())
        files = PrivateOutput(out, token)
        files.write("mint-attestation.json", attestation)
        files.write("actor-candidate.json", candidate)
        reader = FixedReads(token, candidate, native, github.UNSTABLE_QUERY, sender=sender, clock=clock)
        responses = []
        for path in READS:
            report["stage"] = ("repository", "installation_scope", "main_ref", "protection", "signatures", "effective_rules")[len(responses)]
            responses.append(reader.request("GET", path))
        repository, scope, main, protection, signatures, rules = responses
        report["stage"] = "candidate_facts"
        require(isinstance(repository, dict))
        identity = {key: repository.get(key) for key in REPOSITORY}
        require(encoded(identity) == encoded(REPOSITORY))
        require(repository.get("private") is False and repository.get("archived") is False
                and repository.get("disabled") is False and repository.get("default_branch") == "main")
        raw_roles = repository.get("permissions")
        roles = {} if raw_roles is None else raw_roles
        require(isinstance(roles, dict))
        roles = {key: roles.get(key) for key in ("admin", "maintain", "push")}
        require(all(value is None or type(value) is bool for value in roles.values()))
        report["repository_roles"] = roles
        require(isinstance(scope, dict) and type(scope.get("total_count")) is int and scope["total_count"] == 1)
        repositories = scope.get("repositories")
        require(isinstance(repositories, list) and len(repositories) == 1 and isinstance(repositories[0], dict)
                and repositories[0].get("id") == REPOSITORY["id"] and repositories[0].get("full_name") == REPOSITORY["full_name"])
        facts = {"repository": {**identity, **roles}, "installation_repository_ids": [repositories[0]["id"]]}
        require("identity_approval_digest" not in candidate)
        checked = native.validate_installation_grant_candidate(REPOSITORY, candidate, facts)
        require("identity_approval_digest" not in checked and encoded(checked) == encoded(candidate))
        require(isinstance(main, dict) and main.get("ref") == "refs/heads/main"
                and isinstance(main.get("object"), dict) and main["object"].get("type") == "commit"
                and main["object"].get("sha") == MAIN)
        require(isinstance(rules, list) and rules == [])
        report["stage"] = "protection_candidate"
        require(isinstance(protection, dict) and isinstance(signatures, dict) and type(signatures.get("enabled")) is bool)
        require("required_signatures" not in protection or encoded(protection["required_signatures"]) == encoded(signatures))
        actual = {**protection, "required_signatures": signatures}
        snapshot = native.protection_snapshot(actual)
        report["protection_snapshot_digest"] = digest(snapshot)
        require(encoded(snapshot) == encoded(EXPECTED_PROTECTION))
        normalized = native.protection_facts(actual)
        native.validate_installation_grant_time(candidate, now=clock())
        report.update(credential_and_protection_candidate_checks_passed=True,
                      actor_facts=facts, protection_facts=normalized, effective_rules=[], current_main=MAIN,
                      mint_attestation_digest=digest(attestation), actor_candidate_digest=digest(candidate))
        endpoints = {
            "schema_version": "0.1.0", "kind": "readiness-endpoint-access-facts",
            "repository": dict(REPOSITORY), "pull_request": 5, "base_ref": "refs/heads/main",
            "base_revision": MAIN, "head_revision": HEAD, "merge_revision": MERGE,
            "independent_mint_approval": False, "pr_readiness_verified": False, "merge_authority": False,
        }
        report["stage"] = "head_legacy_status_access"
        head = status_facts(reader.request("GET", STATUS_READS[0]), HEAD)
        report["stage"] = "merge_legacy_status_access"
        merged = status_facts(reader.request("GET", STATUS_READS[1]), MERGE)
        endpoints["legacy_statuses"] = {"head": head, "merge": merged}
        report["stage"] = "graphql_policy_access"
        endpoints.update(graphql_facts(reader.request("POST", "/graphql", {
            "query": github.UNSTABLE_QUERY, "variables": dict(QUERY_VARIABLES)})))
        report["stage"] = "comparison_access"
        endpoints["comparison"] = comparison_facts(reader.request("GET", COMPARE_READ))
        native.validate_installation_grant_time(candidate, now=clock())
        require(len(reader.seen) == 10)
        endpoints["endpoint_access_checks_passed"] = True
        files.write("readiness-endpoint-facts.json", endpoints)
        report.update(endpoint_access_checks_passed=True, stage="complete", readiness_endpoint_facts_digest=digest(endpoints))
    except Exception:
        report["error_code"] = ("readiness_endpoint_checks_failed" if report["credential_and_protection_candidate_checks_passed"]
                                else "candidate_or_protection_checks_failed")
    finally:
        report["provider_reads"] = len(reader.seen) if reader else 0
        if files is not None:
            try:
                files.write("preflight.json", report)
            except Exception:
                report["credential_and_protection_candidate_checks_passed"] = False
                report["endpoint_access_checks_passed"] = False
                report["error_code"] = "private_receipt_unavailable"
            finally:
                os.close(files.fd)
    if token and token.encode() in encoded(report):
        return {"credential_and_protection_candidate_checks_passed": False,
                "endpoint_access_checks_passed": False,
                "independent_mint_approval": False, "pr_readiness_verified": False, "merge_authority": False,
                "provider_writes": 0, "provider_reads": len(reader.seen) if reader else 0,
                "stage": "redaction", "error_code": "credential_redaction"}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run_preflight(args.out, core_source=args.core_source)
    print(json.dumps(result, sort_keys=True))
    return 0 if (result["credential_and_protection_candidate_checks_passed"] and result["endpoint_access_checks_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
