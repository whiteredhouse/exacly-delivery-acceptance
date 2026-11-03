"""Fixed App bootstrap and exact-merge check for the dedicated public canary.

The official workflow mints its role token. This helper never accepts a private
key, merges a PR, writes a Git ref or changes repository policy. Its only provider
mutation is at most one real Checks API creation after fixed local verification.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).absolute().parent.parent
REPOSITORY = {"id": 1442278205, "full_name": "whiteredhouse/exacly-delivery-acceptance"}
ROLES = {
    "verifier": {"app_id": 5572341, "installation_id": 177653019},
    "merger": {"app_id": 5572362, "installation_id": 177653055},
}
CHECK_NAME = "exacly-generated-merge"
PREFIX = "/repos/" + REPOSITORY["full_name"]
API = "https://api.github.com"
PUBLIC_GIT = "https://github.com/" + REPOSITORY["full_name"] + ".git"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_URL = re.compile(r"https://github\.com/whiteredhouse/exacly-delivery-acceptance/actions/runs/[1-9][0-9]*\Z")
MAX_RESPONSE = 1024 * 1024
MAX_HTTP_CALLS = 40
WORK_SECONDS = 75
PREFLIGHT_STAGES = frozenset((
    "configuration", "installation_identity", "trusted_source", "role_token",
    "repository_read", "installation_scope_read", "main_ref_read",
    "actor_permissions", "classic_protection_read", "required_signatures_read",
    "effective_rules_read", "classic_policy", "result_persistence",
))
PREFLIGHT_REASONS = frozenset((
    "invalid trusted App configuration",
    "trusted App configuration differs from fixed canary identities",
    "minted installation ID differs from trusted role configuration",
    "trusted source HEAD differs from selected source commit",
    "CANARY_APP_TOKEN is required",
    "repository identity changed", "public canary repository is unavailable",
    "token must select exactly one repository", "token repository scope changed",
    "current main differs from trusted source",
    "merge actor is not a non-admin/non-maintainer push actor",
    "effective rulesets are unsupported by current merge profile",
    "classic protection/signature facts are unavailable",
    "required App check configuration changed", "independent review policy changed",
    "review bypass configuration is unknown", "classic protection capability changed",
    "GitHub rejected the bounded request", "GitHub request outcome is unavailable",
    "request is outside fixed canary API scope", "HTTP read/time budget exhausted",
    "GitHub response status is unsupported", "HTTP deadline expired",
    "duplicate JSON key", "bounded JSON response required", "nonfinite JSON value",
    "JSON response could not be decoded", "local evidence exceeds byte bound",
    "local evidence write was incomplete", "bounded bootstrap could not complete",
))
QUERY = """query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){databaseId id pullRequest(number:$number){number state isDraft merged isCrossRepository headRefOid baseRefOid potentialMergeCommit{oid}}}}"""


class Refused(Exception):
    """A fixed safe diagnostic; raw transport errors are never rendered."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def decode(data):
    require(isinstance(data, bytes) and len(data) <= MAX_RESPONSE, "bounded JSON response required")
    try:
        return json.loads(data, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON value")))
    except (UnicodeError, ValueError):
        raise Refused("JSON response could not be decoded") from None


def clean_environment(*, public_fetch=False):
    """No role token, action token, private key or user Git configuration enters a child."""
    value = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    if public_fetch:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"):
            if name in os.environ:
                value[name] = os.environ[name]
        if "SSL_CERT_FILE" in value:
            value["GIT_SSL_CAINFO"] = value["SSL_CERT_FILE"]
    value.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                  "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull})
    return value


def clean_git(verifier, path, deadline):
    # Git's reviewed constructor has no subprocess. Replace its inherited-env
    # copy before any .read/.object call, including trusted-source inventory.
    git = verifier["Git"](path, deadline)
    git.environment = clean_environment()
    return git


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def transport(method, url, headers, payload, timeout):
    request = urllib.request.Request(url, data=None if payload is None else encoded(payload), headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise Refused("GitHub rejected the bounded request") from None
    except (OSError, urllib.error.URLError, TimeoutError):
        raise Refused("GitHub request outcome is unavailable") from None


class Client:
    def __init__(self, token, deadline, sender=None):
        require(isinstance(token, str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,1024}", token)), "CANARY_APP_TOKEN is required")
        self.token, self.deadline, self.sender = token, deadline, sender or transport
        self.calls, self.check_posts = 0, 0
        self.stage = None

    def request(self, method, path, payload=None):
        reads = (
            path == "/installation/repositories?per_page=100" or path == PREFIX or
            path in (PREFIX + "/branches/main/protection", PREFIX + "/branches/main/protection/required_signatures", PREFIX + "/rules/branches/main") or
            bool(re.fullmatch(re.escape(PREFIX) + r"/git/ref/heads/[A-Za-z0-9._/-]+", path)) or
            bool(re.fullmatch(re.escape(PREFIX) + r"/pulls/[1-9][0-9]*", path)) or
            bool(re.fullmatch(re.escape(PREFIX) + r"/git/commits/[0-9a-f]{40}", path)) or
            bool(re.fullmatch(re.escape(PREFIX) + r"/git/trees/[0-9a-f]{40}\?recursive=1", path)) or
            bool(re.fullmatch(re.escape(PREFIX) + r"/commits/[0-9a-f]{40}/check-runs\?filter=latest&per_page=100", path))
        )
        graph = method == "POST" and path == "/graphql" and isinstance(payload, dict) and payload.get("query") == QUERY and set(payload) == {"query", "variables"} and isinstance(payload.get("variables"), dict) and set(payload["variables"]) == {"owner", "name", "number"} and payload["variables"]["owner"] == "whiteredhouse" and payload["variables"]["name"] == "exacly-delivery-acceptance" and type(payload["variables"]["number"]) is int and payload["variables"]["number"] > 0
        mutation = method == "POST" and path == PREFIX + "/check-runs" and isinstance(payload, dict) and payload.get("name") == CHECK_NAME and isinstance(payload.get("head_sha"), str) and SHA.fullmatch(payload["head_sha"])
        require((method == "GET" and reads and payload is None) or graph or mutation, "request is outside fixed canary API scope")
        require(self.calls < MAX_HTTP_CALLS and self.deadline > time.monotonic(), "HTTP read/time budget exhausted")
        if mutation:
            require(self.check_posts == 0, "check creation cannot be retried")
            self.check_posts += 1
        self.calls += 1
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "exacly-delivery-acceptance"}
        status, data = self.sender(method, API + path, headers, payload, min(10, self.deadline - time.monotonic()))
        require(status == (201 if mutation else 200), "GitHub response status is unsupported")
        require(self.deadline > time.monotonic(), "HTTP deadline expired")
        return decode(data)


class ActionsReader(Client):
    """Separate Actions-read credential; the producer App needs no Actions permission."""

    def request(self, method, path, payload=None):
        allowed = bool(re.fullmatch(re.escape(PREFIX) + r"/actions/runs/[1-9][0-9]*", path)) or path == PREFIX + "/actions/workflows/app-bootstrap.yml/runs?event=workflow_dispatch&branch=main&per_page=100"
        require(method == "GET" and payload is None and allowed, "request is outside fixed Actions-read scope")
        require(self.calls < 4 and self.deadline > time.monotonic(), "Actions read/time budget exhausted")
        self.calls += 1
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "exacly-delivery-acceptance"}
        status, data = self.sender(method, API + path, headers, None, min(10, self.deadline - time.monotonic()))
        require(status == 200 and self.deadline > time.monotonic(), "Actions read is unavailable")
        return decode(data)


def hosted_guard(source, arguments, deadline, sender=None):
    """Conservative hosted history gate, not a global Checks API idempotency key."""
    try:
        expected_environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": REPOSITORY["full_name"], "GITHUB_REPOSITORY_ID": str(REPOSITORY["id"]), "GITHUB_SHA": source, "GITHUB_WORKFLOW_REF": REPOSITORY["full_name"] + "/.github/workflows/app-bootstrap.yml@refs/heads/main"}
        require(all(os.environ.get(key) == value for key, value in expected_environment.items()), "trusted hosted workflow context is unavailable")
        run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
        require(re.fullmatch(r"[1-9][0-9]*", run_id) and re.fullmatch(r"[1-9][0-9]*", attempt), "hosted run/attempt is unavailable")
        require(arguments.run_url == "https://github.com/" + REPOSITORY["full_name"] + "/actions/runs/" + run_id, "run evidence URL differs from current hosted run")
        reader = ActionsReader(os.environ.get("CANARY_ACTIONS_READ_TOKEN"), deadline, sender)
        run = reader.request("GET", PREFIX + "/actions/runs/" + run_id)
        title = "canary-bootstrap:verify:pr-" + str(arguments.pr_number)
        def valid(value):
            return isinstance(value, dict) and value.get("id") == int(run_id) and value.get("run_attempt") == int(attempt) and value.get("event") == "workflow_dispatch" and value.get("head_branch") == "main" and value.get("head_sha") == source and value.get("path") == ".github/workflows/app-bootstrap.yml" and value.get("display_title") == title and value.get("status") == "in_progress" and isinstance(value.get("repository"), dict) and value["repository"].get("id") == REPOSITORY["id"] and value["repository"].get("full_name") == REPOSITORY["full_name"]
        require(valid(run) and type(run.get("workflow_id")) is int and run["workflow_id"] > 0 and type(run.get("run_number")) is int and run["run_number"] > 0, "current server workflow identity differs")
        history = reader.request("GET", PREFIX + "/actions/workflows/app-bootstrap.yml/runs?event=workflow_dispatch&branch=main&per_page=100")
        require(isinstance(history, dict) and isinstance(history.get("workflow_runs"), list) and type(history.get("total_count")) is int and history["total_count"] == len(history["workflow_runs"]) and history["total_count"] < 100, "complete bounded workflow history is unavailable")
        runs = history["workflow_runs"]
        require(all(isinstance(item, dict) and type(item.get("id")) is int and item["id"] > 0 and type(item.get("run_number")) is int and item["run_number"] > 0 and type(item.get("run_attempt")) is int and item["run_attempt"] > 0 and isinstance(item.get("display_title"), str) and re.fullmatch(r"canary-bootstrap:(?:preflight:pr-0|verify:pr-[1-9][0-9]{0,9})", item["display_title"]) and item.get("status") in ("queued", "requested", "pending", "waiting", "in_progress", "completed") and item.get("conclusion") in (None, "success", "failure", "cancelled", "timed_out", "action_required", "neutral", "skipped", "stale", "startup_failure") and item.get("workflow_id") == run["workflow_id"] and item.get("path") == run["path"] and item.get("event") == "workflow_dispatch" and item.get("head_branch") == "main" and isinstance(item.get("head_sha"), str) and SHA.fullmatch(item["head_sha"]) and isinstance(item.get("repository"), dict) and item["repository"].get("id") == REPOSITORY["id"] and item["repository"].get("full_name") == REPOSITORY["full_name"] for item in runs), "workflow history identity is unavailable")
        require(len({item["id"] for item in runs}) == len(runs), "workflow history is ambiguous")
        current = [item for item in runs if item["id"] == int(run_id)]
        require(len(current) == 1 and valid(current[0]) and current[0]["run_number"] == run["run_number"], "current hosted run is not visible in consistent history")
        prior = [item["id"] for item in runs if item["id"] != int(run_id) and item["run_number"] < run["run_number"] and item["display_title"] == title and (item["status"] != "completed" or item["conclusion"] != "success")]
        allowed = int(attempt) == 1 and not prior
        return {"new_post_allowed": allowed, "current_run_id": int(run_id), "attempt": int(attempt), "prior_uncertain_run_ids": prior, "actions_reads": reader.calls, "reason": "first hosted attempt with complete successful prior history" if allowed else "rerun or prior unsuccessful verification requires read-only reconciliation"}
    except Exception:
        return {"new_post_allowed": False, "reason": "trusted current run and complete hosted history could not be established"}


class Bundle:
    def __init__(self, path, verifier):
        self.path = Path(path)
        require(self.path.is_absolute() and ".." not in self.path.parts and self.path != ROOT and ROOT not in self.path.parents, "new absolute output outside trusted source required")
        parent = verifier["open_directory"](self.path.parent)
        try:
            os.mkdir(self.path.name, 0o700, dir_fd=parent)
            self.descriptor = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.fchmod(self.descriptor, 0o700)
            os.fsync(parent)
        finally:
            os.close(parent)

    def write(self, name, value):
        data = encoded(value) + b"\n"
        require(len(data) <= MAX_RESPONSE, "local evidence exceeds byte bound")
        file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.descriptor)
        try:
            os.fchmod(file, 0o600)
            offset = 0
            while offset < len(data):
                written = os.write(file, data[offset:])
                require(written > 0, "local evidence write was incomplete")
                offset += written
            os.fsync(file)
            os.fsync(self.descriptor)
        finally:
            os.close(file)


def load_configuration(verifier):
    value = decode(verifier["read_file"](ROOT, "config/apps.json", 16384))
    require(isinstance(value, dict) and set(value) == {"repository", "check_name", "apps"}, "invalid trusted App configuration")
    require(value["repository"] == REPOSITORY and value["check_name"] == CHECK_NAME and value["apps"] == ROLES, "trusted App configuration differs from fixed canary identities")
    return value


def source_snapshot(verifier, deadline, selected=None):
    git = clean_git(verifier, ROOT, deadline)
    revision = git.read("rev-parse", "HEAD").decode("ascii").strip()
    require(bool(SHA.fullmatch(revision)) and (selected is None or revision == selected), "trusted source HEAD differs from selected source commit")
    tree, _ = git.commit(revision)
    inventory = git.inventory(tree)
    verifier["trusted_sources"](ROOT, inventory)
    return git, revision, inventory


def scope(client):
    client.stage = "repository_read"
    repository = client.request("GET", PREFIX)
    require(isinstance(repository, dict) and repository.get("id") == REPOSITORY["id"] and repository.get("full_name") == REPOSITORY["full_name"], "repository identity changed")
    require(repository.get("private") is False and repository.get("default_branch") == "main" and repository.get("archived") is False and repository.get("disabled") is False, "public canary repository is unavailable")
    client.stage = "installation_scope_read"
    installation = client.request("GET", "/installation/repositories?per_page=100")
    require(isinstance(installation, dict) and type(installation.get("total_count")) is int and installation["total_count"] == 1, "token must select exactly one repository")
    repositories = installation.get("repositories")
    require(isinstance(repositories, list) and len(repositories) == 1 and repositories[0].get("id") == REPOSITORY["id"] and repositories[0].get("full_name") == REPOSITORY["full_name"], "token repository scope changed")
    return repository


def current_main(client, source):
    client.stage = "main_ref_read"
    reference = client.request("GET", PREFIX + "/git/ref/heads/main")
    require(isinstance(reference, dict) and reference.get("ref") == "refs/heads/main" and reference.get("object", {}).get("sha") == source and reference.get("object", {}).get("type") == "commit", "current main differs from trusted source")


def merger_access(client, repository):
    client.stage = "actor_permissions"
    permissions = repository.get("permissions")
    require(isinstance(permissions, dict) and permissions.get("admin") is False and permissions.get("maintain") is False and permissions.get("push") is True, "merge actor is not a non-admin/non-maintainer push actor")
    client.stage = "classic_protection_read"
    protection = client.request("GET", PREFIX + "/branches/main/protection")
    client.stage = "required_signatures_read"
    signatures = client.request("GET", PREFIX + "/branches/main/protection/required_signatures")
    client.stage = "effective_rules_read"
    rules = client.request("GET", PREFIX + "/rules/branches/main")
    client.stage = "classic_policy"
    require(rules == [], "effective rulesets are unsupported by current merge profile")
    require(isinstance(protection, dict) and isinstance(signatures, dict) and signatures.get("enabled") is False, "classic protection/signature facts are unavailable")
    checks, reviews = protection.get("required_status_checks"), protection.get("required_pull_request_reviews")
    require(isinstance(checks, dict) and checks.get("strict") is True and checks.get("checks") == [{"context": CHECK_NAME, "app_id": ROLES["verifier"]["app_id"]}], "required App check configuration changed")
    require(isinstance(reviews, dict) and reviews.get("require_last_push_approval") is True and type(reviews.get("required_approving_review_count")) is int and reviews["required_approving_review_count"] == 1 and reviews.get("dismiss_stale_reviews") is True and reviews.get("require_code_owner_reviews") is False, "independent review policy changed")
    bypass = reviews.get("bypass_pull_request_allowances", {})
    require(isinstance(bypass, dict) and set(bypass) <= {"users", "teams", "apps"} and all(bypass.get(key, []) == [] for key in ("users", "teams", "apps")), "review bypass configuration is unknown")
    for name, expected in (("enforce_admins", True), ("required_linear_history", False), ("allow_force_pushes", False), ("allow_deletions", False), ("required_conversation_resolution", True), ("lock_branch", False)):
        require(isinstance(protection.get(name), dict) and protection[name].get("enabled") is expected, "classic protection capability changed")
    return {"admin": False, "maintain": False, "push": True, "classic_protection_read": True, "required_signatures_read": True, "effective_rules": [], "protection_sha256": digest(encoded(protection))}


def identity(client, number, source, repository, verifier):
    pr = client.request("GET", PREFIX + "/pulls/" + str(number))
    require(isinstance(pr, dict) and pr.get("number") == number and pr.get("state") == "open" and pr.get("draft") is False and pr.get("merged") is False, "selected PR is not open and reviewable")
    base, head = pr.get("base"), pr.get("head")
    require(isinstance(base, dict) and isinstance(head, dict), "PR refs are unavailable")
    for side in (base, head):
        require(isinstance(side.get("repo"), dict) and side["repo"].get("id") == REPOSITORY["id"] and side["repo"].get("full_name") == REPOSITORY["full_name"], "cross-repository PR is unsupported")
    require(base.get("ref") == "main" and base.get("sha") == source, "PR base differs from selected trusted main")
    base_ref, head_ref = "refs/heads/main", "refs/heads/" + head.get("ref", "")
    verifier["safe_ref"](head_ref)
    require(head_ref != base_ref and isinstance(head.get("sha"), str) and SHA.fullmatch(head["sha"]), "invalid PR head identity")
    merge = pr.get("merge_commit_sha")
    require(isinstance(merge, str) and SHA.fullmatch(merge) and len({source, head["sha"], merge}) == 3, "generated merge identity is unavailable")
    current_main(client, source)
    head_now = client.request("GET", PREFIX + "/git/ref/" + head_ref.removeprefix("refs/"))
    require(isinstance(head_now, dict) and head_now.get("ref") == head_ref and head_now.get("object", {}).get("sha") == head["sha"] and head_now.get("object", {}).get("type") == "commit", "current head changed")
    graph = client.request("POST", "/graphql", {"query": QUERY, "variables": {"owner": "whiteredhouse", "name": "exacly-delivery-acceptance", "number": number}})
    require(isinstance(graph, dict) and not graph.get("errors"), "GraphQL merge identity is unavailable")
    graph_repo = graph.get("data", {}).get("repository", {})
    require(graph_repo.get("databaseId") == REPOSITORY["id"] and graph_repo.get("id") == repository.get("node_id") and isinstance(graph_repo.get("id"), str), "GraphQL repository identity changed")
    selected = graph_repo.get("pullRequest", {})
    require(selected.get("number") == number and selected.get("state") == "OPEN" and selected.get("isDraft") is False and selected.get("merged") is False and selected.get("isCrossRepository") is False and selected.get("headRefOid") == head["sha"] and selected.get("baseRefOid") == source and selected.get("potentialMergeCommit", {}).get("oid") == merge, "REST/GraphQL B/H/M identities disagree")
    commit = client.request("GET", PREFIX + "/git/commits/" + merge)
    require(isinstance(commit, dict) and commit.get("sha") == merge and isinstance(commit.get("tree"), dict) and isinstance(commit["tree"].get("sha"), str) and SHA.fullmatch(commit["tree"]["sha"]), "merge commit tree is unavailable")
    parents = commit.get("parents")
    require(isinstance(parents, list) and [parent.get("sha") for parent in parents] == [source, head["sha"]], "generated merge parents differ from ordered B/H")
    head_commit = client.request("GET", PREFIX + "/git/commits/" + head["sha"])
    require(isinstance(head_commit, dict) and head_commit.get("sha") == head["sha"] and isinstance(head_commit.get("tree"), dict) and isinstance(head_commit["tree"].get("sha"), str) and SHA.fullmatch(head_commit["tree"]["sha"]), "head commit tree is unavailable")
    return {"repository_id": REPOSITORY["id"], "pr_number": number, "base_ref": base_ref, "head_ref": head_ref, "base_revision": source, "head_revision": head["sha"], "head_tree": head_commit["tree"]["sha"], "merge_revision": merge, "merge_tree": commit["tree"]["sha"], "merge_parents": [source, head["sha"]]}


def bounded_candidate_trees(client, verifier, selected, inventory):
    directories = {path.rsplit("/", depth)[0] for path in inventory for depth in range(1, path.count("/") + 1)}
    evidence = {}
    for kind in ("head", "merge"):
        tree = selected[kind + "_tree"]
        response = client.request("GET", PREFIX + "/git/trees/" + tree + "?recursive=1")
        require(isinstance(response, dict) and response.get("sha") == tree and response.get("truncated") is False and isinstance(response.get("tree"), list) and len(response["tree"]) <= 80, "complete bounded candidate tree is unavailable")
        files, seen = {}, set()
        for item in response["tree"]:
            require(isinstance(item, dict), "candidate tree entry is invalid")
            path = verifier["safe_path"](item.get("path"))
            require(path not in seen and isinstance(item.get("sha"), str) and SHA.fullmatch(item["sha"]), "candidate tree path/object is invalid")
            seen.add(path)
            if item.get("type") == "tree":
                require(item.get("mode") == "040000" and path in directories, "unexpected candidate directory")
            else:
                require(item.get("type") == "blob" and item.get("mode") == "100644" and type(item.get("size")) is int and 0 <= item["size"] <= verifier["MAX_FILE_BYTES"], "candidate blob mode/size is unsupported")
                files[path] = {"mode": "100644", "blob": item["sha"], "size": item["size"]}
        require(0 < len(files) <= verifier["MAX_FILES"] and set(files) == set(inventory), "candidate file inventory differs before public fetch")
        require(all(files[path]["blob"] == item["blob"] and files[path]["mode"] == item["mode"] for path, item in inventory.items() if path != "canary.txt"), "candidate changes protected source before public fetch")
        require(files["canary.txt"]["size"] <= 40, "candidate canary exceeds byte bound")
        evidence[kind] = files
    return evidence


def fetch_public(verifier, git, candidate, selected, deadline):
    environment = clean_environment(public_fetch=True)
    common = [git.executable, "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false", "-c", "credential.helper=", "-c", "http.extraHeader=", "-c", "http.followRedirects=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    verifier["command"](common + ["init", "--bare", str(candidate)], environment=environment, deadline=min(deadline, time.monotonic() + 5))
    verifier["command"](common + ["-C", str(candidate), "fetch", "--no-tags", "--no-recurse-submodules", "--depth=1", PUBLIC_GIT, selected["base_revision"] + ":" + selected["base_ref"], selected["head_revision"] + ":" + selected["head_ref"], selected["merge_revision"] + ":refs/verification/merge"], environment=environment, deadline=min(deadline, time.monotonic() + 30))


def checks(client, merge):
    result = client.request("GET", PREFIX + "/commits/" + merge + "/check-runs?filter=latest&per_page=100")
    require(isinstance(result, dict) and isinstance(result.get("check_runs"), list) and type(result.get("total_count")) is int and result["total_count"] == len(result["check_runs"]) and result["total_count"] < 100, "latest check inventory is incomplete")
    require(all(isinstance(check, dict) and isinstance(check.get("name"), str) and 0 < len(check["name"]) <= 100 and isinstance(check.get("app"), dict) and type(check["app"].get("id")) is int and check["app"]["id"] > 0 and check.get("head_sha") == merge for check in result["check_runs"]), "latest check identity inventory is unavailable")
    selected = [check for check in result["check_runs"] if isinstance(check, dict) and check.get("name") == CHECK_NAME]
    require(len(selected) <= 1, "duplicate or ambiguous named checks block publication")
    if selected:
        require(selected[0].get("app", {}).get("id") == ROLES["verifier"]["app_id"], "foreign App owns the selected check name")
    return selected


def same_check(check, body):
    require(isinstance(check, dict) and type(check.get("id")) is int and check["id"] > 0, "check result identity is unavailable")
    require(check.get("app", {}).get("id") == ROLES["verifier"]["app_id"], "actual check App differs from selected verifier App")
    require(all(check.get(key) == body[key] for key in ("name", "head_sha", "status", "conclusion", "external_id")), "existing check is not the exact verified result")
    require(isinstance(check.get("details_url"), str) and RUN_URL.fullmatch(check["details_url"]), "check evidence locator is outside the selected repository")
    output = check.get("output")
    require(isinstance(output, dict) and all(output.get(key) == value for key, value in body["output"].items()) and output.get("annotations_count", 0) == 0, "check proof output differs from actual fixed verification")
    return {"id": check["id"], "app_id": ROLES["verifier"]["app_id"], "head_sha": body["head_sha"], "external_id": body["external_id"], "conclusion": "success", "details_url": check["details_url"]}


def verify(client, verifier, bundle, source_git, source, inventory, repository, arguments, deadline, sender=None):
    require(type(arguments.pr_number) is int and 0 < arguments.pr_number < 10**10, "bounded positive PR number required")
    require(isinstance(arguments.run_url, str) and RUN_URL.fullmatch(arguments.run_url), "current Actions run URL required")
    selected = identity(client, arguments.pr_number, source, repository, verifier)
    bundle.write("selected.json", selected)
    bundle.write("candidate-inventory.json", bounded_candidate_trees(client, verifier, selected, inventory))
    manifest = {"kind": "exacly-canary-trusted-base", "schema_version": "1", "base_ref": "refs/heads/main", "base_revision": source, "files": inventory}
    manifest_bytes = encoded(manifest) + b"\n"
    bundle.write("base-manifest.json", manifest)
    manifest_pin = digest(manifest_bytes)
    candidate = bundle.path / "candidate.git"
    fetch_public(verifier, source_git, candidate, selected, deadline)
    candidate_git = clean_git(verifier, candidate, deadline)
    require(candidate_git.read("rev-parse", "refs/verification/merge").decode().strip() == selected["merge_revision"], "public fetched merge ref changed")
    command = [os.path.realpath(os.sys.executable), "-I", "-B", str(ROOT / "tools/verify_merge.py"), "--repository", str(candidate), "--manifest", str(bundle.path / "base-manifest.json"), "--manifest-sha256", manifest_pin, "--base-ref", selected["base_ref"], "--head-ref", selected["head_ref"], "--base", source, "--head", selected["head_revision"], "--merge", selected["merge_revision"], "--tree", selected["merge_tree"]]
    stdout, _ = verifier["command"](command, environment=clean_environment(), deadline=min(deadline, time.monotonic() + 25))
    report = decode(stdout)
    require(isinstance(report, dict) and report.get("status") == "verified" and report.get("manifest_sha256") == manifest_pin and report.get("candidate_code_executed") is False and report.get("provider_writes") == 0, "fixed local verifier did not establish the selected candidate")
    require(all(report.get(key) == selected[key] for key in ("base_ref", "head_ref", "base_revision", "head_revision", "merge_revision", "merge_tree", "merge_parents")), "fixed verifier reported another merge")
    require(report.get("trusted_file_sha256") == {path: item["sha256"] for path, item in inventory.items()} and report.get("trusted_tests", {}).get("result") == "passed" and report["trusted_tests"].get("cases") == 7, "fixed trusted business verification differs")
    bundle.write("verification.json", report)
    proof = {"kind": "exacly-canary-generated-merge-check", "source_commit": source, **selected, "manifest_sha256": manifest_pin, "trusted_file_sha256": report["trusted_file_sha256"], "trusted_cases": 7, "runner_sha256": report["trusted_tests"]["runner_sha256"], "python_version": report["trusted_tests"]["python_version"], "candidate_code_executed": False}
    body = {"name": CHECK_NAME, "head_sha": selected["merge_revision"], "status": "completed", "conclusion": "success", "external_id": digest(encoded(proof)), "details_url": arguments.run_url, "output": {"title": "Verified exact canary merge", "summary": encoded(proof).decode(), "text": "Seven fixed trusted business cases passed. Candidate code was measured as data and is identical except for the bounded canary label. This check grants no merge authority."}}
    existing = checks(client, selected["merge_revision"])
    guard = hosted_guard(source, arguments, deadline, sender)
    bundle.write("hosted-guard.json", guard)
    refreshed_repository = scope(client)
    require(refreshed_repository.get("node_id") == repository.get("node_id") and identity(client, arguments.pr_number, source, refreshed_repository, verifier) == selected, "live B/H/M tuple changed before check publication")
    if existing:
        actual = same_check(existing[0], body)
        return {"status": "reused", "check": actual, "provider_check_posts": 0, "source_commit": source, "hosted_guard": guard}
    if not guard["new_post_allowed"]:
        return {"status": "pending", "reason": "new check is blocked pending read-only reconciliation of hosted run history", "provider_check_posts": 0, "source_commit": source, "hosted_guard": guard, "retry_permitted": False}
    body["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    bundle.write("intent.json", {"kind": "canary-check-creation-intent", "request": body, "maximum_check_posts": 1, "no_post_retry": True, "cross_host_exactly_once_claimed": False})
    created = client.request("POST", PREFIX + "/check-runs", body)
    if isinstance(created, dict):
        bundle.write("post-response.json", {"check_id": created.get("id") if type(created.get("id")) is int else None, "actual_app_id": created.get("app", {}).get("id") if isinstance(created.get("app"), dict) and type(created["app"].get("id")) is int else None, "head_matches": created.get("head_sha") == selected["merge_revision"]})
    actual = same_check(created, body)
    readback = checks(client, selected["merge_revision"])
    require(len(readback) == 1 and same_check(readback[0], body)["id"] == actual["id"], "check readback is absent or ambiguous; retain uncertainty")
    return {"status": "published", "check": actual, "provider_check_posts": 1, "source_commit": source}


def execute(arguments, sender=None):
    deadline = time.monotonic() + WORK_SECONDS
    verifier = runpy.run_path(str(ROOT / "tools/verify_merge.py"), run_name="trusted_canary_verifier")
    bundle = Bundle(arguments.out, verifier)
    client = None
    stage = "configuration"
    try:
        config = load_configuration(verifier)
        role = arguments.role if arguments.command == "preflight" else "verifier"
        stage = "installation_identity"
        require(role in ROLES and arguments.installation_id == ROLES[role]["installation_id"], "minted installation ID differs from trusted role configuration")
        selected_source = arguments.source_commit if arguments.command == "verify" else None
        if selected_source is not None:
            require(isinstance(selected_source, str) and SHA.fullmatch(selected_source), "exact selected source commit required")
        stage = "trusted_source"
        git, source, inventory = source_snapshot(verifier, deadline, selected_source)
        bundle.write("selection.json", {"role": role, "configured_app": config["apps"][role], "source_commit": source, "opaque_token_issuer_api_verified": False, "identity_basis": "trusted workflow selected App/private-key mint and independently checked action installation ID"})
        stage = "role_token"
        client = Client(os.environ.get("CANARY_APP_TOKEN"), deadline, sender)
        repository = scope(client)
        current_main(client, source)
        if arguments.command == "preflight":
            access = merger_access(client, repository) if role == "merger" else {"repository_scope_read": True, "checks_write_proven": False}
            result = {"status": "ready", "role": role, "app_id": ROLES[role]["app_id"], "installation_id": arguments.installation_id, "repository": REPOSITORY, "source_commit": source, "access": access, "opaque_token_issuer_api_verified": False, "provider_check_posts": 0}
        else:
            result = verify(client, verifier, bundle, git, source, inventory, repository, arguments, deadline, sender)
        result["http_calls"] = client.calls
        client.stage = "result_persistence"
        bundle.write("result.json", result)
        return result
    except Exception as error:
        # Raw HTTP/Git diagnostics and arbitrary exception text can contain credentials.
        result = {"status": "uncertain" if client is not None and client.check_posts else "rejected", "reason": str(error) if isinstance(error, Refused) else "bounded bootstrap could not complete", "provider_check_posts": 0 if client is None else client.check_posts, "retry_permitted": False}
        if arguments.command == "preflight":
            result["stage"] = client.stage if client is not None and client.stage is not None else stage
        try:
            bundle.write("result.json", result)
        except Exception:
            result["local_receipt_persisted"] = False
        return result
    finally:
        try:
            os.close(bundle.descriptor)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--role", choices=tuple(ROLES), required=True)
    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--pr-number", type=int, required=True)
    verify_command.add_argument("--source-commit", required=True)
    verify_command.add_argument("--run-url", required=True)
    for command in (preflight, verify_command):
        command.add_argument("--installation-id", type=int, required=True)
        command.add_argument("--out", required=True)
    arguments = parser.parse_args()
    try:
        result = execute(arguments)
    except Exception:
        result = {"status": "uncertain", "reason": "bootstrap state and private output could not be established", "provider_check_posts": None, "retry_permitted": False}
    summary = {"status": result["status"], "out": arguments.out, "provider_check_posts": result.get("provider_check_posts", 0)}
    if arguments.command == "preflight" and result["status"] == "rejected":
        reason, stage = result.get("reason"), result.get("stage")
        summary["reason"] = reason if isinstance(reason, str) and reason in PREFLIGHT_REASONS else "bounded bootstrap could not complete"
        summary["stage"] = stage if isinstance(stage, str) and stage in PREFLIGHT_STAGES else "unknown"
    print(json.dumps(summary))
    return 0 if result["status"] in ("ready", "published", "reused") else 1


if __name__ == "__main__":
    raise SystemExit(main())
