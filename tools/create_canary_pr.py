"""Prepare one fixed data-only canary PR with the ordinary workflow token.

Original preparation permits four HTTP mutation attempts. The separately reviewed
supplemental mode permits one PR POST only, preserving the original accounting.
Neither mode updates an existing ref, force pushes, retries a POST or merges.
Git author text is deterministic metadata. Only GitHub's PR response establishes
the actual bot author. Candidate code is never imported or executed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

REPOSITORY = {"id": 1442278205, "full_name": "whiteredhouse/exacly-delivery-acceptance", "node_id": "R_kgDOVfdrPQ"}
BASE = "723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8"
BASE_TREE = "104a733dbd6a504e9fb995f9c621e65ebda13798"
BRANCH = "canary/native-merge-001"
SOURCE_BRANCH = "codex/native-merge-trial"
CANARY = "canary=native-merge-001\n"
BOT = {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
IDENTITY = {"name": "github-actions[bot]", "email": "41898282+github-actions[bot]@users.noreply.github.com", "date": "2026-11-02T15:20:00Z"}
MESSAGE = "Prepare bounded native merge canary\n"
TITLE = "Bounded native merge acceptance canary"
API = "https://api.github.com"
PREFIX = "/repos/" + REPOSITORY["full_name"]
WORKFLOW = ".github/workflows/app-bootstrap.yml"
RUN_TITLE = "canary-bootstrap:create-canary:pr-0"
FINISH_RUN_TITLE = "canary-bootstrap:finish-canary-pr:pr-0"
# Separately reviewed supplemental PR preparation; this is not native merge
# approval or a retrospective assertion about the original failure's HTTP cause.
SUPPLEMENTAL_DECISION = "canary-native-merge-001-finish-pr-v1"
ORIGINAL_RUN = 41473383834
ORIGINAL_SOURCE = "860221a3aa537b415b6411f45c8755fb99fb11e8"
ORIGINAL_ARTIFACT = 13155927139
ORIGINAL_ARTIFACT_DIGEST = "sha256:84cb592a85459ed660fed8694d460ab249eafa32f7a057c60b23875cf8d2da1c"
HISTORY = PREFIX + "/actions/workflows/app-bootstrap.yml/runs?event=workflow_dispatch&branch=codex%2Fnative-merge-trial&per_page=100"
PULLS = PREFIX + "/pulls?state=all&head=whiteredhouse%3Acanary%2Fnative-merge-001&base=main&per_page=100"
MAX_BYTES, MAX_CALLS, WORK_SECONDS = 1024 * 1024, 32, 75
ROOT = Path(__file__).resolve().parent.parent
BASE_FILES = {
    ".github/workflows/app-bootstrap.yml": "09554bb45697dd892af700b02ece48a14018055a",
    ".github/workflows/ci.yml": "5486db43765ee2ebe1698f67dfd5d134d2b4ad1d",
    ".gitignore": "e11d7d5d333b7664b32edc397e73c8a1f2b8f47e",
    "README.md": "5a994569df05e3b968277c249fbcc5beb95543a3",
    "canary.txt": "1a163a3207b56fa39659f8542d1f1e7501ed1450",
    "canary_app.py": "39fb8679eed9a12a26244a21158e71fc5f213f47",
    "config/apps.json": "79dbb7ecee5e3602c540a2ef35af1c242f33d660",
    "config/protection.json": "eb87a047a507dc8a9c7f1faf4b8d9088b3006f57",
    "docs/APP-SETUP.md": "3c6ce37800c6fc3cafac2f007dfa0c2c3d41fcc1",
    "tests/test_app_bootstrap.py": "ccb6e2412548d694be7e0e2e98b8be94464ca3c1",
    "tests/test_canary_app.py": "307ff33467db6d24656cd6941af37a3c92e40832",
    "tests/test_verify_merge.py": "ab65fdd825243301f477db72d1842540bb8a4d82",
    "tools/app_bootstrap.py": "7cc93511360f2607b0454f3d25c4ac78d8b4bd67",
    "tools/verify_merge.py": "4b3cea314241e843a8bda4838c8fcba31dd4bce7",
}


class Stopped(Exception):
    """Only fixed, locally selected error codes cross the reporting boundary."""


def require(condition, code="unexpected_provider_facts"):
    if not condition:
        raise Stopped(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def git_hash(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def tree_inventory(files):
    """Compute Git's exact tree identities without Git or a subprocess."""
    root, inventory = {}, {}
    for path, oid in files.items():
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = oid
    def visit(node, prefix=""):
        data = bytearray()
        for name in sorted(node, key=lambda item: item + ("/" if isinstance(node[item], dict) else "")):
            child, path = node[name], prefix + name
            mode, kind = ("040000", "tree") if isinstance(child, dict) else ("100644", "blob")
            oid = visit(child, path + "/") if kind == "tree" else child
            inventory[path] = {"mode": mode, "type": kind, "sha": oid}
            data.extend((mode.lstrip("0") + " " + name).encode() + b"\0" + bytes.fromhex(oid))
        return git_hash("tree", bytes(data))
    return visit(root), inventory


require(tree_inventory(BASE_FILES)[0] == BASE_TREE, "invalid_fixed_base_inventory")
HEAD_FILES = {**BASE_FILES, "canary.txt": git_hash("blob", CANARY.encode())}
TREE, INVENTORY = tree_inventory(HEAD_FILES)
epoch = int(dt.datetime.fromisoformat(IDENTITY["date"].replace("Z", "+00:00")).timestamp())
person = IDENTITY["name"] + " <" + IDENTITY["email"] + "> " + str(epoch) + " +0000"
HEAD = git_hash("commit", ("tree " + TREE + "\nparent " + BASE + "\nauthor " + person + "\ncommitter " + person + "\n\n" + MESSAGE).encode())
PR_BODY = "Fixed acceptance canary: only canary.txt changes to native-merge-001.\n\nBase: " + BASE + "\nHead: " + HEAD + "\nTree: " + TREE + "\n\nIndependent human review and genuine exact-merge verification are required. No merge authority is granted by this PR.\n"
MUTATIONS = {
    PREFIX + "/git/trees": {"base_tree": BASE_TREE, "tree": [{"path": "canary.txt", "mode": "100644", "type": "blob", "content": CANARY}]},
    PREFIX + "/git/commits": {"message": MESSAGE, "tree": TREE, "parents": [BASE], "author": IDENTITY, "committer": IDENTITY},
    PREFIX + "/git/refs": {"ref": "refs/heads/" + BRANCH, "sha": HEAD},
    PREFIX + "/pulls": {"title": TITLE, "body": PR_BODY, "head": BRANCH, "base": "main", "draft": False, "maintainer_can_modify": False},
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "invalid_provider_json")
        result[key] = value
    return result


def decode(data):
    require(isinstance(data, bytes) and len(data) <= MAX_BYTES, "invalid_provider_json")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(Stopped("invalid_provider_json")))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *arguments):
        return None


def transport(method, url, headers, payload, timeout):
    request = urllib.request.Request(url, data=None if payload is None else encoded(payload), headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read(MAX_BYTES + 1)
        finally:
            error.close()


class ResultFile:
    def __init__(self, path):
        self.path = Path(path)
        require(self.path.is_absolute() and self.path.parent.resolve() == self.path.parent and ROOT not in self.path.parents, "invalid_result_path")
        self.path.mkdir(mode=0o700)
        os.chmod(self.path, 0o700)
        self.counter = 0

    def save(self, result):
        data = encoded(result) + b"\n"
        require(len(data) <= MAX_BYTES, "private_result_unavailable")
        temporary = self.path / (".author-result-" + str(self.counter))
        self.counter += 1
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                require(written > 0, "private_result_unavailable")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path / "author-result.json")
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class Client:
    def __init__(self, token, run_id, result, output, sender=None, *, finish_pr=False):
        require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_.-]{20,1024}", token), "author_token_unavailable")
        self.token, self.run_id, self.result, self.output = token, run_id, result, output
        self.sender, self.deadline, self.calls, self.writes = sender or transport, time.monotonic() + WORK_SECONDS, 0, 0
        self.sent = set()
        self.mutation_limit = 1 if finish_pr else 4
        self.mutations = {PREFIX + "/pulls": MUTATIONS[PREFIX + "/pulls"]} if finish_pr else MUTATIONS
        self.reads = {PREFIX, PREFIX + "/git/ref/heads/main", PREFIX + "/git/ref/heads/" + BRANCH,
                      PREFIX + "/git/commits/" + BASE, PREFIX + "/git/commits/" + HEAD,
                      PREFIX + "/git/trees/" + BASE_TREE + "?recursive=1", PREFIX + "/git/trees/" + TREE + "?recursive=1",
                      PREFIX + "/actions/runs/" + str(run_id), HISTORY, PULLS}
        if finish_pr:
            self.reads.update((PREFIX + "/actions/runs/" + str(ORIGINAL_RUN), PREFIX + "/actions/artifacts/" + str(ORIGINAL_ARTIFACT)))

    def request(self, method, path, payload=None, *, missing=False):
        mutation = method == "POST" and path in self.mutations and encoded(payload) == encoded(self.mutations[path])
        require(mutation or (method == "GET" and path in self.reads and payload is None), "request_outside_fixed_scope")
        require(self.calls < MAX_CALLS and time.monotonic() < self.deadline, "request_budget_exhausted")
        if mutation:
            require(path not in self.sent and self.writes < self.mutation_limit, "mutation_retry_forbidden")
            self.sent.add(path)
            self.writes += 1
            self.result["intents"].append({"method": method, "path": path, "request": payload})
            self.result["provider_mutation_attempts"] = self.writes
            if "supplemental_mutation_attempts" in self.result:
                self.result["supplemental_mutation_attempts"] = self.writes
            self.output.save(self.result)
        self.calls += 1
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "exacly-canary-author"}
        status, data = self.sender(method, API + path, headers, payload, min(10, self.deadline - time.monotonic()))
        require(time.monotonic() < self.deadline, "request_budget_exhausted")
        if missing and method == "GET" and status == 404:
            return None
        if status != (201 if mutation else 200):
            if type(status) is int and status in (400, 401, 403, 404, 409, 410, 422, 429, 500, 502, 503, 504):
                self.result["provider_failure_http_status"] = status
            if status == 403 and mutation and path == PREFIX + "/pulls":
                try:
                    reason = decode(data)
                except Exception:
                    reason = None
                if isinstance(reason, dict) and reason.get("message") == "GitHub Actions is not permitted to create or approve pull requests.":
                    raise Stopped("actions_pr_creation_disabled")
            raise Stopped("provider_request_rejected")
        return decode(data)


def context(*, finish_pr=False):
    mode = "finish-canary-pr" if finish_pr else "create-canary"
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": REPOSITORY["full_name"],
                "GITHUB_REPOSITORY_ID": str(REPOSITORY["id"]), "GITHUB_REF": "refs/heads/" + SOURCE_BRANCH,
                "GITHUB_WORKFLOW_REF": REPOSITORY["full_name"] + "/" + WORKFLOW + "@refs/heads/" + SOURCE_BRANCH,
                "GITHUB_JOB": mode, "CANARY_MODE": mode, "CANARY_PR_NUMBER": ""}
    require(all(os.environ.get(key) == value for key, value in expected.items()), "invalid_hosted_context")
    source, run, attempt = (os.environ.get(key, "") for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    require(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[1-9][0-9]*", attempt), "invalid_hosted_context")
    return source, int(run), int(attempt)


def history_allows_creation(client, source, run_id, attempt, *, finish_pr=False):
    run = client.request("GET", PREFIX + "/actions/runs/" + str(run_id))
    history = client.request("GET", HISTORY)
    def valid(item):
        return isinstance(item, dict) and type(item.get("id")) is int and type(item.get("run_number")) is int and type(item.get("run_attempt")) is int and item["run_attempt"] > 0 and item.get("repository", {}).get("id") == REPOSITORY["id"] and item["repository"].get("full_name") == REPOSITORY["full_name"] and item.get("path") == WORKFLOW and item.get("event") == "workflow_dispatch" and item.get("head_branch") == SOURCE_BRANCH and isinstance(item.get("head_sha"), str) and re.fullmatch(r"[0-9a-f]{40}", item["head_sha"]) and type(item.get("workflow_id")) is int and isinstance(item.get("display_title"), str)
    title = FINISH_RUN_TITLE if finish_pr else RUN_TITLE
    require(valid(run) and run["id"] == run_id and run["head_sha"] == source and run["run_attempt"] == attempt and run["display_title"] == title and run.get("status") == "in_progress", "hosted_history_unavailable")
    require(isinstance(history, dict) and isinstance(history.get("workflow_runs"), list) and type(history.get("total_count")) is int and history["total_count"] == len(history["workflow_runs"]) < 100, "hosted_history_unavailable")
    rows = history["workflow_runs"]
    require(all(valid(row) and row["workflow_id"] == run["workflow_id"] for row in rows) and len({row["id"] for row in rows}) == len(rows), "hosted_history_unavailable")
    current = [row for row in rows if row["id"] == run_id]
    require(len(current) == 1 and current[0]["head_sha"] == source and current[0]["run_attempt"] == attempt
            and current[0]["run_number"] == run["run_number"] and current[0]["display_title"] == title
            and current[0].get("status") == "in_progress", "hosted_history_unavailable")
    prior = [row["id"] for row in rows if row["run_number"] < run["run_number"] and row["display_title"] == RUN_TITLE]
    client.result["prior_author_run_ids"] = prior
    if finish_pr:
        original = client.request("GET", PREFIX + "/actions/runs/" + str(ORIGINAL_RUN))
        def original_matches(item):
            return valid(item) and item["id"] == ORIGINAL_RUN and item["head_sha"] == ORIGINAL_SOURCE and item["run_attempt"] == 1 and item["run_number"] == 5 and item["display_title"] == RUN_TITLE and item.get("status") == "completed" and item.get("conclusion") == "failure" and item["workflow_id"] == run["workflow_id"]
        create_rows = [row for row in rows if row["display_title"] == RUN_TITLE]
        require(original_matches(original) and len(create_rows) == 1 and original_matches(create_rows[0])
                and prior == [ORIGINAL_RUN], "supplemental_original_history_unavailable")
        artifact = client.request("GET", PREFIX + "/actions/artifacts/" + str(ORIGINAL_ARTIFACT))
        selected = artifact.get("workflow_run", {}) if isinstance(artifact, dict) else {}
        require(isinstance(artifact, dict) and artifact.get("id") == ORIGINAL_ARTIFACT
                and artifact.get("name") == "create-canary-41473383834-1" and artifact.get("expired") is False
                and artifact.get("digest") == ORIGINAL_ARTIFACT_DIGEST
                and selected.get("id") == ORIGINAL_RUN and selected.get("head_sha") == ORIGINAL_SOURCE
                and selected.get("repository_id") == selected.get("head_repository_id") == REPOSITORY["id"]
                and selected.get("head_branch") == SOURCE_BRANCH, "supplemental_original_artifact_unavailable")
        prior_finish = [row["id"] for row in rows if row["run_number"] < run["run_number"] and row["display_title"] == FINISH_RUN_TITLE]
        client.result["prior_finish_run_ids"] = prior_finish
        client.result["supplemental_slot_previously_consumed_or_uncertain"] = bool(prior_finish)
        return attempt == 1 and not prior_finish
    return attempt == 1 and not prior


def check_tree(value, oid, inventory):
    require(isinstance(value, dict) and value.get("sha") == oid and value.get("truncated") is False and isinstance(value.get("tree"), list), "unexpected_tree")
    actual = {}
    for entry in value["tree"]:
        require(isinstance(entry, dict) and isinstance(entry.get("path"), str) and entry["path"] not in actual, "unexpected_tree")
        actual[entry["path"]] = {key: entry.get(key) for key in ("mode", "type", "sha")}
    require(actual == inventory, "unexpected_tree")


def check_commit(value):
    require(isinstance(value, dict) and value.get("sha") == HEAD and value.get("tree", {}).get("sha") == TREE and [p.get("sha") for p in value.get("parents", [])] == [BASE], "unexpected_commit")
    # GitHub's Git-commit JSON omits the raw object's final LF. The exact SHA
    # still binds the selected raw message bytes, parents and tree.
    require(value.get("message") in (MESSAGE, MESSAGE[:-1]) and all(all(value.get(role, {}).get(key) == expected for key, expected in IDENTITY.items())
            for role in ("author", "committer")), "unexpected_commit")


def check_ref(value):
    require(isinstance(value, dict) and value.get("ref") == "refs/heads/" + BRANCH and value.get("object", {}).get("sha") == HEAD and value["object"].get("type") == "commit", "unexpected_canary_ref")


def check_pr(value):
    require(isinstance(value, dict) and type(value.get("number")) is int and 0 < value["number"] < 10**10, "unexpected_pr")
    require(value.get("state") == "open" and value.get("draft") is False and value.get("merged") is False, "unexpected_pr")
    require(all(value.get("user", {}).get(key) == expected for key, expected in BOT.items()), "unexpected_pr_author")
    for name, ref, sha in (("base", "main", BASE), ("head", BRANCH, HEAD)):
        side = value.get(name, {})
        require(side.get("ref") == ref and side.get("sha") == sha and side.get("repo", {}).get("id") == REPOSITORY["id"] and side["repo"].get("full_name") == REPOSITORY["full_name"], "unexpected_pr")
    require(value.get("title") == TITLE and value.get("body") == PR_BODY and value.get("html_url") == "https://github.com/" + REPOSITORY["full_name"] + "/pull/" + str(value["number"]), "unexpected_pr")


def prepare(out, sender=None, *, finish_pr=False):
    result = {"kind": "exacly-fixed-canary-author", "status": "failed", "stage": "context", "expected_base": BASE,
              "expected_head": HEAD, "expected_tree": TREE, "head_ref": "refs/heads/" + BRANCH, "canary_content": CANARY,
              "provider_mutation_attempts": 0, "intents": [], "automatic_retry": False, "native_merge_authority": False, "independent_review_verified": False}
    if finish_pr:
        result.update(kind="exacly-fixed-canary-supplemental-pr", supplemental_preparation_decision=SUPPLEMENTAL_DECISION,
                      original_run_id=ORIGINAL_RUN, original_source_commit=ORIGINAL_SOURCE,
                      original_artifact_id=ORIGINAL_ARTIFACT, original_artifact_digest=ORIGINAL_ARTIFACT_DIGEST,
                      original_failure_http_status_retained=False, original_pr_post_outcome="unconfirmed", original_mutation_attempts=4,
                      supplemental_mutation_limit=1, supplemental_mutation_attempts=0,
                      aggregate_bootstrap_mutation_limit=5)
    output, client = None, None
    try:
        output = ResultFile(out)
        output.save(result)
        source, run_id, attempt = context(finish_pr=finish_pr)
        result.update(source_commit=source, run_id=run_id, run_attempt=attempt)
        client = Client(os.environ.get("CANARY_AUTHOR_TOKEN"), run_id, result, output, sender, finish_pr=finish_pr)
        allowed = history_allows_creation(client, source, run_id, attempt, finish_pr=finish_pr)
        repo = client.request("GET", PREFIX)
        require(all(repo.get(key) == value for key, value in REPOSITORY.items()) and repo.get("default_branch") == "main" and all(repo.get(key) is False for key in ("private", "archived", "disabled")), "unexpected_repository")
        def main_matches():
            main = client.request("GET", PREFIX + "/git/ref/heads/main")
            require(main.get("ref") == "refs/heads/main" and main.get("object", {}).get("sha") == BASE and main["object"].get("type") == "commit", "main_changed")
        main_matches()
        base = client.request("GET", PREFIX + "/git/commits/" + BASE)
        require(base.get("sha") == BASE and base.get("tree", {}).get("sha") == BASE_TREE, "unexpected_base_commit")
        check_tree(client.request("GET", PREFIX + "/git/trees/" + BASE_TREE + "?recursive=1"), BASE_TREE, tree_inventory(BASE_FILES)[1])
        head = client.request("GET", PREFIX + "/git/ref/heads/" + BRANCH, missing=True)
        prs = client.request("GET", PULLS)
        require(isinstance(prs, list) and len(prs) < 100, "ambiguous_existing_pr")
        result["stage"] = "discovery"
        if finish_pr:
            require(head is not None, "supplemental_existing_head_unavailable")
            check_ref(head)
            check_commit(client.request("GET", PREFIX + "/git/commits/" + HEAD))
            check_tree(client.request("GET", PREFIX + "/git/trees/" + TREE + "?recursive=1"), TREE, INVENTORY)
        if prs:
            require(len(prs) == 1 and head is not None, "ambiguous_existing_pr")
            number = prs[0].get("number")
            require(type(number) is int and 0 < number < 10**10, "unexpected_pr")
            path = PREFIX + "/pulls/" + str(number)
            client.reads.add(path)
            pr = client.request("GET", path)
            check_pr(pr)
            check_ref(head)
            if not finish_pr:
                check_commit(client.request("GET", PREFIX + "/git/commits/" + HEAD))
                check_tree(client.request("GET", PREFIX + "/git/trees/" + TREE + "?recursive=1"), TREE, INVENTORY)
            result["status"] = "discovered"
        else:
            if finish_pr:
                require(allowed, "supplemental_attempt_requires_reconciliation")
            else:
                require(head is None, "existing_head_requires_reconciliation")
                require(allowed, "prior_author_attempt_requires_reconciliation")
                result["stage"] = "tree"
                created = client.request("POST", PREFIX + "/git/trees", MUTATIONS[PREFIX + "/git/trees"])
                require(created.get("sha") == TREE, "unexpected_tree")
                check_tree(client.request("GET", PREFIX + "/git/trees/" + TREE + "?recursive=1"), TREE, INVENTORY)
                result["stage"] = "commit"
                check_commit(client.request("POST", PREFIX + "/git/commits", MUTATIONS[PREFIX + "/git/commits"]))
                main_matches()
                result["stage"] = "branch"
                check_ref(client.request("POST", PREFIX + "/git/refs", MUTATIONS[PREFIX + "/git/refs"]))
            main_matches()
            check_ref(client.request("GET", PREFIX + "/git/ref/heads/" + BRANCH))
            result["stage"] = "pr"
            created = client.request("POST", PREFIX + "/pulls", MUTATIONS[PREFIX + "/pulls"])
            number = created.get("number")
            require(type(number) is int and 0 < number < 10**10, "unexpected_pr")
            client.reads.add(PREFIX + "/pulls/" + str(number))
            pr = client.request("GET", PREFIX + "/pulls/" + str(number))
            check_pr(pr)
            result["status"] = "created"
        result.update(stage="complete", pr_number=pr["number"], pr_url=pr["html_url"], actual_pr_author=BOT)
    except Stopped as error:
        result["error_code"] = error.args[0]
    except Exception:
        result["error_code"] = "bounded_author_preparation_failed"
    finally:
        result["provider_requests"] = client.calls if client else 0
        result["provider_mutation_attempts"] = client.writes if client else 0
        if finish_pr:
            result["supplemental_mutation_attempts"] = result["provider_mutation_attempts"]
        result["possible_provider_effect"] = result["provider_mutation_attempts"] > 0
        if output is not None:
            try:
                output.save(result)
            except Exception:
                result.update(status="failed", error_code="private_result_unavailable")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--finish-pr", action="store_true", help="Use the separately reviewed, one-shot PR-only supplemental preparation decision")
    arguments = parser.parse_args()
    result = prepare(arguments.out, finish_pr=arguments.finish_pr)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("created", "discovered") else 1


if __name__ == "__main__":
    raise SystemExit(main())
