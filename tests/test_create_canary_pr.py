"""Fixed author HTTP boundaries; no live requests or provider mutations."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

SOURCE = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("fixed_canary_author", SOURCE / "tools/create_canary_pr.py")
author = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(author)
TOKEN = "fixture_ordinary_workflow_token_12345"
SOURCE_SHA = "b" * 40


def environment(attempt="1"):
    return {"CANARY_AUTHOR_TOKEN": TOKEN, "CANARY_MODE": "create-canary", "CANARY_PR_NUMBER": "",
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": author.REPOSITORY["full_name"],
            "GITHUB_REPOSITORY_ID": str(author.REPOSITORY["id"]), "GITHUB_REF": "refs/heads/" + author.SOURCE_BRANCH,
            "GITHUB_WORKFLOW_REF": author.REPOSITORY["full_name"] + "/" + author.WORKFLOW + "@refs/heads/" + author.SOURCE_BRANCH,
            "GITHUB_JOB": "create-canary", "GITHUB_SHA": SOURCE_SHA, "GITHUB_RUN_ID": "901", "GITHUB_RUN_ATTEMPT": attempt}


class Backend:
    def __init__(self):
        self.calls, self.posts, self.head, self.prs = [], [], None, []
        self.run = {"id": 901, "run_number": 5, "run_attempt": 1, "workflow_id": 77, "path": author.WORKFLOW,
                    "event": "workflow_dispatch", "head_branch": author.SOURCE_BRANCH, "head_sha": SOURCE_SHA,
                    "display_title": author.RUN_TITLE, "status": "in_progress", "conclusion": None, "repository": copy.deepcopy(author.REPOSITORY)}
        self.history = [copy.deepcopy(self.run)]
        self.count = None
        self.repo = {**author.REPOSITORY, "private": False, "disabled": False, "archived": False, "default_branch": "main"}
        self.main = {"ref": "refs/heads/main", "object": {"sha": author.BASE, "type": "commit"}}
        self.commit = {"sha": author.HEAD, "tree": {"sha": author.TREE}, "parents": [{"sha": author.BASE}],
                       "author": copy.deepcopy(author.IDENTITY), "committer": copy.deepcopy(author.IDENTITY), "message": author.MESSAGE}
        self.pr = {"number": 4, "state": "open", "draft": False, "merged": False, "user": copy.deepcopy(author.BOT),
                   "title": author.TITLE, "body": author.PR_BODY, "html_url": "https://github.com/" + author.REPOSITORY["full_name"] + "/pull/4",
                   "base": {"ref": "main", "sha": author.BASE, "repo": copy.deepcopy(author.REPOSITORY)},
                   "head": {"ref": author.BRANCH, "sha": author.HEAD, "repo": copy.deepcopy(author.REPOSITORY)}}
        self.output, self.override = None, None

    @staticmethod
    def tree(oid):
        entries = author.tree_inventory(author.BASE_FILES)[1] if oid == author.BASE_TREE else author.INVENTORY
        return {"sha": oid, "truncated": False, "tree": [{"path": name, **value} for name, value in entries.items()]}

    def sender(self, method, url, headers, payload, timeout):
        assert url.startswith(author.API + "/") and 0 < timeout <= 10
        assert headers["Authorization"] == "Bearer " + TOKEN
        assert headers["X-GitHub-Api-Version"] == "2026-03-10"
        path = url.removeprefix(author.API)
        self.calls.append((method, path, copy.deepcopy(payload)))
        if method == "POST":
            assert payload == author.MUTATIONS[path]
            saved = json.loads((self.output / "author-result.json").read_text())
            assert saved["intents"][-1] == {"method": method, "path": path, "request": payload}
            assert saved["provider_mutation_attempts"] == len(self.posts) + 1
            assert self.output.stat().st_mode & 0o777 == 0o700
            assert (self.output / "author-result.json").stat().st_mode & 0o777 == 0o600
            self.posts.append(path)
        if self.override:
            answer = self.override(method, path, payload)
            if answer is not None:
                return answer
        if path == author.PREFIX:
            value = self.repo
        elif path == author.PREFIX + "/actions/runs/901":
            value = self.run
        elif path == author.HISTORY:
            value = {"total_count": len(self.history) if self.count is None else self.count, "workflow_runs": self.history}
        elif path == author.PREFIX + "/git/ref/heads/main":
            value = self.main
        elif path == author.PREFIX + "/git/commits/" + author.BASE:
            value = {"sha": author.BASE, "tree": {"sha": author.BASE_TREE}}
        elif path.startswith(author.PREFIX + "/git/trees/"):
            value = self.tree(path.rsplit("/", 1)[1].split("?")[0])
        elif path == author.PREFIX + "/git/ref/heads/" + author.BRANCH:
            if self.head is None:
                return 404, b'{"message":"Not Found"}'
            value = self.head
        elif path == author.PULLS:
            value = self.prs
        elif path == author.PREFIX + "/git/commits":
            value = self.commit
        elif path == author.PREFIX + "/git/commits/" + author.HEAD:
            value = self.commit
        elif path == author.PREFIX + "/git/trees":
            value = {"sha": author.TREE}
        elif path == author.PREFIX + "/git/refs":
            self.head = {"ref": "refs/heads/" + author.BRANCH, "object": {"sha": author.HEAD, "type": "commit"}}
            value = self.head
        elif path == author.PREFIX + "/pulls":
            self.prs = [copy.deepcopy(self.pr)]
            value = self.pr
        elif path == author.PREFIX + "/pulls/4":
            value = self.pr
        else:
            raise AssertionError("Unexpected fixed author endpoint")
        return (201 if method == "POST" else 200), author.encoded(value)

    def existing(self):
        self.head = {"ref": "refs/heads/" + author.BRANCH, "object": {"sha": author.HEAD, "type": "commit"}}
        self.prs = [copy.deepcopy(self.pr)]

    def prior(self, conclusion="failure"):
        self.history.append({**copy.deepcopy(self.run), "id": 900, "run_number": 4, "status": "completed", "conclusion": conclusion})


class CreateCanaryTests(unittest.TestCase):
    def prepare(self, backend, changes=None, env=None):
        with tempfile.TemporaryDirectory(prefix="fixed-author-test-") as folder:
            backend.output = Path(folder) / "result"
            context = environment()
            context.update(changes or {})
            with patch.object(author.os, "environ", env if env is not None else context):
                result = author.prepare(backend.output, backend.sender)
            persisted = json.loads((backend.output / "author-result.json").read_text())
            self.assertEqual(result, persisted)
            self.assertEqual(sorted(p.name for p in backend.output.iterdir()), ["author-result.json"])
            self.assertNotIn(TOKEN, json.dumps(result))
            return result

    def test_positive_fixed_four_http_effects_and_real_bot_author(self):
        backend = Backend()
        result = self.prepare(backend)
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["provider_mutation_attempts"], 4)
        self.assertEqual(backend.posts, list(author.MUTATIONS))
        self.assertEqual(result["actual_pr_author"], author.BOT)
        self.assertEqual(result["expected_base"], author.BASE)
        self.assertEqual(result["expected_tree"], author.TREE)
        self.assertEqual(result["expected_head"], author.HEAD)
        self.assertFalse(result["native_merge_authority"])
        self.assertFalse(result["independent_review_verified"])
        self.assertFalse(result["automatic_retry"])
        self.assertTrue(all(call[0] in ("GET", "POST") for call in backend.calls))

    def test_expected_tree_matches_real_git_index_without_a_token(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
            def git(*args, data=None):
                return subprocess.run(["git", "-C", folder, *args], input=data, env=env, check=True, capture_output=True, timeout=5).stdout.decode().strip()
            git("init", "--quiet")
            for name, oid in author.HEAD_FILES.items():
                git("update-index", "--add", "--cacheinfo", "100644," + oid + "," + name)
            self.assertEqual(git("write-tree", "--missing-ok"), author.TREE)

    def test_wrong_hosted_context_stops_before_http(self):
        for key, value in (("GITHUB_REPOSITORY_ID", "7"), ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_REF", "refs/heads/main"), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_JOB", "app-grant-preflight"), ("CANARY_MODE", "verify"),
                           ("CANARY_PR_NUMBER", "4"), ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_SHA", "bad")):
            with self.subTest(key=key):
                backend = Backend()
                self.assertEqual(self.prepare(backend, {key:value})["status"], "failed")
                self.assertEqual(backend.calls, [])

    def test_wrong_repo_or_base_has_zero_mutations(self):
        for change in ("repository", "base", "base-tree"):
            with self.subTest(change=change):
                backend = Backend()
                if change == "repository": backend.repo["id"] = 7
                elif change == "base": backend.main["object"]["sha"] = "f" * 40
                else:
                    backend.override = lambda method, path, payload: (200, author.encoded({"sha":author.BASE,"tree":{"sha":"f"*40}})) if path.endswith("/git/commits/" + author.BASE) else None
                self.assertEqual(self.prepare(backend)["status"], "failed")
                self.assertEqual(backend.posts, [])

    def test_changed_or_duplicate_full_base_inventory_is_rejected(self):
        for kind in ("changed", "duplicate", "truncated"):
            backend = Backend()
            value = backend.tree(author.BASE_TREE)
            if kind == "changed": value["tree"][0]["sha"] = "f" * 40
            elif kind == "duplicate": value["tree"].append(copy.deepcopy(value["tree"][0]))
            else: value["truncated"] = True
            backend.override = lambda method, path, payload: (200, author.encoded(value)) if path.endswith(author.BASE_TREE + "?recursive=1") else None
            self.assertEqual(self.prepare(backend)["status"], "failed")
            self.assertEqual(backend.posts, [])

    def test_history_incomplete_duplicate_or_inconsistent_blocks_all_writes(self):
        for kind in ("incomplete", "duplicate", "wrong-source", "wrong-attempt", "wrong-workflow"):
            backend = Backend()
            if kind == "incomplete": backend.count = 2
            elif kind == "duplicate": backend.history.append(copy.deepcopy(backend.run))
            elif kind == "wrong-source": backend.history[0]["head_sha"] = "f" * 40
            elif kind == "wrong-attempt": backend.history[0]["run_attempt"] = 2
            else: backend.history[0]["workflow_id"] = 88
            self.assertEqual(self.prepare(backend)["status"], "failed")
            self.assertEqual(backend.posts, [])

    def test_incidental_run_metadata_does_not_break_semantic_identity(self):
        backend = Backend()
        backend.run["updated_at"] = "2026-11-02T15:20:01Z"
        backend.history[0]["updated_at"] = "2026-11-02T15:20:02Z"
        self.assertEqual(self.prepare(backend)["status"], "created")

    def test_any_prior_author_run_blocks_new_effects_even_success(self):
        for conclusion in ("success", "failure", "cancelled", "timed_out", None):
            backend = Backend()
            backend.prior(conclusion)
            result = self.prepare(backend)
            self.assertEqual(result["error_code"], "prior_author_attempt_requires_reconciliation")
            self.assertEqual(backend.posts, [])

    def test_rerun_never_creates_and_can_discover_only_exact_existing_pr(self):
        for existing in (False, True):
            backend = Backend()
            backend.run["run_attempt"] = backend.history[0]["run_attempt"] = 2
            if existing: backend.existing()
            result = self.prepare(backend, {"GITHUB_RUN_ATTEMPT":"2"})
            self.assertEqual(result["status"], "discovered" if existing else "failed")
            self.assertEqual(backend.posts, [])

    def test_prior_unknown_with_exact_existing_pr_is_read_only_discovery(self):
        backend = Backend()
        backend.prior()
        backend.existing()
        result = self.prepare(backend)
        self.assertEqual(result["status"], "discovered")
        self.assertEqual(result["provider_mutation_attempts"], 0)
        self.assertEqual(result["prior_author_run_ids"], [900])

    def test_partial_branch_without_pr_never_resumes(self):
        backend = Backend()
        backend.existing()
        backend.prs = []
        result = self.prepare(backend)
        self.assertEqual(result["error_code"], "existing_head_requires_reconciliation")
        self.assertEqual(backend.posts, [])

    def test_wrong_tree_never_publishes_commit_or_ref(self):
        backend = Backend()
        bad = backend.tree(author.TREE)
        bad["tree"][0]["mode"] = "120000"
        backend.override = lambda method, path, payload: (200, author.encoded(bad)) if path.endswith(author.TREE + "?recursive=1") else None
        result = self.prepare(backend)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(backend.posts, [author.PREFIX + "/git/trees"])

    def test_wrong_returned_commit_parent_or_tree_stops_before_ref(self):
        for field in ("parent", "tree", "sha", "message", "committer"):
            backend = Backend()
            if field == "parent": backend.commit["parents"] = [{"sha":"f"*40}]
            elif field == "tree": backend.commit["tree"]["sha"] = "f"*40
            elif field == "sha": backend.commit["sha"] = "f"*40
            elif field == "message": backend.commit["message"] = "different"
            else: backend.commit["committer"]["email"] = "other@example.invalid"
            self.assertEqual(self.prepare(backend)["error_code"], "unexpected_commit")
            self.assertEqual(backend.posts, [author.PREFIX + "/git/trees", author.PREFIX + "/git/commits"])

    def test_provider_commit_json_can_omit_raw_objects_final_lf(self):
        backend = Backend()
        backend.commit["message"] = author.MESSAGE[:-1]
        self.assertEqual(self.prepare(backend)["status"], "created")
        self.assertEqual(len(backend.posts), 4)
        backend = Backend()
        backend.commit["message"] = author.MESSAGE[:-1]
        backend.commit["sha"] = "f" * 40
        self.assertEqual(self.prepare(backend)["error_code"], "unexpected_commit")
        self.assertEqual(len(backend.posts), 2)

    def test_main_race_after_immutable_objects_stops_before_ref(self):
        backend = Backend()
        def change(method, path, payload):
            if path == author.PREFIX + "/git/commits" and method == "POST":
                backend.main["object"]["sha"] = "f"*40
        backend.override = change
        self.assertEqual(self.prepare(backend)["error_code"], "main_changed")
        self.assertEqual(len(backend.posts), 2)

    def test_actual_pr_author_cannot_be_faked_by_git_metadata(self):
        for wrong in ({"login":"p1c2u","id":1679024,"type":"User"}, {**author.BOT,"id":7}, {**author.BOT,"type":"User"}):
            backend = Backend()
            backend.pr["user"] = wrong
            result = self.prepare(backend)
            self.assertEqual(result["error_code"], "unexpected_pr_author")
            self.assertEqual(result["provider_mutation_attempts"], 4)

    def test_conflicting_duplicate_closed_or_foreign_pr_never_writes(self):
        for kind in ("duplicate", "closed", "foreign", "changed-head", "wrong-author"):
            backend = Backend()
            backend.existing()
            if kind == "duplicate": backend.prs *= 2
            elif kind == "closed": backend.pr["state"] = "closed"
            elif kind == "foreign": backend.pr["head"]["repo"]["id"] = 7
            elif kind == "changed-head": backend.pr["head"]["sha"] = "f"*40
            else: backend.pr["user"]["id"] = 7
            self.assertEqual(self.prepare(backend)["status"], "failed")
            self.assertEqual(backend.posts, [])

    def test_unknown_response_after_each_mutation_never_retries_or_exposes_token(self):
        for index, path_to_fail in enumerate(author.MUTATIONS, 1):
            backend = Backend()
            def fail(method, path, payload):
                if method == "POST" and path == path_to_fail:
                    raise urllib.error.URLError("lost reply containing " + TOKEN)
            backend.override = fail
            result = self.prepare(backend)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["provider_mutation_attempts"], index)
            self.assertEqual(len(backend.posts), index)
            self.assertEqual(backend.posts.count(path_to_fail), 1)
            self.assertNotIn(TOKEN, json.dumps(result))

    def test_existing_output_does_not_reset_authority_or_make_requests(self):
        backend = Backend()
        with tempfile.TemporaryDirectory() as folder, patch.object(author.os, "environ", environment()):
            backend.output = Path(folder)
            result = author.prepare(Path(folder), backend.sender)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(backend.calls, [])

    def test_no_app_token_key_or_subprocess_access(self):
        class Guarded(dict):
            def get(self, key, default=None):
                if key in ("CANARY_APP_TOKEN", "MERGER_PRIVATE_KEY", "VERIFIER_PRIVATE_KEY"):
                    raise AssertionError("App credential access forbidden")
                return super().get(key, default)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("No subprocess permitted")):
            self.assertEqual(self.prepare(Backend(), env=Guarded(environment()))["status"], "created")

    def test_transport_builds_exact_request_and_forbids_redirects(self):
        class Reply:
            status = 201
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, limit):
                self.limit = limit
                return b'{}'
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Reply()
        opener = Opener()
        payload = author.MUTATIONS[author.PREFIX + "/git/refs"]
        with patch.object(author.urllib.request, "build_opener", return_value=opener) as build:
            status, data = author.transport("POST", author.API + author.PREFIX + "/git/refs", {"Authorization":"Bearer " + TOKEN}, payload, 5)
        self.assertEqual((status,data), (201,b'{}'))
        self.assertIsInstance(build.call_args.args[0], author.NoRedirect)
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.request.data, author.encoded(payload))
        self.assertEqual(opener.request.headers["Authorization"], "Bearer " + TOKEN)
        self.assertIsNone(author.NoRedirect().redirect_request(None,None,None,None,None,None))

    def test_client_rejects_unscoped_paths_payloads_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as folder:
            out = author.ResultFile(Path(folder)/"out")
            result = {"intents":[]}
            client = author.Client(TOKEN,901,result,out,sender=lambda *args: (200,b'{"id":1,"id":2}'))
            for method, path, payload in (("PATCH",author.PREFIX+"/git/refs",{}), ("POST",author.PREFIX+"/git/refs",{"ref":"refs/heads/main","sha":author.HEAD}), ("GET","/user",None)):
                with self.assertRaises(author.Stopped): client.request(method,path,payload)
            with self.assertRaises(author.Stopped): client.request("GET",author.PREFIX)


if __name__ == "__main__":
    unittest.main()
