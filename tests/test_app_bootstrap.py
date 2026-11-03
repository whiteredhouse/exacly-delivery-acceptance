"""Mocked GitHub transport and real local Git; no live check or API write."""

import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

SOURCE = Path(__file__).absolute().parent.parent
SPEC = importlib.util.spec_from_file_location("trusted_app_bootstrap", SOURCE / "tools/app_bootstrap.py")
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)
ROLE_TOKEN = "fixture_role_token"
READ_TOKEN = "fixture_actions_read_token"


class Fixture:
    def __init__(self, folder):
        self.root = Path(folder)
        self.source, self.origin = self.root / "trusted", self.root / "origin.git"
        self.source.mkdir()
        for path in SOURCE.rglob("*"):
            relative = path.relative_to(SOURCE)
            if ".git" in relative.parts or "__pycache__" in relative.parts or not path.is_file():
                continue
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        self.environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_AUTHOR_NAME": "Canary fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                            "GIT_COMMITTER_NAME": "Canary fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                            "GIT_AUTHOR_DATE": "2026-11-02T00:00:00Z", "GIT_COMMITTER_DATE": "2026-11-02T00:00:00Z"}
        self.git(self.source, "init", "--initial-branch=main")
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "--no-gpg-sign", "-m", "Reviewed fixture source")
        self.base = self.git(self.source, "rev-parse", "HEAD").strip()
        self.git(self.source, "clone", "--bare", "--no-local", str(self.source), str(self.origin))
        self.git(self.origin, "read-tree", self.base)
        blob = self.git(self.origin, "hash-object", "-w", "--stdin", data=b"canary=positive-001\n").strip()
        self.git(self.origin, "update-index", "--add", "--cacheinfo", "100644," + blob + ",canary.txt")
        self.tree = self.git(self.origin, "write-tree").strip()
        self.head = self.git(self.origin, "commit-tree", self.tree, "-p", self.base, "-m", "Harmless canary label").strip()
        self.merge = self.git(self.origin, "commit-tree", self.tree, "-p", self.base, "-p", self.head, "-m", "Fixture generated merge").strip()
        self.git(self.origin, "update-ref", "refs/heads/canary/positive", self.head)
        self.git(self.origin, "update-ref", "refs/pull/1/merge", self.merge)
        self.fetches = 0
        self.counter = 0

    def git(self, repository, *arguments, data=None, binary=False):
        completed = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(repository), *arguments], input=data, env=self.environment, capture_output=True, timeout=5, check=True)
        return completed.stdout if binary else completed.stdout.decode()

    def fetch(self, verifier, git, candidate, selected, deadline):
        self.fetches += 1
        shutil.copytree(self.origin, candidate)
        self.git(candidate, "update-ref", "refs/verification/merge", self.merge)

    def tree_api(self, tree):
        result = []
        for line in self.git(self.origin, "ls-tree", "-r", "-t", "-z", tree, binary=True).split(b"\0"):
            if line:
                meta, path = line.split(b"\t", 1)
                mode, kind, sha = meta.decode().split()
                entry = {"path": path.decode(), "mode": mode, "type": kind, "sha": sha}
                if kind == "blob":
                    entry["size"] = len(self.git(self.origin, "cat-file", "blob", sha, binary=True))
                result.append(entry)
        return {"sha": tree, "truncated": False, "tree": result}

    def arguments(self, command="verify", role="verifier"):
        self.counter += 1
        return argparse.Namespace(command=command, role=role, installation_id=app.ROLES[role]["installation_id"], source_commit=self.base, pr_number=1, run_url="https://github.com/" + app.REPOSITORY["full_name"] + "/actions/runs/901", out=str(self.root / ("evidence-" + str(self.counter))))

    def hosted_environment(self, run_id=901, attempt=1):
        return {"CANARY_APP_TOKEN": ROLE_TOKEN, "CANARY_ACTIONS_READ_TOKEN": READ_TOKEN,
                "GITHUB_TOKEN": "fixture_unused_github_token", "GH_TOKEN": "fixture_unused_gh_token",
                "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                "GITHUB_REPOSITORY": app.REPOSITORY["full_name"], "GITHUB_REPOSITORY_ID": str(app.REPOSITORY["id"]),
                "GITHUB_SHA": self.base, "GITHUB_RUN_ID": str(run_id), "GITHUB_RUN_ATTEMPT": str(attempt),
                "GITHUB_WORKFLOW_REF": app.REPOSITORY["full_name"] + "/.github/workflows/app-bootstrap.yml@refs/heads/main"}


class Backend:
    def __init__(self, fixture):
        self.fixture, self.calls, self.posts, self.results = fixture, [], 0, []
        self.repository = {**app.REPOSITORY, "node_id": "R_fixture_canary", "private": False, "archived": False, "disabled": False, "default_branch": "main", "permissions": {"admin": False, "maintain": False, "push": True}}
        self.scope_count = 1
        self.scope_repositories = [copy.deepcopy(self.repository)]
        self.run = {"id": 901, "run_number": 3, "run_attempt": 1, "workflow_id": 77, "path": ".github/workflows/app-bootstrap.yml", "event": "workflow_dispatch", "head_branch": "main", "head_sha": fixture.base, "display_title": "canary-bootstrap:verify:pr-1", "status": "in_progress", "conclusion": None, "repository": copy.deepcopy(self.repository)}
        self.history = [copy.deepcopy(self.run)]
        self.history_count = None
        self.pr_reads = 0
        self.race = False
        self.graph_merge = fixture.merge
        self.tree_override = None
        self.post_error = False
        self.persist_before_lost_reply = False
        self.wrong_post_app = False
        self.output = None
        self.protection = {
            "required_status_checks": {"strict": True, "checks": [{"context": app.CHECK_NAME, "app_id": app.ROLES["verifier"]["app_id"]}]},
            "required_pull_request_reviews": {"require_last_push_approval": True, "required_approving_review_count": 1, "dismiss_stale_reviews": True, "require_code_owner_reviews": False, "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []}},
            **{name: {"enabled": expected} for name, expected in (("enforce_admins", True), ("required_linear_history", False), ("allow_force_pushes", False), ("allow_deletions", False), ("required_conversation_resolution", True), ("lock_branch", False))},
        }
        self.signatures, self.rules = {"enabled": False}, []

    def sender(self, method, url, headers, payload, timeout):
        self.calls.append((method, url, copy.deepcopy(payload)))
        self.assert_headers(url, headers, timeout)
        path = url.removeprefix(app.API)
        fixture = self.fixture
        if path == app.PREFIX:
            result = self.repository
        elif path == "/installation/repositories?per_page=100":
            result = {"total_count": self.scope_count, "repositories": self.scope_repositories}
        elif path == app.PREFIX + "/git/ref/heads/main":
            result = {"ref": "refs/heads/main", "object": {"sha": fixture.base, "type": "commit"}}
        elif path == app.PREFIX + "/git/ref/heads/canary/positive":
            result = {"ref": "refs/heads/canary/positive", "object": {"sha": fixture.head, "type": "commit"}}
        elif path == app.PREFIX + "/pulls/1":
            self.pr_reads += 1
            result = {"number": 1, "state": "open", "draft": False, "merged": False, "base": {"ref": "main", "sha": fixture.base, "repo": copy.deepcopy(self.repository)}, "head": {"ref": "canary/positive", "sha": fixture.head, "repo": copy.deepcopy(self.repository)}, "merge_commit_sha": fixture.merge}
            if self.race and self.pr_reads > 1:
                result["head"]["sha"] = "9" * 40
        elif path == "/graphql":
            result = {"data": {"repository": {"databaseId": app.REPOSITORY["id"], "id": self.repository["node_id"], "pullRequest": {"number": 1, "state": "OPEN", "isDraft": False, "merged": False, "isCrossRepository": False, "headRefOid": fixture.head, "baseRefOid": fixture.base, "potentialMergeCommit": {"oid": self.graph_merge}}}}}
        elif path.startswith(app.PREFIX + "/git/commits/"):
            sha = path.rsplit("/", 1)[1]
            result = {"sha": sha, "tree": {"sha": fixture.tree}, "parents": [{"sha": fixture.base}, {"sha": fixture.head}]}
        elif path.startswith(app.PREFIX + "/git/trees/"):
            result = fixture.tree_api(path.rsplit("/", 1)[1].split("?")[0])
            if self.tree_override:
                self.tree_override(result)
        elif "/check-runs?filter=" in path:
            result = {"total_count": len(self.results), "check_runs": self.results}
        elif path == app.PREFIX + "/check-runs" and method == "POST":
            self.posts += 1
            assert self.output is not None
            intent = Path(self.output) / "intent.json"
            assert intent.is_file() and intent.stat().st_mode & 0o777 == 0o600
            assert json.loads(intent.read_text())["request"] == payload
            result = {**copy.deepcopy(payload), "id": 444, "app": {"id": app.ROLES["verifier"]["app_id"] if not self.wrong_post_app else 999}}
            if not self.post_error or self.persist_before_lost_reply:
                self.results = [result]
            if self.post_error:
                raise urllib.error.URLError("simulated lost reply " + ROLE_TOKEN)
            return 201, app.encoded(result)
        elif path == app.PREFIX + "/branches/main/protection":
            result = self.protection
        elif path == app.PREFIX + "/branches/main/protection/required_signatures":
            result = self.signatures
        elif path == app.PREFIX + "/rules/branches/main":
            result = self.rules
        elif path.startswith(app.PREFIX + "/actions/runs/"):
            result = self.run
        elif path == app.PREFIX + "/actions/workflows/app-bootstrap.yml/runs?event=workflow_dispatch&branch=main&per_page=100":
            result = {"total_count": len(self.history) if self.history_count is None else self.history_count, "workflow_runs": self.history}
        else:
            raise AssertionError("unexpected fixture endpoint")
        return 200, app.encoded(result)

    @staticmethod
    def assert_headers(url, headers, timeout):
        assert url.startswith(app.API + "/")
        expected = READ_TOKEN if "/actions/" in url else ROLE_TOKEN
        assert headers["Authorization"] == "Bearer " + expected
        assert headers["Accept"] == "application/vnd.github+json"
        assert 0 < timeout <= 10


class AppBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="app-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(self.temporary.name)
        self.backend = Backend(self.fixture)
        self.environment = self.fixture.hosted_environment()

    def execute(self, arguments=None, environment=None):
        arguments = arguments or self.fixture.arguments()
        self.backend.output = arguments.out
        with patch.object(app, "ROOT", self.fixture.source), patch.object(app, "fetch_public", self.fixture.fetch), patch.dict(os.environ, self.environment if environment is None else environment, clear=True):
            return app.execute(arguments, self.backend.sender)

    def cli(self, arguments, sender=None):
        self.backend.output = arguments.out
        argv = ["app_bootstrap.py", arguments.command,
                "--installation-id", str(arguments.installation_id), "--out", arguments.out]
        if arguments.command == "preflight":
            argv.extend(("--role", arguments.role))
        else:
            argv.extend(("--pr-number", str(arguments.pr_number),
                         "--source-commit", arguments.source_commit, "--run-url", arguments.run_url))
        stdout = io.StringIO()
        with patch.object(app, "ROOT", self.fixture.source), patch.object(app, "fetch_public", self.fixture.fetch), patch.object(app, "transport", sender or self.backend.sender), patch.dict(os.environ, self.environment, clear=True), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
            status = app.main()
        return status, json.loads(stdout.getvalue())

    def test_actual_fixed_verification_creates_one_M_check_after_private_intent(self):
        arguments = self.fixture.arguments()
        result = self.execute(arguments)
        self.assertEqual(result["status"], "published", result)
        self.assertEqual(result["check"]["app_id"], 5572341)
        self.assertEqual(result["check"]["head_sha"], self.fixture.merge)
        self.assertEqual(self.backend.posts, 1)
        output = Path(arguments.out)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for path in output.glob("*.json"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(ROLE_TOKEN, path.read_text())
            self.assertNotIn(READ_TOKEN, path.read_text())
        report = json.loads((output / "verification.json").read_text())
        self.assertEqual(report["trusted_tests"]["cases"], 7)
        self.assertIn("Ran 7 tests", report["trusted_tests"]["output"])
        self.assertFalse(report["candidate_code_executed"])

    def test_real_preflight_scope_is_read_only_and_does_not_claim_opaque_issuer_proof(self):
        for role in ("verifier", "merger"):
            result = self.execute(self.fixture.arguments("preflight", role))
            self.assertEqual(result["status"], "ready", result)
            self.assertFalse(result["opaque_token_issuer_api_verified"])
            self.assertEqual(result["provider_check_posts"], 0)
        self.assertEqual(self.backend.posts, 0)

    def test_cli_reports_rejected_merger_guard_and_preserves_ready_output(self):
        self.backend.repository["permissions"]["admin"] = True
        status, summary = self.cli(self.fixture.arguments("preflight", "merger"))
        self.assertEqual(status, 1)
        self.assertEqual(summary["status"], "rejected")
        self.assertEqual(summary["reason"], "merge actor is not a non-admin/non-maintainer push actor")
        self.assertEqual(summary["stage"], "actor_permissions")
        self.assertEqual(summary["provider_check_posts"], 0)
        self.assertEqual(self.backend.posts, 0)
        status, summary = self.cli(self.fixture.arguments("preflight", "verifier"))
        self.assertEqual(status, 0)
        self.assertEqual(summary["status"], "ready")
        self.assertEqual(set(summary), {"status", "out", "provider_check_posts"})

    def test_cli_reports_failed_preflight_read_without_credential_diagnostics(self):
        for suffix, stage in (("/branches/main/protection", "classic_protection_read"),
                              ("/branches/main/protection/required_signatures", "required_signatures_read"),
                              ("/rules/branches/main", "effective_rules_read")):
            for error, reason in ((app.Refused("GitHub rejected the bounded request"), "GitHub rejected the bounded request"),
                                  (OSError("raw HTTP/Git failure " + ROLE_TOKEN), "bounded bootstrap could not complete"),
                                  (app.Refused("unexpected diagnostic " + ROLE_TOKEN), "bounded bootstrap could not complete")):
                def sender(method, url, headers, payload, timeout):
                    if url == app.API + app.PREFIX + suffix:
                        raise error
                    return self.backend.sender(method, url, headers, payload, timeout)
                status, summary = self.cli(self.fixture.arguments("preflight", "merger"), sender)
                self.assertEqual(status, 1)
                self.assertEqual(summary["status"], "rejected")
                self.assertEqual(summary["stage"], stage)
                self.assertEqual(summary["reason"], reason)
                self.assertEqual(summary["provider_check_posts"], 0)
                self.assertNotIn(ROLE_TOKEN, json.dumps(summary))
                self.assertNotIn(READ_TOKEN, json.dumps(summary))
        self.assertEqual(self.backend.posts, 0)

    def test_cli_keeps_lost_check_reply_uncertain_without_preflight_fields(self):
        self.backend.post_error = True
        status, summary = self.cli(self.fixture.arguments())
        self.assertEqual(status, 1)
        self.assertEqual(summary["status"], "uncertain")
        self.assertEqual(summary["provider_check_posts"], 1)
        self.assertEqual(set(summary), {"status", "out", "provider_check_posts"})
        self.assertNotIn(ROLE_TOKEN, json.dumps(summary))
        self.assertEqual(self.backend.posts, 1)

    def test_wrong_installation_or_source_is_rejected_before_API_calls(self):
        for field, value in (("installation_id", 1), ("source_commit", "0" * 40)):
            arguments = self.fixture.arguments()
            setattr(arguments, field, value)
            result = self.execute(arguments)
            self.assertEqual(result["status"], "rejected")
        self.assertFalse(self.backend.calls)

    def test_no_generic_GH_or_GITHUB_token_fallback(self):
        environment = self.environment.copy()
        del environment["CANARY_APP_TOKEN"]
        result = self.execute(environment=environment)
        self.assertEqual(result["status"], "rejected")
        self.assertFalse(self.backend.calls)

    def test_repository_identity_privacy_and_scope_are_enforced(self):
        for mutation in (lambda: self.backend.repository.update(id=1), lambda: self.backend.repository.update(private=True), lambda: setattr(self.backend, "scope_count", 2)):
            self.backend = Backend(self.fixture)
            mutation()
            result = self.execute()
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(self.backend.posts, 0)

    def test_merger_requires_actual_narrow_permissions_and_readable_classic_policy(self):
        mutations = (lambda: self.backend.repository["permissions"].update(admin=True), lambda: self.backend.repository["permissions"].update(maintain=True), lambda: self.backend.repository["permissions"].update(push=False), lambda: self.backend.rules.append({"type": "deletion"}), lambda: self.backend.signatures.update(enabled=True), lambda: self.backend.protection["required_status_checks"].update(strict=False))
        for mutation in mutations:
            self.backend = Backend(self.fixture)
            mutation()
            result = self.execute(self.fixture.arguments("preflight", "merger"))
            self.assertEqual(result["status"], "rejected", result)
            self.assertEqual(self.backend.posts, 0)

    def test_REST_GraphQL_identity_mismatch_rejects_before_fetch(self):
        self.backend.graph_merge = "8" * 40
        result = self.execute()
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(self.fixture.fetches, 0)
        self.assertEqual(self.backend.posts, 0)

    def test_candidate_metadata_rejects_before_any_public_fetch(self):
        changes = (
            lambda tree: tree.update(truncated=True),
            lambda tree: tree["tree"].append({"path": "unexpected", "type": "blob", "mode": "100644", "sha": "7" * 40, "size": 1}),
            lambda tree: next(item for item in tree["tree"] if item["path"] == "canary.txt").update(size=128 * 1024 + 1),
            lambda tree: next(item for item in tree["tree"] if item["path"] == "canary.txt").update(mode="120000"),
            lambda tree: next(item for item in tree["tree"] if item["path"] == "canary_app.py").update(sha="7" * 40),
        )
        for change in changes:
            self.backend = Backend(self.fixture)
            self.backend.tree_override = change
            result = self.execute()
            self.assertEqual(result["status"], "rejected", result)
        self.assertEqual(self.fixture.fetches, 0)

    def test_identity_race_after_actual_verification_does_not_publish(self):
        self.backend.race = True
        result = self.execute()
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(self.fixture.fetches, 1)
        self.assertEqual(self.backend.posts, 0)

    def test_unique_owned_exact_result_is_reused_without_POST(self):
        first = self.execute()
        self.assertEqual(first["status"], "published", first)
        second = self.execute()
        self.assertEqual(second["status"], "reused", second)
        self.assertEqual(self.backend.posts, 1)

    def test_duplicate_foreign_or_changed_existing_result_is_not_overwritten(self):
        self.assertEqual(self.execute()["status"], "published")
        original = copy.deepcopy(self.backend.results)
        for mutation in (lambda: self.backend.results.append(copy.deepcopy(self.backend.results[0])), lambda: self.backend.results[0]["app"].update(id=999), lambda: self.backend.results[0].update(external_id="sha256:" + "0" * 64)):
            self.backend.results = copy.deepcopy(original)
            mutation()
            result = self.execute()
            self.assertEqual(result["status"], "rejected", result)
        self.assertEqual(self.backend.posts, 1)

    def test_lost_reply_is_uncertain_and_does_not_retry(self):
        self.backend.post_error = True
        arguments = self.fixture.arguments()
        result = self.execute(arguments)
        self.assertEqual(result["status"], "uncertain", result)
        self.assertEqual(result["provider_check_posts"], 1)
        self.assertFalse(result["retry_permitted"])
        self.assertEqual(self.backend.posts, 1)
        self.assertTrue((Path(arguments.out) / "intent.json").is_file())
        self.assertNotIn(ROLE_TOKEN, json.dumps(result))

    def prior_failed_run(self):
        previous = copy.deepcopy(self.backend.run)
        previous.update(id=900, run_number=2, status="completed", conclusion="failure")
        self.backend.history.append(previous)
        return previous

    def test_unknown_prior_POST_cannot_resend_from_fresh_output_directory(self):
        self.backend.post_error = True
        self.assertEqual(self.execute()["status"], "uncertain")
        self.prior_failed_run()
        self.backend.post_error = False
        result = self.execute()
        self.assertEqual(result["status"], "pending", result)
        self.assertEqual(self.backend.posts, 1)

    def test_uncertain_prior_run_allows_only_discovery_of_exact_owned_result(self):
        self.backend.post_error = True
        self.backend.persist_before_lost_reply = True
        self.assertEqual(self.execute()["status"], "uncertain")
        self.prior_failed_run()
        self.backend.post_error = False
        result = self.execute()
        self.assertEqual(result["status"], "reused", result)
        self.assertFalse(result["hosted_guard"]["new_post_allowed"])
        self.assertEqual(self.backend.posts, 1)

    def test_hosted_guard_blocks_wrong_run_attempt_and_incomplete_history(self):
        for mutation in (lambda: self.backend.run.update(head_sha="0" * 40), lambda: self.backend.run.update(id=999), lambda: self.backend.run.update(run_attempt=2), lambda: self.backend.run.update(run_number=2), lambda: setattr(self.backend, "history_count", 2), lambda: self.backend.history.clear()):
            self.backend = Backend(self.fixture)
            mutation()
            result = self.execute()
            self.assertEqual(result["status"], "pending", result)
            self.assertEqual(self.backend.posts, 0)

    def test_current_rerun_and_prior_failed_cancelled_or_inprogress_run_block_new_POST(self):
        for status, conclusion in (("completed", "failure"), ("completed", "cancelled"), ("completed", "timed_out"), ("in_progress", None)):
            self.backend = Backend(self.fixture)
            previous = self.prior_failed_run()
            previous.update(status=status, conclusion=conclusion)
            self.assertEqual(self.execute()["status"], "pending")
        self.backend = Backend(self.fixture)
        self.backend.run["run_attempt"] = 2
        self.backend.history[0]["run_attempt"] = 2
        environment = self.fixture.hosted_environment(attempt=2)
        self.assertEqual(self.execute(environment=environment)["status"], "pending")
        self.assertEqual(self.backend.posts, 0)

    def test_missing_prior_run_number_or_title_cannot_authorize_a_new_POST(self):
        for missing in ("run_number", "display_title"):
            self.backend = Backend(self.fixture)
            previous = self.prior_failed_run()
            del previous[missing]
            self.assertEqual(self.execute()["status"], "pending")
            self.assertEqual(self.backend.posts, 0)

    def test_result_persistence_failure_after_POST_preserves_uncertainty(self):
        original = app.Bundle.write
        def broken(bundle, name, value):
            if name == "result.json":
                raise OSError("simulated fsync failure " + ROLE_TOKEN)
            return original(bundle, name, value)
        with patch.object(app.Bundle, "write", broken):
            result = self.execute()
        self.assertEqual(result["status"], "uncertain", result)
        self.assertEqual(result["provider_check_posts"], 1)
        self.assertFalse(result["local_receipt_persisted"])
        self.assertNotIn(ROLE_TOKEN, json.dumps(result))
        self.assertEqual(self.backend.posts, 1)

    def test_wrong_actual_check_App_or_ambiguous_readback_retains_uncertainty(self):
        self.backend.wrong_post_app = True
        result = self.execute()
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual(result["provider_check_posts"], 1)

    def test_existing_output_directory_is_never_reused(self):
        arguments = self.fixture.arguments()
        output = Path(arguments.out)
        output.mkdir()
        (output / "control").write_text("keep")
        with self.assertRaises(FileExistsError):
            self.execute(arguments)
        self.assertEqual((output / "control").read_text(), "keep")
        self.assertFalse(self.backend.calls)

    def test_all_actual_parent_Git_and_verifier_children_are_credential_free(self):
        actual = subprocess.Popen
        observed = []
        def checked(*arguments, **keywords):
            environment = keywords.get("env", {})
            observed.append(arguments[0][0])
            for name in ("CANARY_APP_TOKEN", "CANARY_ACTIONS_READ_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
                self.assertNotIn(name, environment)
            self.assertNotIn(ROLE_TOKEN, json.dumps(environment))
            self.assertNotIn(READ_TOKEN, json.dumps(environment))
            return actual(*arguments, **keywords)
        with patch.object(subprocess, "Popen", checked):
            result = self.execute()
        self.assertEqual(result["status"], "published", result)
        self.assertTrue(any("git" in executable for executable in observed))
        self.assertTrue(any("python" in executable for executable in observed))

    def test_public_fetch_is_fixed_shallow_and_never_has_App_tokens(self):
        calls = []
        def command(arguments, *, environment, deadline):
            calls.append((arguments, environment))
            self.assertNotIn("CANARY_APP_TOKEN", environment)
            self.assertNotIn("CANARY_ACTIONS_READ_TOKEN", environment)
            self.assertNotIn("GITHUB_TOKEN", environment)
            self.assertNotIn("GH_TOKEN", environment)
            return b"", b""
        selected = {"base_ref": "refs/heads/main", "head_ref": "refs/heads/canary/positive", "base_revision": self.fixture.base, "head_revision": self.fixture.head, "merge_revision": self.fixture.merge}
        with patch.dict(os.environ, self.environment, clear=True):
            app.fetch_public({"command": command}, argparse.Namespace(executable="/usr/bin/git"), self.fixture.root / "fresh.git", selected, time.monotonic() + 30)
        self.assertEqual(len(calls), 2)
        self.assertIn("--depth=1", calls[1][0])
        self.assertIn(app.PUBLIC_GIT, calls[1][0])
        self.assertIn("http.followRedirects=false", calls[1][0])
        self.assertIn("credential.helper=", calls[1][0])


class HTTPBoundaryTests(unittest.TestCase):
    def test_fixed_origin_no_redirects_and_bounded_response(self):
        self.assertIsNone(app.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.invalid/"))
        client = app.Client(ROLE_TOKEN, time.monotonic() + 5, lambda *args: (302, ROLE_TOKEN.encode()))
        with self.assertRaises(app.Refused):
            client.request("GET", app.PREFIX)
        self.assertEqual(client.calls, 1)
        huge = app.Client(ROLE_TOKEN, time.monotonic() + 5, lambda *args: (200, b"x" * (app.MAX_RESPONSE + 1)))
        with self.assertRaises(app.Refused):
            huge.request("GET", app.PREFIX)
        with self.assertRaises(app.Refused):
            huge.request("GET", "https://example.invalid/steal")

    def test_read_budget_and_expired_deadline_fail_before_transport(self):
        count = []
        client = app.Client(ROLE_TOKEN, time.monotonic() + 5, lambda *args: (count.append(1) or 200, b"{}"))
        for _ in range(app.MAX_HTTP_CALLS):
            client.request("GET", app.PREFIX)
        with self.assertRaises(app.Refused):
            client.request("GET", app.PREFIX)
        self.assertEqual(len(count), app.MAX_HTTP_CALLS)
        client.deadline = time.monotonic() - 1
        with self.assertRaises(app.Refused):
            client.request("GET", app.PREFIX)

    def test_client_cannot_retry_check_creation(self):
        calls = []
        def lost(*arguments):
            calls.append(1)
            raise OSError("lost reply")
        client = app.Client(ROLE_TOKEN, time.monotonic() + 5, lost)
        body = {"name": app.CHECK_NAME, "head_sha": "1" * 40}
        with self.assertRaises(OSError):
            client.request("POST", app.PREFIX + "/check-runs", body)
        with self.assertRaises(app.Refused):
            client.request("POST", app.PREFIX + "/check-runs", body)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
