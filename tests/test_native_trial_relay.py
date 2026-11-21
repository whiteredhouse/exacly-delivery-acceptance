"""Offline tests for the fixed owner relay; no GitHub credentials or requests."""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_trial_relay", ROOT / "tools/native_trial_relay.py")
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)
NOW = dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc)
TOKEN = "fake-relay-token-must-never-be-reported"
CONTEXT = {"repository": relay.REPOSITORY, "repository_id": relay.REPOSITORY_ID,
           "source": "f" * 40, "run_id": 901, "run_attempt": 1,
           "workflow_ref": relay.REPOSITORY + "/" + relay.WORKFLOW + "@" + relay.REF,
           "ref": relay.REF, "job": relay.JOB}


def selection(phase="merge"):
    value = {"phase": phase, "run_id": 901, "run_attempt": 1, "challenge": "a" * 64,
             "packet_digest": "sha256:" + "b" * 64, "issuer": "p1c2u",
             "approval_id": phase + "-owner-selection", "approval_digest": "sha256:" + "c" * 64}
    if phase == "merge":
        value["identity_digest"] = "sha256:" + "d" * 64
    return value


def comment(body, identifier=71):
    return {"id": identifier, "body": body, "created_at": "2026-11-02T12:00:00Z",
            "updated_at": "2026-11-02T12:00:00Z",
            "user": {"id": 1679024, "login": "p1c2u", "type": "User"},
            "url": relay.API + relay.PREFIX + "/issues/comments/" + str(identifier),
            "html_url": "https://github.com/" + relay.REPOSITORY + "/pull/5#issuecomment-" + str(identifier),
            "issue_url": relay.API + relay.PREFIX + "/issues/5"}


class Timer:
    def __init__(self):
        self.seconds = 0
        self.sleeps = []

    def now(self):
        return NOW + dt.timedelta(seconds=self.seconds)

    def mono(self):
        return float(self.seconds)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.seconds += seconds


class Backend:
    def __init__(self):
        self.calls, self.headers, self.status, self.raw = [], {}, {}, {}
        repository = {"id": relay.REPOSITORY_ID, "full_name": relay.REPOSITORY}
        self.run = {"id": 901, "run_number": 20, "run_attempt": 1, "workflow_id": 77,
                    "path": relay.WORKFLOW, "event": "workflow_dispatch",
                    "head_branch": "codex/preflight-diagnostics", "head_sha": CONTEXT["source"],
                    "display_title": relay.TITLE, "status": "in_progress", "conclusion": None,
                    "repository": repository, "head_repository": copy.deepcopy(repository)}
        self.history = [self.run]
        self.jobs = {"total_count": 1, "jobs": [{"id": 88, "name": relay.JOB, "run_id": 901,
                                                "run_attempt": 1, "head_sha": CONTEXT["source"],
                                                "status": "in_progress", "conclusion": None}]}
        self.comments, self.final_comments = [], {}
        self.comment_polls = 0
        self.on_comments = None
        self.fail_path = None
        self.on_request = None
        self.history_total = None

    def sender(self, method, url, headers, payload, timeout):
        self.calls.append(url)
        assert method == "GET" and payload is None and headers["Authorization"] == "Bearer " + TOKEN
        assert 0 < timeout <= 10
        path = url.removeprefix(relay.API)
        if self.on_request:
            self.on_request(path)
        if path == self.fail_path:
            raise RuntimeError(TOKEN)
        if path == relay.PREFIX + "/actions/workflows/app-bootstrap.yml":
            value = {"id": 77, "path": relay.WORKFLOW, "state": "active"}
        elif path == relay.PREFIX + "/actions/runs/901":
            value = self.run
        elif path.startswith(relay.PREFIX + "/actions/workflows/77/runs?"):
            page = int(path.rsplit("=", 1)[1])
            value = {"total_count": len(self.history) if self.history_total is None else self.history_total,
                     "workflow_runs": self.history[(page - 1) * 100:page * 100]}
        elif path == relay.PREFIX + "/actions/runs/901/attempts/1/jobs?per_page=100":
            value = self.jobs
        elif path == relay.COMMENTS:
            self.comment_polls += 1
            if self.on_comments:
                self.on_comments(self)
            value = self.comments
        elif path.startswith(relay.PREFIX + "/issues/comments/"):
            identifier = int(path.rsplit("/", 1)[1])
            value = self.final_comments.get(identifier)
            if value is None:
                value = next(item for item in self.comments if item["id"] == identifier)
        else:
            raise AssertionError("unexpected endpoint")
        data = self.raw.get(path, json.dumps(value).encode())
        return self.status.get(path, 200), data, self.headers.get(path, {})


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.backend, self.timer = Backend(), Timer()
        self.client = relay.Relay(TOKEN, CONTEXT, sender=self.backend.sender,
                                  clock=self.timer.now, monotonic=self.timer.mono, sleep=self.timer.sleep)

    def host(self):
        return self.client.check_host()

    def wait(self, value=None, seconds=600):
        return self.client.wait(value or selection(), expires_at=self.timer.now() + dt.timedelta(seconds=seconds))

    def approve(self, value=None, identifier=71):
        self.backend.comments = [comment(relay.approval_command(value or selection()), identifier)]

    def test_exact_owner_selection_and_final_get_are_bound_to_all_pins(self):
        self.assertEqual(self.host()["reads"], 4)
        expected = selection()
        self.approve(expected)
        receipt = self.wait(expected)
        self.assertEqual(receipt["selection"], expected)
        self.assertEqual(receipt["owner_id"], 1679024)
        self.assertEqual(receipt["repository_id"], relay.REPOSITORY_ID)
        self.assertEqual(receipt["pull_request"], 5)
        self.assertEqual(receipt["command_digest"], "sha256:" + hashlib.sha256(relay.approval_command(expected).encode()).hexdigest())
        self.assertEqual(self.client.reads, 6)
        self.assertTrue(self.backend.calls[-1].endswith("/issues/comments/71"))
        self.assertNotIn(TOKEN, json.dumps(receipt))

    def test_observation_requires_separate_selection_after_merge(self):
        self.host()
        self.approve()
        self.wait()
        self.approve(selection("observe"), 72)
        result = self.wait(selection("observe"))
        self.assertEqual(result["selection"]["phase"], "observe")
        self.assertNotIn("identity_digest", result["selection"])
        self.assertEqual(self.client.reads, 8)
        with self.assertRaises(relay.RelayStopped):
            self.wait(selection("observe"))
        self.assertEqual(self.client.reads, 8)

    def test_current_host_exact_identity_guards(self):
        mutations = [{"id": 999}, {"head_sha": "0" * 40}, {"run_attempt": 2},
                     {"event": "push"}, {"head_branch": "main"}, {"path": "other.yml"},
                     {"display_title": "canary-bootstrap:native-positive-trial:pr-0"},
                     {"status": "completed"}, {"head_repository": {"id": 1}}]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.setUp()
                self.backend.run.update(mutation)
                with self.assertRaises(relay.RelayStopped):
                    self.host()

    def test_context_cannot_select_another_repository_branch_or_attempt(self):
        for key, value in (("repository_id", True), ("repository", "other/repo"),
                           ("run_attempt", 2), ("job", "other"), ("ref", "refs/heads/main"),
                           ("source", "z" * 40), ("run_id", True)):
            with self.subTest(key=key):
                context = {**CONTEXT, key: value}
                with self.assertRaises(relay.RelayStopped):
                    relay.Relay(TOKEN, context, sender=self.backend.sender)
        self.assertEqual(self.backend.calls, [])

    def test_any_prior_trial_blocks_even_failed_cancelled_or_different_source(self):
        for conclusion in (None, "success", "failure", "cancelled", "timed_out"):
            with self.subTest(conclusion=conclusion):
                self.setUp()
                old = copy.deepcopy(self.backend.run)
                old.update(id=800, run_number=19, run_attempt=4, head_sha="1" * 40,
                           head_branch="older-reviewed-branch", status="completed", conclusion=conclusion)
                self.backend.history.append(old)
                with self.assertRaisesRegex(relay.RelayStopped, "already exists"):
                    self.host()
                self.assertEqual(self.client.reads, 3)
                with self.assertRaises(relay.RelayStopped):
                    self.host()
                self.assertEqual(self.client.reads, 3)

    def test_nontrial_history_is_allowed_without_filtering_source_or_branch(self):
        old = copy.deepcopy(self.backend.run)
        old.update(id=800, run_number=19, head_sha="1" * 40, head_branch="main",
                   display_title="canary-bootstrap:app-grant-preflight:pr-0", status="completed", conclusion="failure")
        self.backend.history.append(old)
        self.assertEqual(self.host()["history_count"], 2)
        self.assertFalse(any("branch=" in url or "status=" in url for url in self.backend.calls))

    def test_partial_duplicate_or_absent_current_history_rejects(self):
        for kind in ("partial", "duplicate", "missing", "count-bool", "over-bound"):
            with self.subTest(kind=kind):
                self.setUp()
                if kind == "partial": self.backend.history_total = 2
                if kind == "duplicate": self.backend.history.append(copy.deepcopy(self.backend.run))
                if kind == "missing": self.backend.history = []
                if kind == "count-bool": self.backend.history_total = True
                if kind == "over-bound": self.backend.history_total = 500
                with self.assertRaises(relay.RelayStopped):
                    self.host()

    def test_complete_bounded_history_pagination_is_verified_and_charged(self):
        self.backend.run["run_number"] = 200
        for number in range(1, 101):
            old = copy.deepcopy(self.backend.run)
            old.update(id=number, run_number=number, display_title="old-read-only-run",
                       status="completed", conclusion="success")
            self.backend.history.append(old)
        path = relay.PREFIX + "/actions/workflows/77/runs"
        self.backend.headers[path + "?per_page=100&page=1"] = {
            "Link": '<' + relay.API + path + '?per_page=100&page=2>; rel="next", <' + relay.API + path + '?per_page=100&page=2>; rel="last"'}
        self.backend.headers[path + "?per_page=100&page=2"] = {
            "Link": '<' + relay.API + path + '?per_page=100&page=1>; rel="prev", <' + relay.API + path + '?per_page=100&page=1>; rel="first"'}
        self.assertEqual(self.host()["history_count"], 101)
        self.assertEqual(self.client.reads, 5)

    def test_unsafe_history_links_never_followed(self):
        path = relay.PREFIX + "/actions/workflows/77/runs?per_page=100&page=1"
        self.backend.headers[path] = {"Link": '<https://evil.invalid/token>; rel="next"'}
        with self.assertRaises(relay.RelayStopped):
            self.host()
        self.assertEqual(self.client.reads, 3)
        self.assertTrue(all(url.startswith(relay.API + relay.PREFIX) for url in self.backend.calls))

    def test_wrong_or_partial_job_inventory_rejects(self):
        mutations = (("run_id", 1), ("run_attempt", 2), ("run_attempt", True),
                     ("head_sha", "a" * 40), ("status", "queued"), ("name", "different"))
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                self.setUp()
                self.backend.jobs["jobs"][0][key] = value
                with self.assertRaises(relay.RelayStopped):
                    self.host()
        self.setUp()
        self.backend.jobs["total_count"] = 2
        with self.assertRaises(relay.RelayStopped):
            self.host()

    def test_wrong_owner_bot_stale_edited_or_unsafe_comment_rejects(self):
        mutations = (("owner", None), ("bot", None), ("stale", None), ("edited", None),
                     ("url", "https://evil.invalid"), ("html_url", "https://github.com/other/repo/pull/5#issuecomment-71"),
                     ("issue_url", relay.API + relay.PREFIX + "/issues/6"))
        for key, value in mutations:
            with self.subTest(key=key):
                self.setUp()
                self.host()
                self.approve()
                item = self.backend.comments[0]
                if key == "owner": item["user"]["id"] = 123
                elif key == "bot": item["user"]["type"] = "Bot"
                elif key == "stale": item.update(created_at="2026-11-02T11:59:59Z", updated_at="2026-11-02T11:59:59Z")
                elif key == "edited": item["updated_at"] = "2026-11-02T12:00:01Z"
                else: item[key] = value
                with self.assertRaises(relay.RelayStopped):
                    self.wait()
                self.assertEqual(self.client.reads, 5)

    def test_multiple_owner_matches_and_exact_denial_abort(self):
        for mode in ("duplicate", "deny"):
            with self.subTest(mode=mode):
                self.setUp()
                self.host()
                self.approve()
                self.backend.comments.append(comment(relay.approval_command(selection()) if mode == "duplicate"
                                                     else relay.deny_command(selection()), 72))
                with self.assertRaises(relay.RelayStopped):
                    self.wait()
                self.assertEqual(self.client.reads, 5)

    def test_nonmatching_old_comments_are_ignored(self):
        self.host()
        self.approve()
        old = comment("Old unrelated discussion", 12)
        old.update(created_at="2020-01-01T00:00:00Z", updated_at="2020-01-02T00:00:00Z", user={"id": 2})
        self.backend.comments.insert(0, old)
        self.assertEqual(self.wait()["comment_id"], 71)

    def test_comment_final_get_must_revalidate_every_selected_fact(self):
        for change in ("body", "owner", "updated", "id", "url"):
            with self.subTest(change=change):
                self.setUp()
                self.host()
                self.approve()
                final = copy.deepcopy(self.backend.comments[0])
                if change == "owner": final["user"]["id"] = 2
                elif change == "updated": final["updated_at"] = "2026-11-02T12:00:01Z"
                elif change == "id": final["id"] = 72
                else: final[change] += "changed"
                self.backend.final_comments[71] = final
                with self.assertRaises(relay.RelayStopped):
                    self.wait()
                self.assertEqual(self.client.reads, 6)

    def test_partial_comments_and_duplicate_ids_are_not_accepted(self):
        for mode in ("link", "hundred", "duplicate"):
            with self.subTest(mode=mode):
                self.setUp()
                self.host()
                self.approve()
                if mode == "link": self.backend.headers[relay.COMMENTS] = {"Link": '<https://evil.invalid>; rel="next"'}
                if mode == "hundred": self.backend.comments = [comment("irrelevant", number) for number in range(1, 101)]
                if mode == "duplicate": self.backend.comments.append(copy.deepcopy(self.backend.comments[0]))
                with self.assertRaises(relay.RelayStopped):
                    self.wait()

    def test_all_selection_fields_are_exact_and_no_partial_command_is_accepted(self):
        self.host()
        command = relay.approval_command(selection())
        self.backend.comments = [comment(command + "\n")]
        with self.assertRaisesRegex(relay.RelayStopped, "poll budget"):
            self.wait()
        self.assertEqual(self.backend.comment_polls, 25)
        self.assertEqual(self.timer.sleeps, [20] * 24)
        self.assertEqual(self.client.reads, 29)
        with self.assertRaises(relay.RelayStopped):
            self.wait()
        self.assertEqual(self.client.reads, 29)

    def test_approval_for_another_run_or_bad_selection_never_reads(self):
        for key, value in (("run_id", 902), ("run_attempt", True), ("issuer", "other"),
                           ("identity_digest", "sha256:bad"), ("approval_id", "a b"),
                           ("challenge", "A" * 64), ("unknown", "field")):
            with self.subTest(key=key):
                self.setUp()
                self.host()
                with self.assertRaises(relay.RelayStopped):
                    self.wait({**selection(), key: value})
                self.assertEqual(self.client.reads, 4)

    def test_http_failure_and_malformed_json_have_no_retry_or_secret_output(self):
        path = relay.PREFIX + "/actions/workflows/app-bootstrap.yml"
        for mode in ("raise", "redirect", "rate-limit", "duplicate-json", "oversize", "nonfinite"):
            with self.subTest(mode=mode):
                self.setUp()
                if mode == "raise": self.backend.fail_path = path
                if mode == "redirect": self.backend.status[path] = 302
                if mode == "rate-limit": self.backend.status[path] = 429
                if mode == "duplicate-json": self.backend.raw[path] = b'{"id":77,"id":77}'
                if mode == "oversize": self.backend.raw[path] = b" " * (relay.MAX_BODY + 1)
                if mode == "nonfinite": self.backend.raw[path] = b'{"id":NaN}'
                with self.assertRaises(relay.RelayStopped) as caught:
                    self.host()
                self.assertNotIn(TOKEN, str(caught.exception))
                self.assertEqual(len(self.backend.calls), 1)
                with self.assertRaises(relay.RelayStopped):
                    self.host()
                self.assertEqual(len(self.backend.calls), 1)

    def test_budget_is_shared_and_final_revalidation_is_charged(self):
        self.host()
        self.approve()
        self.client.reads = 63
        with self.assertRaisesRegex(relay.RelayStopped, "GET budget"):
            self.wait()
        # A published window must fund its final reread and the following
        # phase; reject before spending a GET that cannot yield authority.
        self.assertEqual(self.client.reads, 63)
        self.assertEqual(len(self.backend.calls), 4)

    def test_expired_or_overdue_read_cannot_return_authority(self):
        for mode in ("expired", "wall", "during-final"):
            with self.subTest(mode=mode):
                self.setUp()
                self.host()
                self.approve()
                if mode == "wall":
                    self.backend.on_request = lambda path: setattr(self.timer, "seconds", 601)
                if mode == "during-final":
                    def expire(path):
                        if "/issues/comments/" in path:
                            self.timer.seconds = 601
                    self.backend.on_request = expire
                with self.assertRaisesRegex(relay.RelayStopped, "deadline"):
                    self.wait(seconds=-1 if mode == "expired" else 600)

    def test_phase_order_host_gate_and_no_automatic_renewal(self):
        with self.assertRaises(relay.RelayStopped):
            self.wait()
        self.assertEqual(self.client.reads, 0)
        self.setUp()
        self.host()
        with self.assertRaises(relay.RelayStopped):
            self.wait(selection("observe"))
        self.assertEqual(self.client.reads, 4)

    def restore(self, state, context=None, token=TOKEN):
        return relay.Relay.restore(token, context or CONTEXT, state, sender=self.backend.sender,
                                   clock=self.timer.now, monotonic=self.timer.mono, sleep=self.timer.sleep)

    def test_checkpoint_restores_total_budget_phase_order_and_original_time(self):
        self.host()
        prepared = self.client.export_state()
        self.assertNotIn(TOKEN, json.dumps(prepared))
        self.timer.seconds = 15
        self.client = self.restore(prepared)
        self.assertEqual(self.client.reads, 4)
        # Owner can select after upload and before the next Python step starts.
        self.approve()
        self.assertEqual(self.wait()["created_at"], "2026-11-02T12:00:00Z")
        merged = self.client.export_state()
        self.assertEqual(merged["payload"]["created_at"], prepared["payload"]["created_at"])
        self.assertEqual(merged["payload"]["created_monotonic"], prepared["payload"]["created_monotonic"])
        self.timer.seconds = 30
        self.client = self.restore(merged)
        self.assertEqual(self.client.reads, 6)
        self.approve(selection("observe"), 72)
        self.wait(selection("observe"))
        self.assertEqual(self.client.reads, 8)
        finished = self.client.export_state()
        self.client = self.restore(finished)
        with self.assertRaises(relay.RelayStopped):
            self.wait(selection("observe"))
        self.assertEqual(len(self.backend.calls), 8)

    def test_checkpoint_cannot_change_context_token_counters_phases_or_clock(self):
        self.host()
        state = self.client.export_state()
        for field, value in (("reads", 0), ("phases", []), ("created_monotonic", 1000),
                             ("host_checked", False), ("context", {**CONTEXT, "source": "a" * 40})):
            with self.subTest(field=field):
                changed = copy.deepcopy(state)
                changed["payload"][field] = value
                if field == "phases":
                    changed["payload"][field] = ["merge"]
                with self.assertRaises(relay.RelayStopped):
                    self.restore(changed)
        with self.assertRaises(relay.RelayStopped):
            self.restore(state, context={**CONTEXT, "source": "a" * 40})
        with self.assertRaises(relay.RelayStopped):
            self.restore(state, token="different-job-read-token")
        self.assertEqual(len(self.backend.calls), 4)

    def test_restored_budget_does_not_reset_between_steps(self):
        self.host()
        self.client.reads = 63
        self.client = self.restore(self.client.export_state())
        self.approve()
        with self.assertRaisesRegex(relay.RelayStopped, "GET budget"):
            self.wait()
        self.assertEqual(self.client.reads, 63)
        self.assertEqual(len(self.backend.calls), 4)
        with self.assertRaises(relay.RelayStopped):
            self.client.export_state()

    def test_failed_or_inflight_wait_cannot_be_checkpointed(self):
        self.host()
        self.backend.on_comments = lambda _: self.client.export_state()
        with self.assertRaises(relay.RelayStopped):
            self.wait()
        with self.assertRaises(relay.RelayStopped):
            self.client.export_state()

    def test_checkpoint_original_job_lifetime_cannot_be_extended(self):
        self.host()
        state = self.client.export_state()
        self.timer.seconds = 1800
        with self.assertRaisesRegex(relay.RelayStopped, "lifetime"):
            self.restore(state)

    def test_checkpoint_preserves_original_monotonic_deadline(self):
        self.host()
        self.approve()
        self.wait()
        state = self.client.export_state()
        self.timer.seconds = 10
        restored = self.restore(state)
        self.assertEqual(restored.export_state()["payload"]["deadline_monotonic"],
                         state["payload"]["deadline_monotonic"])
        self.assertEqual(restored.export_state()["payload"]["expires_at"],
                         state["payload"]["expires_at"])


if __name__ == "__main__":
    unittest.main()
