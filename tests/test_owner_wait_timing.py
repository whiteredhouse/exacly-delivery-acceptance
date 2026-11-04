"""Published owner deadlines and safe stops match the bounded, shared relay.

All clocks and GitHub responses are controlled. These cases create no App token,
operator installation, allowance, workflow dispatch or live provider activity.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
from types import SimpleNamespace
import unittest

import test_native_positive_trial as coordinator_fixture
import test_native_supplemental_trial as supplemental_fixture
import test_native_trial_relay as relay_fixture


SECRET = "fixture-credential-response-body-/private/journal.sqlite3"


def date(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class SplitClock:
    def __init__(self):
        self.wall = 0.0
        self.monotonic = 0.0
        self.sleeps = []

    def now(self):
        return relay_fixture.NOW + dt.timedelta(seconds=self.wall)

    def mono(self):
        return self.monotonic

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.advance(seconds)


class OwnerWaitTimingTests(unittest.TestCase):
    def setUp(self):
        self.setup()

    def setup(self, *, supplemental=True):
        self.relay = relay_fixture.relay
        self.clock = SplitClock()
        self.read_latency = 0
        self.after_read = None
        self.request_times = []
        if supplemental:
            module = supplemental_fixture.load("native_trial_protocol")
            self.protocol = module.load(supplemental_fixture.ROOT)
            self.context = copy.deepcopy(supplemental_fixture.CONTEXT)
            self.token = supplemental_fixture.TOKEN
            self.backend = supplemental_fixture.Backend(self.relay, module, self.protocol)
        else:
            self.protocol = None
            self.context = copy.deepcopy(relay_fixture.CONTEXT)
            self.token = relay_fixture.TOKEN
            self.backend = relay_fixture.Backend()
        self.client = self.relay.Relay(
            self.token, self.context, protocol=self.protocol, sender=self.sender,
            clock=self.clock.now, monotonic=self.clock.mono, sleep=self.clock.sleep,
        )
        self.client.check_host()
        if supplemental:
            self.client.check_supplemental_allowance()
            self.client.recheck_host()
        self.comment_polls = 0

    def sender(self, method, url, headers, payload, timeout):
        path = url.removeprefix(self.relay.API)
        self.request_times.append((path, self.clock.wall, self.clock.monotonic))
        if path == self.relay.COMMENTS:
            self.comment_polls += 1
        result = self.backend.sender(method, url, headers, payload, timeout)
        self.clock.advance(self.read_latency)
        if self.after_read is not None:
            self.after_read(path)
        return result

    def selection(self, phase="merge"):
        return relay_fixture.selection(phase)

    def plan(self, phase="merge", *, lease=None):
        return self.client.plan_wait(
            self.selection(phase),
            credential_expires_at=lease or relay_fixture.NOW + dt.timedelta(seconds=1800),
        )

    def approve(self, phase="merge", *, created=None, identifier=71):
        value = relay_fixture.comment(self.relay.approval_command(self.selection(phase)), identifier)
        timestamp = (created or self.clock.now()).strftime("%Y-%m-%dT%H:%M:%SZ")
        value.update(created_at=timestamp, updated_at=timestamp)
        self.backend.comments = [value]

    def last_poll_approval(self, plan, *, phase="merge", created=None):
        original = self.sender

        def sender(method, url, headers, payload, timeout):
            if url.removeprefix(self.relay.API) == self.relay.COMMENTS:
                if self.comment_polls + 1 == plan["allowed_polls"]:
                    self.approve(phase, created=created or date(plan["submit_by"]) - dt.timedelta(seconds=1))
            return original(method, url, headers, payload, timeout)

        self.client._sender = sender

    def restore(self, state):
        self.client = self.relay.Relay.restore(
            self.token, self.context, state, protocol=self.protocol, sender=self.sender,
            clock=self.clock.now, monotonic=self.clock.mono, sleep=self.clock.sleep,
        )
        return self.client

    def test_public_window_ends_with_actual_last_poll_instead_of_ten_minute_claim(self):
        self.setup(supplemental=False)
        plan = self.plan()
        self.assertEqual(plan["allowed_polls"], 25)
        self.assertEqual(date(plan["submit_by"]) - date(plan["issued_at"]), dt.timedelta(seconds=480))
        self.assertEqual(date(plan["verify_by"]) - date(plan["submit_by"]), dt.timedelta(seconds=21))
        self.assertLess(date(plan["verify_by"]), date(plan["issued_at"]) + dt.timedelta(seconds=600))
        with self.assertRaises(self.relay.RelayStopped) as stopped:
            self.client.wait(self.selection(), plan=plan)
        self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.POLL_BUDGET_EXHAUSTED)
        self.assertEqual(self.clock.wall, 480)
        self.assertEqual(self.clock.monotonic, 480)
        self.assertEqual(self.comment_polls, 25)
        self.assertEqual(self.clock.sleeps, [20] * 24)

    def test_supplemental_plan_preserves_budgets_and_reserves_history_and_observation(self):
        self.assertEqual(self.client.reads, 10)
        before = len(self.backend.calls)
        plan = self.plan()
        self.assertEqual(plan["allowed_polls"], 25)
        self.assertEqual(plan["post_selection_reads"], 6)
        self.assertEqual(plan["future_phase_reads"], 8)
        self.assertEqual(plan["verification_reserve_seconds"], 71)
        self.assertEqual(date(plan["submit_by"]) - date(plan["issued_at"]), dt.timedelta(seconds=480))
        self.assertEqual(date(plan["verify_by"]) - date(plan["issued_at"]), dt.timedelta(seconds=551))
        self.assertEqual(len(self.backend.calls), before)
        self.assertEqual(self.relay.MAX_READS, 64)
        self.assertEqual(self.relay.MAX_POLLS, 25)
        self.assertEqual(self.relay.MAX_SECONDS, 600)

    def test_last_poll_accepts_pre_cutoff_comment_and_finishes_reserved_verification(self):
        plan = self.plan()
        self.last_poll_approval(plan)
        self.read_latency = 10
        receipt = self.client.wait(self.selection(), plan=plan)
        self.assertEqual(receipt["created_at"], (date(plan["submit_by"]) - dt.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertGreater(self.clock.now(), date(plan["submit_by"]))
        self.client.recheck_host()
        self.assertLess(self.clock.now(), date(plan["verify_by"]))
        self.assertEqual(self.comment_polls, 25)
        self.assertEqual(self.client.reads, 41)

    def test_comment_created_exactly_at_public_submission_cutoff_is_refused(self):
        plan = self.plan()
        self.last_poll_approval(plan, created=date(plan["submit_by"]))
        with self.assertRaises(self.relay.RelayStopped):
            self.client.wait(self.selection(), plan=plan)
        self.assertFalse(any(path.endswith("/issues/comments/71") for path, _, _ in self.request_times))

    def test_final_comment_read_finishing_at_verification_cutoff_returns_no_selection(self):
        plan = self.plan()
        self.last_poll_approval(plan)

        def finish_at_cutoff(path):
            if path.endswith("/issues/comments/71"):
                self.clock.wall = (date(plan["verify_by"]) - relay_fixture.NOW).total_seconds()
                self.clock.monotonic = self.clock.wall

        self.after_read = finish_at_cutoff
        with self.assertRaises(self.relay.RelayStopped) as stopped:
            self.client.wait(self.selection(), plan=plan)
        self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.VERIFICATION_EXPIRED)

    def test_pre_effect_history_finishing_at_verification_cutoff_is_refused(self):
        plan = self.plan()
        self.last_poll_approval(plan)
        self.read_latency = 10
        self.client.wait(self.selection(), plan=plan)

        def finish_at_cutoff(path):
            if path.endswith("/approvals"):
                self.clock.wall = (date(plan["verify_by"]) - relay_fixture.NOW).total_seconds()
                self.clock.monotonic = self.clock.wall

        self.after_read = finish_at_cutoff
        with self.assertRaises(self.relay.RelayStopped):
            self.client.recheck_host()

    def test_final_local_allowance_validation_must_finish_before_verification_cutoff(self):
        plan = self.plan()
        self.approve()
        self.client.wait(self.selection(), plan=plan)
        review = self.client._review_allowance

        def late_validation():
            result = review()
            self.clock.wall = (date(plan["verify_by"]) - relay_fixture.NOW).total_seconds()
            self.clock.monotonic = self.clock.wall
            return result

        self.client._review_allowance = late_validation
        with self.assertRaises(self.relay.RelayStopped) as stopped:
            self.client.recheck_host()
        self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.VERIFICATION_EXPIRED)

    def test_low_get_budget_exposes_shorter_window_and_keeps_observer_minimum(self):
        self.client.reads = 48
        plan = self.plan()
        self.assertEqual(plan["allowed_polls"], 2)
        self.assertEqual(date(plan["submit_by"]) - date(plan["issued_at"]), dt.timedelta(seconds=20))
        self.last_poll_approval(plan)
        self.client.wait(self.selection(), plan=plan)
        self.client.recheck_host()
        self.assertEqual(self.client.reads, 56)
        observe = self.plan("observe")
        self.assertEqual(observe["allowed_polls"], 2)
        self.assertEqual(observe["future_phase_reads"], 0)
        self.assertEqual(date(observe["submit_by"]) - date(observe["issued_at"]), dt.timedelta(seconds=20))

    def test_insufficient_get_reserve_stops_before_publication_or_provider_read(self):
        self.client.reads = 49
        before = len(self.backend.calls)
        with self.assertRaises(self.relay.RelayStopped) as stopped:
            self.plan()
        self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.READ_BUDGET_INSUFFICIENT)
        self.assertEqual(self.client.reads, 49)
        self.assertEqual(len(self.backend.calls), before)

    def test_observer_window_uses_shared_remaining_gets_after_full_merge_polling(self):
        merge = self.plan()
        self.last_poll_approval(merge)
        self.client.wait(self.selection(), plan=merge)
        self.client.recheck_host()
        self.assertEqual(self.client.reads, 41)
        observe = self.plan("observe")
        self.assertEqual(observe["allowed_polls"], 17)
        self.assertEqual(date(observe["submit_by"]) - date(observe["issued_at"]), dt.timedelta(seconds=320))
        self.assertEqual(observe["post_selection_reads"], 6)
        self.assertEqual(observe["future_phase_reads"], 0)

    def test_credential_deadline_can_shorten_but_never_extend_the_public_plan(self):
        lease = self.clock.now() + dt.timedelta(seconds=100)
        plan = self.plan(lease=lease)
        self.assertEqual(plan["allowed_polls"], 2)
        self.assertEqual(date(plan["submit_by"]) - date(plan["issued_at"]), dt.timedelta(seconds=20))
        self.assertEqual(date(plan["verify_by"]) - date(plan["issued_at"]), dt.timedelta(seconds=91))
        self.assertLess(date(plan["verify_by"]), lease)

    def test_too_short_credential_cannot_publish_a_window_without_verification_reserve(self):
        before = len(self.backend.calls)
        with self.assertRaises(self.relay.RelayStopped):
            self.plan(lease=self.clock.now() + dt.timedelta(seconds=90))
        self.assertEqual(len(self.backend.calls), before)

    def test_upload_and_step_restore_preserve_public_cutoffs_and_do_not_catch_up(self):
        plan = self.plan()
        state = self.client.export_state()
        self.clock.advance(120)
        self.restore(state)
        restored_plan = self.client.export_state()["payload"]["pending_wait"]["plan"]
        self.assertEqual(restored_plan, plan)
        self.approve(created=relay_fixture.NOW + dt.timedelta(seconds=90))
        receipt = self.client.wait(self.selection(), plan=plan)
        self.assertEqual(receipt["created_at"], "2026-11-02T12:01:30Z")
        scans = [wall for path, wall, _ in self.request_times if path == self.relay.COMMENTS]
        self.assertEqual(scans, [120])

    def test_off_slot_upload_delay_skips_missed_scans_and_preserves_twenty_second_spacing(self):
        for delay, second in ((5, 40), (25, 60)):
            with self.subTest(delay=delay):
                self.setup()
                plan = self.plan()
                state = self.client.export_state()
                self.clock.advance(delay)
                self.restore(state)
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.wait(self.selection(), plan=plan)
                scans = [wall for path, wall, _ in self.request_times if path == self.relay.COMMENTS]
                self.assertEqual(scans[:2], [delay, second])
                self.assertEqual(scans[-1], 480)
                self.assertLessEqual(len(scans), plan["allowed_polls"])
                self.assertTrue(all(later - earlier >= 20 for earlier, later in zip(scans, scans[1:])))

    def test_restore_near_submission_cutoff_waits_for_final_slot_without_burst(self):
        plan = self.plan()
        state = self.client.export_state()
        self.clock.advance(470)
        self.restore(state)
        self.approve(created=relay_fixture.NOW + dt.timedelta(seconds=469))
        self.client.wait(self.selection(), plan=plan)
        scans = [wall for path, wall, _ in self.request_times if path == self.relay.COMMENTS]
        self.assertEqual(scans, [480])

    def test_late_wakeup_near_final_slot_defers_every_scan_to_preserve_spacing(self):
        plan = self.plan()

        def wake_late(seconds):
            self.clock.sleep(seconds)
            if self.clock.monotonic == 460:
                self.clock.advance(1)

        self.client._sleep = wake_late
        with self.assertRaises(self.relay.RelayStopped):
            self.client.wait(self.selection(), plan=plan)
        scans = [wall for path, wall, _ in self.request_times if path == self.relay.COMMENTS]
        self.assertEqual(scans[-2:], [440, 480])
        self.assertNotIn(461, scans)
        self.assertTrue(all(later - earlier >= 20 for earlier, later in zip(scans, scans[1:])))

    def test_comment_matching_before_this_proposal_publication_is_not_a_fresh_selection(self):
        self.clock.advance(100)
        plan = self.plan()
        self.approve(created=relay_fixture.NOW + dt.timedelta(seconds=99))
        with self.assertRaises(self.relay.RelayStopped):
            self.client.wait(self.selection(), plan=plan)

    def test_restored_plan_cannot_be_renewed_for_the_same_phase(self):
        plan = self.plan()
        state = self.client.export_state()
        self.clock.advance(120)
        self.restore(state)
        before = len(self.backend.calls)
        with self.assertRaises(self.relay.RelayStopped) as stopped:
            self.plan()
        self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.PHASE_REUSED)
        self.assertEqual(len(self.backend.calls), before)
        self.assertEqual(plan["submit_by"], "2026-11-02T12:08:00.000000Z")

    def test_starting_or_restoring_wait_at_submission_cutoff_fails_without_a_get(self):
        for action in ("wait", "restore"):
            with self.subTest(action=action):
                self.setup()
                plan = self.plan()
                state = self.client.export_state()
                self.clock.advance(480)
                self.approve(created=relay_fixture.NOW + dt.timedelta(seconds=479))
                before = len(self.backend.calls)
                with self.assertRaises(self.relay.RelayStopped) as stopped:
                    if action == "wait":
                        self.client.wait(self.selection(), plan=plan)
                    else:
                        self.restore(state)
                self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.SUBMISSION_EXPIRED)
                self.assertEqual(len(self.backend.calls), before)

    def test_checkpoint_tamper_cannot_extend_submission_verification_or_shared_reads(self):
        self.plan()
        state = self.client.export_state()
        mutations = (
            lambda p: p["pending_wait"]["plan"].update(submit_by="2026-11-02T12:20:00.000000Z"),
            lambda p: p["pending_wait"]["plan"].update(verify_by="2026-11-02T12:21:00.000000Z"),
            lambda p: p["pending_wait"].update(verify_monotonic=1260),
            lambda p: p.update(reads=0),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(state)
                mutate(changed["payload"])
                with self.assertRaises(self.relay.RelayStopped):
                    self.restore(changed)

    def test_old_checkpoint_shape_is_not_treated_as_a_new_wait_allowance(self):
        self.plan()
        state = self.client.export_state()
        state["payload"]["schema_version"] = "0.1.0"
        with self.assertRaises(self.relay.RelayStopped):
            self.restore(state)

    def test_either_clock_reaching_verification_cutoff_cannot_return_owner_authority(self):
        for moving in ("wall", "monotonic"):
            with self.subTest(moving=moving):
                self.setup()
                plan = self.plan()
                self.approve()
                setattr(self.clock, moving, 551)
                before = len(self.backend.calls)
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.wait(self.selection(), plan=plan)
                self.assertEqual(len(self.backend.calls), before)

    def test_clock_regression_after_checkpoint_cannot_refresh_the_window(self):
        for moving in ("wall", "monotonic"):
            with self.subTest(moving=moving):
                self.setup()
                self.clock.advance(10)
                self.plan()
                state = self.client.export_state()
                setattr(self.clock, moving, 9)
                before = len(self.backend.calls)
                with self.assertRaises(self.relay.RelayStopped):
                    self.restore(state)
                self.assertEqual(len(self.backend.calls), before)

    def test_original_job_lifetime_clips_observer_window_without_resetting_birth(self):
        self.approve()
        merge = self.plan()
        self.client.wait(self.selection(), plan=merge)
        self.client.recheck_host()
        self.clock.advance(1700)
        observe = self.plan("observe", lease=relay_fixture.NOW + dt.timedelta(seconds=3600))
        self.assertEqual(date(observe["submit_by"]) - relay_fixture.NOW, dt.timedelta(seconds=1720))
        self.assertEqual(date(observe["verify_by"]) - relay_fixture.NOW, dt.timedelta(seconds=1791))
        self.assertLess(date(observe["verify_by"]), relay_fixture.NOW + dt.timedelta(seconds=1800))

    def test_sender_cannot_forge_an_owned_owner_denial_stop_reason(self):
        plan = self.plan()

        def forged_provider_exception(path):
            if path == self.relay.COMMENTS:
                raise self.relay.RelayStopped(SECRET, code=self.relay.RelayStopCode.OWNER_DENIED)

        self.backend.on_request = forged_provider_exception
        with self.assertRaises(self.relay.RelayStopped) as stopped:
            self.client.wait(self.selection(), plan=plan)
        self.assertEqual(stopped.exception.code, self.relay.RelayStopCode.PROVIDER_READ_FAILED)
        report = coordinator_fixture.coordinator.failure_report(
            "merge", None, error=stopped.exception, relays=self.relay)
        self.assertEqual(report["diagnostic"], {"component": "relay", "code": "provider_read_failed"})
        self.assertNotIn(SECRET, json.dumps(report))


class ClosedStopDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.relay = relay_fixture.relay
        self.coordinator = coordinator_fixture.coordinator

    def projection(self, error, *, module=None):
        return self.coordinator.failure_report(
            "merge", None, error=error, relays=self.relay if module is None else module)["diagnostic"]

    def test_each_exact_owned_stop_enum_has_only_fixed_component_and_code(self):
        for code in self.relay.RelayStopCode:
            with self.subTest(code=code.value):
                error = self.relay.RelayStopped(SECRET, code=code)
                self.assertEqual(self.projection(error), {"component": "relay", "code": code.value})
                self.assertNotIn(SECRET, json.dumps(self.projection(error)))

    def test_unknown_string_forged_or_subclassed_tags_do_not_become_public_codes(self):
        class Derived(self.relay.RelayStopped):
            pass

        foreign = RuntimeError(SECRET)
        foreign.code = self.relay.RelayStopCode.OWNER_DENIED
        errors = (
            self.relay.RelayStopped(SECRET), self.relay.RelayStopped(SECRET, code="owner_denied"),
            self.relay.RelayStopped(SECRET, code=SECRET),
            Derived(SECRET, code=self.relay.RelayStopCode.OWNER_DENIED), foreign,
        )
        for error in errors:
            with self.subTest(error_type=type(error).__name__):
                self.assertEqual(self.projection(error), {"component": "unknown", "code": "unclassified_failure"})

    def test_exception_args_text_cause_and_response_attributes_are_not_inspected(self):
        accesses = []

        class Sensitive(RuntimeError):
            def __str__(self):
                accesses.append("str")
                raise AssertionError("exception text was inspected")

            def __getattribute__(self, name):
                if name in {"args", "code", "response", "__cause__", "__context__"}:
                    accesses.append(name)
                    raise AssertionError("exception details were inspected")
                return super().__getattribute__(name)

        error = Sensitive(SECRET)
        self.assertEqual(self.projection(error), {"component": "unknown", "code": "unclassified_failure"})
        self.assertEqual(accesses, [])
        wrapper = RuntimeError(SECRET)
        wrapper.__cause__ = self.relay.RelayStopped(SECRET, code=self.relay.RelayStopCode.OWNER_DENIED)
        self.assertEqual(self.projection(wrapper), {"component": "unknown", "code": "unclassified_failure"})

    def test_malformed_or_failing_projection_uses_fixed_unclassified_fallback(self):
        error = self.relay.RelayStopped(SECRET, code=self.relay.RelayStopCode.OWNER_DENIED)
        projections = ({"component": "relay", "code": "owner_denied", "body": SECRET}, SECRET, None)
        for value in projections:
            with self.subTest(value_type=type(value).__name__):
                module = SimpleNamespace(
                    RelayStopped=self.relay.RelayStopped, RelayStopCode=self.relay.RelayStopCode,
                    safe_diagnostic=lambda selected, value=value: value,
                )
                self.assertEqual(self.projection(error, module=module),
                                 {"component": "unknown", "code": "unclassified_failure"})

    def test_known_applied_state_and_no_resend_are_independent_of_safe_stop_code(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory(prefix="known-applied-stop-") as directory:
            private = Path(directory)
            private.chmod(0o700)
            self.coordinator.create_private(private / "merge-result.json", {"status": "applied"}, ())
            error = self.relay.RelayStopped(SECRET, code=self.relay.RelayStopCode.VERIFICATION_EXPIRED)
            report = self.coordinator.failure_report("observe", private, error=error, relays=self.relay)
            self.assertEqual(report["native_effect"], "applied")
            self.assertFalse(report["resend_allowed"])
            self.assertEqual(report["error_code"], "native_positive_trial_stopped")
            self.assertEqual(report["diagnostic"], {"component": "relay", "code": "verification_expired"})
            self.assertNotIn(SECRET, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
