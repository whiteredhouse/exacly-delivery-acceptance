"""Offline behavioral checks for the three one-shot hosted coordinator steps.

The packet, owner-relay and execution boundaries below are controlled fixtures.
Real private files and phase markers exercise the coordinator; no provider or
native merge is contacted, and these tests make no live-acceptance claim.
"""
import copy
from contextlib import redirect_stdout
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_positive_trial", ROOT / "tools/native_positive_trial.py")
coordinator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coordinator)
NOW = dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc)
APP_TOKEN = "fixture-app-token-never-serialize"
RELAY_TOKEN = "fixture-read-only-relay-token-never-serialize"
SECRET_ERROR = "fixture-private-exception-text"
CONTEXT = {"repository": coordinator.REPOSITORY, "repository_id": 1442278205,
           "source": "f" * 40, "run_id": 901, "run_attempt": 1,
           "workflow_ref": coordinator.REPOSITORY + "/.github/workflows/app-bootstrap.yml@" + coordinator.REF,
           "ref": coordinator.REF, "job": "native-positive-trial"}


def selection(phase):
    value = {"phase": phase, "run_id": 901, "run_attempt": 1,
             "challenge": ("a" if phase == "merge" else "b") * 64,
             "packet_digest": "sha256:" + ("c" if phase == "merge" else "d") * 64,
             "issuer": "p1c2u", "approval_id": phase + "-fixture",
             "approval_digest": "sha256:" + "e" * 64}
    if phase == "merge":
        value["identity_digest"] = "sha256:" + "1" * 64
    return value


class Packets:
    def __init__(self, events):
        self.events = events
        self.prepared = None
        self.lease_seconds = 1800
        self.fail_write = None

    def write_safe(self, path, value, token):
        self.events.append(("write", path.name))
        if path.name == self.fail_write:
            raise RuntimeError(SECRET_ERROR + APP_TOKEN + RELAY_TOKEN)
        coordinator.create_private(path, value, (token, RELAY_TOKEN))

    def prepare(self, private, spec, context, core, token, installation_id, *, now):
        self.events.append(("packet-prepare", installation_id, copy.deepcopy(context)))
        private.mkdir(mode=0o700)
        authority_expiry = coordinator.timestamp(now + dt.timedelta(seconds=self.lease_seconds))
        prepared = {"private_dir": str(private), "core_source": str(core), "spec": spec,
                    "context": copy.deepcopy(context), "selection": selection("merge"),
                    "proposal": {"status": "proposed", "authority_granted": False,
                                 "operation_approval": {"expires_at": authority_expiry},
                                 "configuration": {"actor": {"grant": {
                                     "not_after": authority_expiry}}}},
                    "paths": {"journal": str(private / "journal.json")}, "_token": token}
        coordinator.create_private(private / "journal.json", {"original_journal": True}, (token, RELAY_TOKEN))
        self.prepared = prepared
        return prepared

    def save_private(self, prepared):
        state = {key: value for key, value in prepared.items() if key not in ("_token", "observer")}
        coordinator.create_private(Path(prepared["private_dir"]) / "prepared-state.json", state, (APP_TOKEN, RELAY_TOKEN))

    def restore(self, private, core, token):
        self.events.append(("packet-restore",))
        value = coordinator.read_private(private / "prepared-state.json")
        value["_token"] = token
        if (private / "observer-state.json").exists():
            value["observer"] = coordinator.read_private(private / "observer-state.json")
        return value

    def build_observer(self, prepared, report, *, now):
        self.events.append(("observer-draft", copy.deepcopy(report)))
        actual_packet = {"read_only": True, "actual_applied_receipt": report["receipt"],
                         "run_id": prepared["context"]["run_id"],
                         "read_approval": {"expires_at": prepared["proposal"]["configuration"]["actor"]["grant"]["not_after"]}}
        observer_selection = selection("observe")
        observer_selection["packet_digest"] = coordinator.digest(actual_packet)
        observer = {"selection": observer_selection,
                    "proposal": {"actual_packet": actual_packet, "packet": actual_packet},
                    "paths": {"packet": str(Path(prepared["private_dir"]) / "observer-packet.json")}}
        self.write_safe(Path(observer["paths"]["packet"]), actual_packet, prepared["_token"])
        self.write_safe(Path(prepared["private_dir"]) / "observer-state.json", observer, prepared["_token"])
        prepared["observer"] = observer
        return observer


class Relays:
    def __init__(self, events, *, clock):
        self.events = events
        self.clock = clock
        self.wait_error = None
        self.host_error = None
        self.receipts = []
        outer = self

        class Client:
            def __init__(self, token, context):
                assert token == RELAY_TOKEN and context == CONTEXT
                self.context = copy.deepcopy(context)
                self.phases = []
                self.reads = 0
                self.created_at = outer.clock()
                self.pending_plan = None

            @staticmethod
            def approval_command(value):
                return outer.approval_command(value)

            @staticmethod
            def deny_command(value):
                return outer.deny_command(value)

            def check_host(self):
                outer.events.append(("host",))
                if outer.host_error:
                    raise outer.host_error
                self.reads = 4

            def export_state(self):
                payload = {"context": self.context, "reads": self.reads, "phases": self.phases,
                           "created_at": coordinator.timestamp(self.created_at), "pending_plan": self.pending_plan}
                return {"payload": copy.deepcopy(payload), "fixture_mac": coordinator.digest(payload)}

            @classmethod
            def restore(cls, token, context, state):
                outer.events.append(("relay-restore", state["payload"]["reads"]))
                coordinator.require(state["fixture_mac"] == coordinator.digest(state["payload"]), "fixture_relay_changed")
                client = cls(token, context)
                coordinator.require(state["payload"]["context"] == context)
                client.reads = state["payload"]["reads"]
                client.phases = list(state["payload"]["phases"])
                client.created_at = coordinator.date(state["payload"]["created_at"])
                client.pending_plan = copy.deepcopy(state["payload"]["pending_plan"])
                return client

            def plan_wait(self, value, *, credential_expires_at):
                coordinator.require(self.pending_plan is None, "fixture_plan_cannot_restart")
                coordinator.require(value["phase"] == ("merge" if not self.phases else "observe"))
                issued = outer.clock()
                # Scheduling boundaries are tested against the real Relay separately.
                # This fixture binds the coordinator's published plan and original job clock.
                cap = min(issued + dt.timedelta(seconds=600), self.created_at + dt.timedelta(seconds=1800),
                          credential_expires_at)
                slots = min(24, int(((cap - issued).total_seconds() - 21) // 20))
                coordinator.require(slots >= 1, "fixture_no_usable_selection_window")
                submit = issued + dt.timedelta(seconds=slots * 20)

                def stamp(instant):
                    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")

                self.pending_plan = {"phase": value["phase"], "selection_digest": coordinator.digest(value),
                                     "issued_at": stamp(issued), "submit_by": stamp(submit),
                                     "verify_by": stamp(submit + dt.timedelta(seconds=21)),
                                     "allowed_polls": slots + 1,
                                     "post_selection_reads": 1,
                                     "future_phase_reads": 3 if value["phase"] == "merge" else 0,
                                     "verification_reserve_seconds": 21}
                outer.events.append(("owner-plan", copy.deepcopy(value), copy.deepcopy(self.pending_plan)))
                return copy.deepcopy(self.pending_plan)

            def wait(self, value, *, plan):
                coordinator.require(plan == self.pending_plan
                                    and plan["selection_digest"] == coordinator.digest(value), "fixture_plan_changed")
                coordinator.require(outer.clock() <= coordinator.date(plan["submit_by"]),
                                    "owner_selection_deadline_expired")
                outer.events.append(("owner-wait", copy.deepcopy(value), copy.deepcopy(plan)))
                if outer.wait_error:
                    raise outer.wait_error
                coordinator.require(value["phase"] == ("merge" if not self.phases else "observe"))
                self.phases.append(value["phase"])
                self.pending_plan = None
                self.reads += 2
                receipt = {"selection": copy.deepcopy(value), "fixture_fresh_owner_receipt": len(outer.receipts) + 1}
                outer.receipts.append(receipt)
                return receipt

        self.Relay = Client

    @staticmethod
    def approval_command(value):
        return "/fixture-native-trial approve " + coordinator.digest(value)

    @staticmethod
    def deny_command(value):
        return "/fixture-native-trial deny " + coordinator.digest(value)


class Execution:
    def __init__(self, events, relays):
        self.events, self.relays = events, relays
        self.merge_report = {"status": "applied", "receipt": {"id": "actual-receipt-from-fixture-invoke"}}
        self.replay_proof = {"status": "passed", "journal_unchanged": True, "network_syscalls": 0}
        self.observer_proof = {"status": "passed", "tests_passed": 1, "tests_skipped": 0,
                               "observer_calls": 1, "journal_unchanged": True}
        self.execute_error = self.replay_error = self.observe_error = None

    def execute(self, prepared, receipt, *, token):
        assert token == APP_TOKEN and receipt is self.relays.receipts[-1]
        assert receipt["selection"] == prepared["selection"]
        self.events.append(("execute", receipt))
        coordinator.create_private(Path(prepared["private_dir"]) / "execution-attempt.json",
                                   {"native_attempt": True}, (APP_TOKEN, RELAY_TOKEN))
        if self.execute_error:
            raise self.execute_error
        return copy.deepcopy(self.merge_report)

    def offline_replay(self, prepared, report, *, token):
        assert token == APP_TOKEN and report == self.merge_report
        self.events.append(("offline-replay",))
        if self.replay_error:
            raise self.replay_error
        return copy.deepcopy(self.replay_proof)

    def observe(self, prepared, observer, receipt, *, token):
        assert token == APP_TOKEN and receipt is self.relays.receipts[-1]
        assert receipt["selection"] == observer["selection"]
        self.events.append(("observe", receipt, copy.deepcopy(observer)))
        if self.observe_error:
            raise self.observe_error
        return copy.deepcopy(self.observer_proof)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="coordinator-fixture-")
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name).resolve()
        self.private = self.temp / "native-positive-901-1"
        self.core = self.temp / "controlled-core"
        self.core.mkdir()
        self.events = []
        self.now = NOW
        self.packets, self.relays = Packets(self.events), Relays(self.events, clock=lambda: self.now)
        self.execution = Execution(self.events, self.relays)
        self.output = io.StringIO()
        self.environment = {"CANARY_INSTALLATION_ID": "177653055", "RUNNER_TEMP": str(self.temp),
                            "CANARY_APP_TOKEN": APP_TOKEN, "CANARY_RELAY_TOKEN": RELAY_TOKEN}
        self.environment_patch = patch.dict(os.environ, self.environment, clear=True)
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)

    def run_phase(self, phase, **overrides):
        arguments = {"packets": self.packets, "relays": self.relays, "execution": self.execution,
                     "ctx": CONTEXT, "app_token": APP_TOKEN, "relay_token": RELAY_TOKEN,
                     "now": lambda: self.now, **overrides}
        with redirect_stdout(self.output):
            return coordinator.run(phase, self.private, self.core, **arguments)

    def read(self, name):
        return coordinator.read_private(self.private / name)

    def rewrite(self, name, change):
        path = self.private / name
        value = self.read(name)
        change(value)
        path.write_bytes(coordinator.canonical(value))
        path.chmod(0o600)

    def events_named(self, name):
        return [event for event in self.events if event[0] == name]

    def test_prepare_drafts_without_owner_wait_or_execution(self):
        result = self.run_phase("prepare")
        self.assertEqual(result["native_effect"], "not_attempted")
        self.assertEqual(len(self.events_named("host")), 1)
        for name in ("owner-wait", "execute", "offline-replay", "observe"):
            self.assertEqual(self.events_named(name), [])
        proposal = self.read("merge-approval-instructions.json")
        self.assertFalse(proposal["authority_granted"])
        self.assertEqual(proposal["owner"], {"id": 1679024, "login": "p1c2u"})
        self.assertEqual(proposal["comment_destination"], "https://github.com/" + coordinator.REPOSITORY + "/pull/5")
        checkpoint = self.read("coordinator-prepared.json")
        self.assertEqual(checkpoint["context"], CONTEXT)
        self.assertEqual(proposal["wait_plan"], self.events_named("owner-plan")[0][2])
        self.assertEqual(checkpoint["wait_plan"], proposal["wait_plan"])
        self.assertEqual(checkpoint["relay"]["payload"]["pending_plan"], proposal["wait_plan"])
        self.assertEqual(proposal["expires_at"], proposal["wait_plan"]["submit_by"])
        self.assertEqual(proposal["verification_expires_at"], proposal["wait_plan"]["verify_by"])
        self.assertTrue((self.private / "prepare-consumed.json").exists())
        for path in self.private.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.private.stat().st_mode & 0o777, 0o700)

    def test_full_three_phase_flow_preserves_receipt_and_requires_separate_observer_selection(self):
        self.run_phase("prepare")
        self.run_phase("merge")
        result = self.run_phase("observe")
        self.assertEqual(result["status"], "positive_trial_completed")
        self.assertFalse(result["runner_loss_recovery_verified"])
        self.assertEqual(len(self.events_named("execute")), 1)
        self.assertEqual(len(self.events_named("observe")), 1)
        waits = self.events_named("owner-wait")
        self.assertEqual([event[1]["phase"] for event in waits], ["merge", "observe"])
        self.assertEqual([event[2] for event in waits], [event[2] for event in self.events_named("owner-plan")])
        self.assertNotEqual(waits[0][1]["challenge"], waits[1][1]["challenge"])
        observer = self.events_named("observe")[0][2]
        self.assertEqual(observer["proposal"]["actual_packet"]["actual_applied_receipt"], self.execution.merge_report["receipt"])
        self.assertEqual(waits[1][1]["packet_digest"], coordinator.digest(observer["proposal"]["actual_packet"]))
        self.assertEqual(self.events_named("execute")[0][1], self.relays.receipts[0])
        self.assertEqual(self.read("coordinator-observed.json")["relay"]["payload"]["reads"], 8)
        public_and_private_output = self.output.getvalue() + "".join(
            path.read_text() for path in self.private.iterdir() if path.is_file())
        self.assertNotIn(APP_TOKEN, public_and_private_output)
        self.assertNotIn(RELAY_TOKEN, public_and_private_output)

    def test_absent_owner_selection_stops_before_execute_and_consumes_phase(self):
        self.run_phase("prepare")
        self.relays.wait_error = RuntimeError(SECRET_ERROR)
        with self.assertRaises(RuntimeError):
            self.run_phase("merge")
        self.assertEqual(self.events_named("execute"), [])
        self.assertTrue((self.private / "merge-consumed.json").exists())
        self.relays.wait_error = None
        with self.assertRaises(FileExistsError):
            self.run_phase("merge")
        self.assertEqual(len(self.events_named("owner-wait")), 1)

    def test_authentic_old_checkpoint_cannot_replay_prepare_merge_or_observe(self):
        self.run_phase("prepare")
        old_checkpoint = (self.private / "coordinator-prepared.json").read_bytes()
        with self.assertRaises(coordinator.Stopped):
            self.run_phase("prepare")
        self.run_phase("merge")
        (self.private / "coordinator-prepared.json").write_bytes(old_checkpoint)
        with self.assertRaises(FileExistsError):
            self.run_phase("merge")
        self.run_phase("observe")
        with self.assertRaises(FileExistsError):
            self.run_phase("observe")
        self.assertEqual(len(self.events_named("execute")), 1)
        self.assertEqual(len(self.events_named("observe")), 1)

    def test_wrong_manifest_context_phase_and_modified_relay_state_stop_before_execute(self):
        cases = ("manifest", "context", "phase", "relay", "wait_plan")
        for case in cases:
            with self.subTest(case=case):
                if self.private.exists():
                    # A separate fixture filesystem keeps each case independent.
                    shutil.rmtree(self.private)
                self.events.clear()
                self.run_phase("prepare")
                if case == "manifest":
                    self.rewrite("prepared-state.json", lambda value: value["proposal"].update(unreviewed=True))
                elif case == "context":
                    self.rewrite("coordinator-prepared.json", lambda value: value["context"].update(source="0" * 40))
                elif case == "phase":
                    self.rewrite("coordinator-prepared.json", lambda value: value.update(phase="merge"))
                elif case == "relay":
                    self.rewrite("coordinator-prepared.json", lambda value: value["relay"]["payload"].update(reads=0))
                else:
                    self.rewrite("coordinator-prepared.json", lambda value: value["wait_plan"].update(
                        submit_by="2026-11-02T12:09:00.000000Z"))
                with self.assertRaises(coordinator.Stopped):
                    self.run_phase("merge")
                self.assertEqual(self.events_named("execute"), [])
                self.assertEqual(self.events_named("owner-wait"), [])

    def test_nonapplied_outcome_never_observes_or_resends(self):
        self.run_phase("prepare")
        self.execution.merge_report["status"] = "uncertain"
        with self.assertRaisesRegex(coordinator.Stopped, "not_applied"):
            self.run_phase("merge")
        with self.assertRaises(FileExistsError):
            self.run_phase("merge")
        with self.assertRaises(FileNotFoundError):
            self.run_phase("observe")
        self.assertEqual(len(self.events_named("execute")), 1)
        self.assertEqual(self.events_named("offline-replay"), [])
        self.assertEqual(self.events_named("observer-draft"), [])
        self.assertEqual(self.events_named("observe"), [])

    def test_modified_applied_report_journal_or_observer_selection_cannot_observe(self):
        for case in ("report", "journal", "observer"):
            with self.subTest(case=case):
                if self.private.exists():
                    shutil.rmtree(self.private)
                self.events.clear()
                self.relays.receipts.clear()
                self.run_phase("prepare")
                self.run_phase("merge")
                if case == "report":
                    self.rewrite("merge-result.json", lambda value: value["receipt"].update(id="different-applied-receipt"))
                elif case == "journal":
                    self.rewrite("journal.json", lambda value: value.update(changed=True))
                else:
                    self.rewrite("observer-state.json", lambda value: value["selection"].update(challenge="9" * 64))
                with self.assertRaises(coordinator.Stopped):
                    self.run_phase("observe")
                self.assertEqual(len(self.events_named("owner-wait")), 1)
                self.assertEqual(self.events_named("observe"), [])

    def test_expired_proposal_stops_before_owner_reads_and_does_not_renew_upload_window(self):
        self.run_phase("prepare")
        issued = self.read("merge-approval-instructions.json")
        self.assertEqual(issued["proposal_issued_at"], "2026-11-02T12:00:00.000000Z")
        self.assertEqual(issued["expires_at"], "2026-11-02T12:08:00.000000Z")
        self.assertEqual(issued["verification_expires_at"], "2026-11-02T12:08:21.000000Z")
        self.now += dt.timedelta(seconds=481)
        with self.assertRaisesRegex(coordinator.Stopped, "deadline_expired"):
            self.run_phase("merge")
        self.assertEqual(self.events_named("owner-wait"), [])
        self.assertEqual(self.events_named("execute"), [])

    def test_artifact_upload_delay_reduces_remaining_wait_instead_of_extending_deadline(self):
        self.run_phase("prepare")
        published_plan = self.read("merge-approval-instructions.json")["wait_plan"]
        self.now += dt.timedelta(seconds=120)
        self.run_phase("merge")
        wait = self.events_named("owner-wait")[0]
        self.assertEqual(wait[2], published_plan)
        self.assertEqual(coordinator.date(wait[2]["submit_by"]), NOW + dt.timedelta(seconds=480))
        self.assertEqual((coordinator.date(wait[2]["submit_by"]) - self.now).total_seconds(), 360)
        self.assertEqual(coordinator.date(wait[2]["verify_by"]), NOW + dt.timedelta(seconds=501))
        observer = self.read("observer-approval-instructions.json")
        self.assertEqual(coordinator.date(observer["expires_at"]), self.now + dt.timedelta(seconds=480))
        self.assertEqual(coordinator.date(observer["verification_expires_at"]), self.now + dt.timedelta(seconds=501))
        self.assertEqual(len(self.events_named("owner-plan")), 2)

    def test_grant_expiry_caps_proposal_and_already_expired_grant_cannot_wait(self):
        self.packets.lease_seconds = 50
        self.run_phase("prepare")
        proposal = self.read("merge-approval-instructions.json")
        self.assertEqual(proposal["expires_at"], "2026-11-02T12:00:20.000000Z")
        self.assertEqual(proposal["verification_expires_at"], "2026-11-02T12:00:41.000000Z")
        self.now += dt.timedelta(seconds=51)
        with self.assertRaises(coordinator.Stopped):
            self.run_phase("merge")
        self.assertEqual(self.events_named("owner-wait"), [])

    def test_unusable_grant_stops_before_publishing_a_selection_plan(self):
        self.packets.lease_seconds = 30
        with self.assertRaisesRegex(coordinator.Stopped, "no_usable_selection_window"):
            self.run_phase("prepare")
        self.assertFalse((self.private / "merge-approval-instructions.json").exists())
        self.assertFalse((self.private / "coordinator-prepared.json").exists())
        self.assertEqual(self.events_named("owner-wait"), [])
        self.assertEqual(self.events_named("execute"), [])

    def test_replay_requires_passed_zero_network_and_unchanged_journal(self):
        for key, value in (("status", "failed"), ("network_syscalls", 1),
                           ("network_syscalls", False), ("journal_unchanged", False)):
            with self.subTest(key=key):
                if self.private.exists():
                    shutil.rmtree(self.private)
                self.events.clear()
                self.relays.receipts.clear()
                self.execution.replay_proof = {"status": "passed", "journal_unchanged": True, "network_syscalls": 0}
                self.execution.replay_proof[key] = value
                self.run_phase("prepare")
                with self.assertRaisesRegex(coordinator.Stopped, "replay_not_proved"):
                    self.run_phase("merge")
                self.assertEqual(self.events_named("observer-draft"), [])
                self.assertEqual(self.read("merge-result.json")["status"], "applied")
                self.assertEqual(coordinator.failure_report("merge", self.private)["native_effect"], "applied")

    def test_observer_requires_one_pass_zero_skips_one_call_and_unchanged_journal(self):
        for key, value in (("status", "failed"), ("tests_passed", 0), ("tests_skipped", 1),
                           ("observer_calls", 2), ("tests_passed", True), ("tests_skipped", False),
                           ("observer_calls", True), ("journal_unchanged", False)):
            with self.subTest(key=key):
                if self.private.exists():
                    shutil.rmtree(self.private)
                self.events.clear()
                self.relays.receipts.clear()
                self.execution.observer_proof = {"status": "passed", "tests_passed": 1, "tests_skipped": 0,
                                                 "observer_calls": 1, "journal_unchanged": True}
                self.execution.observer_proof[key] = value
                self.run_phase("prepare")
                self.run_phase("merge")
                with self.assertRaisesRegex(coordinator.Stopped, "observer_not_proved"):
                    self.run_phase("observe")
                self.assertFalse((self.private / "coordinator-observed.json").exists())
                self.assertEqual(len(self.events_named("observe")), 1)
                self.assertEqual(coordinator.failure_report("observe", self.private)["native_effect"], "applied")

    def test_private_storage_refuses_existing_insecure_symlink_or_secret_state(self):
        self.private.mkdir(mode=0o700)
        path = self.private / "checkpoint.json"
        with self.assertRaises(coordinator.Stopped):
            coordinator.create_private(path, {"leaked": APP_TOKEN}, (APP_TOKEN, RELAY_TOKEN))
        self.assertFalse(path.exists())
        coordinator.create_private(path, {"safe": True}, (APP_TOKEN, RELAY_TOKEN))
        with self.assertRaises(FileExistsError):
            coordinator.create_private(path, {"safe": False}, (APP_TOKEN, RELAY_TOKEN))
        path.chmod(0o644)
        with self.assertRaises(coordinator.Stopped):
            coordinator.read_private(path)
        link = self.private / "linked-checkpoint.json"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            coordinator.read_private(link)
        self.assertEqual(json.loads(path.read_bytes()), {"safe": True})

    def test_failure_during_native_attempt_reports_uncertainty_and_never_resends(self):
        self.run_phase("prepare")
        self.execution.execute_error = RuntimeError(SECRET_ERROR)
        with self.assertRaises(RuntimeError):
            self.run_phase("merge")
        self.assertEqual(coordinator.failure_report("merge", self.private)["native_effect"], "inspect_original_journal")
        with self.assertRaises(FileExistsError):
            self.run_phase("merge")
        self.assertEqual(len(self.events_named("execute")), 1)

    def test_observer_selection_failure_consumes_phase_and_retains_applied_effect(self):
        self.run_phase("prepare")
        self.run_phase("merge")
        self.relays.wait_error = RuntimeError("fixture-owner-did-not-select-observer")
        with self.assertRaises(RuntimeError):
            self.run_phase("observe")
        self.assertTrue((self.private / "observe-consumed.json").exists())
        self.assertEqual(self.events_named("observe"), [])
        self.assertEqual(coordinator.failure_report("observe", self.private)["native_effect"], "applied")
        self.relays.wait_error = None
        with self.assertRaises(FileExistsError):
            self.run_phase("observe")
        self.assertEqual(len(self.events_named("owner-wait")), 2)
        self.assertEqual(self.events_named("observe"), [])

    def test_lost_applied_report_requires_journal_inspection_and_cannot_resend(self):
        self.run_phase("prepare")
        self.packets.fail_write = "merge-result.json"
        with self.assertRaises(RuntimeError):
            self.run_phase("merge")
        self.assertTrue((self.private / "execution-attempt.json").exists())
        self.assertFalse((self.private / "merge-result.json").exists())
        self.assertEqual(coordinator.failure_report("merge", self.private)["native_effect"], "inspect_original_journal")
        self.packets.fail_write = None
        with self.assertRaises(FileExistsError):
            self.run_phase("merge")
        self.assertEqual(len(self.events_named("execute")), 1)
        self.assertEqual(self.events_named("offline-replay"), [])
        self.assertEqual(self.events_named("observer-draft"), [])

    def test_private_applied_execution_report_survives_public_report_write_failure(self):
        self.run_phase("prepare")
        actual_execute = self.execution.execute

        def retain_actual_report(*args, **kwargs):
            report = actual_execute(*args, **kwargs)
            coordinator.create_private(self.private / "execution-report.json", report, (APP_TOKEN, RELAY_TOKEN))
            return report

        self.packets.fail_write = "merge-result.json"
        with patch.object(self.execution, "execute", side_effect=retain_actual_report):
            with self.assertRaises(RuntimeError):
                self.run_phase("merge")
        self.assertFalse((self.private / "merge-result.json").exists())
        self.assertEqual(self.read("execution-report.json"), self.execution.merge_report)
        self.assertEqual(coordinator.failure_report("merge", self.private)["native_effect"], "applied")
        self.packets.fail_write = None
        with self.assertRaises(FileExistsError):
            self.run_phase("merge")
        self.assertEqual(len(self.events_named("execute")), 1)
        self.assertEqual(self.events_named("offline-replay"), [])

    def test_credential_roles_and_installation_cannot_be_substituted(self):
        with self.assertRaisesRegex(coordinator.Stopped, "credential_roles_collide"):
            self.run_phase("prepare", relay_token=APP_TOKEN)
        self.assertEqual(self.events, [])
        with patch.dict(os.environ, {"CANARY_INSTALLATION_ID": "123"}):
            with self.assertRaisesRegex(coordinator.Stopped, "wrong_installation"):
                self.run_phase("prepare")
        self.assertEqual(self.events_named("packet-prepare"), [])

    def test_exact_host_environment_source_and_private_runtime_path(self):
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_REPOSITORY": coordinator.REPOSITORY, "GITHUB_REPOSITORY_ID": "1442278205",
                       "GITHUB_REF": coordinator.REF, "GITHUB_JOB": "native-positive-trial",
                       "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTOR_ID": "1679024",
                       "GITHUB_WORKFLOW_REF": CONTEXT["workflow_ref"], "GITHUB_SHA": CONTEXT["source"],
                       "GITHUB_RUN_ID": "901"}
        completed = [subprocess.CompletedProcess([], 0, (CONTEXT["source"] + "\n").encode(), b""),
                     subprocess.CompletedProcess([], 0, b"", b"")]
        with patch.dict(os.environ, environment), patch.object(coordinator.subprocess, "run", side_effect=completed):
            self.assertEqual(coordinator.context(), CONTEXT)
        for key, value in (("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_ACTOR_ID", "1"),
                           ("GITHUB_REF", "refs/heads/main"), ("GITHUB_REPOSITORY_ID", "1")):
            with self.subTest(key=key), patch.dict(os.environ, {**environment, key: value}), \
                 patch.object(coordinator.subprocess, "run") as no_git:
                with self.assertRaises(coordinator.Stopped):
                    coordinator.context()
                no_git.assert_not_called()
        self.assertEqual(coordinator.private_path(self.private, CONTEXT), self.private)
        for wrong in (self.temp / "native-positive-901-2", self.temp / "arbitrary-runtime", Path("relative")):
            with self.assertRaises(coordinator.Stopped):
                coordinator.private_path(wrong, CONTEXT)

    def test_changed_checkout_is_rejected_before_loading_helpers(self):
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_REPOSITORY": coordinator.REPOSITORY, "GITHUB_REPOSITORY_ID": "1442278205",
                       "GITHUB_REF": coordinator.REF, "GITHUB_JOB": "native-positive-trial",
                       "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTOR_ID": "1679024",
                       "GITHUB_WORKFLOW_REF": CONTEXT["workflow_ref"], "GITHUB_SHA": CONTEXT["source"],
                       "GITHUB_RUN_ID": "901"}
        for head, status in (("a" * 40, b""), (CONTEXT["source"], b" M tools/native_positive_trial.py\n")):
            with self.subTest(head=head, status=status), patch.dict(os.environ, environment), \
                 patch.object(coordinator.subprocess, "run", side_effect=[
                     subprocess.CompletedProcess([], 0, (head + "\n").encode(), b""),
                     subprocess.CompletedProcess([], 0, status, b"")]):
                with self.assertRaisesRegex(coordinator.Stopped, "source_changed"):
                    coordinator.context()


if __name__ == "__main__":
    unittest.main()
