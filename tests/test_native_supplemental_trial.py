"""Supplemental capacity needs exact owner authority and complete cumulative history.

These tests use controlled GitHub responses. They grant no live allowance and do
not contact GitHub, initialize an operator journal, or mint an App credential.
"""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 11, 3, 14, tzinfo=dt.timezone.utc)
TOKEN = "controlled-supplemental-relay-credential-never-publish"
CONTEXT = {
    "repository": "whiteredhouse/exacly-delivery-acceptance",
    "repository_id": 1442278205,
    "source": "f" * 40,
    "run_id": 901,
    "run_attempt": 1,
    "workflow_ref": (
        "whiteredhouse/exacly-delivery-acceptance/.github/workflows/"
        "app-bootstrap.yml@refs/heads/codex/preflight-diagnostics"
    ),
    "ref": "refs/heads/codex/preflight-diagnostics",
    "job": "native-positive-trial",
}


def load(name):
    selected = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(module)
    return module


class Clock:
    def __init__(self):
        self.seconds = 0

    def now(self):
        return NOW + dt.timedelta(seconds=self.seconds)

    def mono(self):
        return float(self.seconds)

    def sleep(self, seconds):
        self.seconds += seconds


class Backend:
    """The real relay parser sees a complete fixed workflow, history and review."""

    def __init__(self, relay, protocol_module, protocol):
        self.relay = relay
        self.calls = []
        self.headers = {}
        self.raw = {}
        self.status = {}
        self.on_request = None
        repository = {"id": 1442278205, "full_name": CONTEXT["repository"]}
        owner = {"id": 1679024, "login": "p1c2u", "type": "User"}
        self.run = {
            "id": 901, "run_number": 12, "run_attempt": 1, "workflow_id": 403984410,
            "path": ".github/workflows/app-bootstrap.yml", "event": "workflow_dispatch",
            "head_branch": "codex/preflight-diagnostics", "head_sha": CONTEXT["source"],
            "display_title": "canary-bootstrap:native-positive-trial:pr-5",
            "status": "in_progress", "conclusion": None,
            "repository": repository, "head_repository": copy.deepcopy(repository),
            "actor": owner, "triggering_actor": copy.deepcopy(owner),
        }
        self.history = [self.run]
        for number, frozen in enumerate(protocol["spec"]["accounting"]["history_baseline"], start=1):
            old = copy.deepcopy(self.run)
            old.update(
                id=frozen["run_id"], run_number=number, run_attempt=frozen["run_attempt"],
                workflow_id=frozen["workflow_id"], head_sha=frozen["source"],
                display_title=frozen["title"], status=frozen["status"], conclusion=frozen["conclusion"],
            )
            self.history.append(old)
        self.predecessor = next(item for item in self.history if item["id"] == 41526436188)
        self.history_total = None
        self.comments = []
        self.jobs = {"total_count": 1, "jobs": [{
            "id": 88, "name": "native-positive-trial", "run_id": 901,
            "run_attempt": 1, "head_sha": CONTEXT["source"],
            "status": "in_progress", "conclusion": None,
        }]}
        self.approvals = [{
            "state": "approved",
            "comment": protocol_module.allowance_command(protocol, CONTEXT),
            "user": copy.deepcopy(owner),
            "environments": [{"id": 26032127012, "name": "canary-merger-diagnostic"}],
        }]

    def sender(self, method, url, headers, payload, timeout):
        assert method == "GET" and payload is None
        assert headers["Authorization"] == "Bearer " + TOKEN and 0 < timeout <= 10
        self.calls.append(url)
        path = url.removeprefix(self.relay.API)
        if self.on_request:
            self.on_request(path)
        prefix = self.relay.PREFIX
        if path == prefix + "/actions/workflows/app-bootstrap.yml":
            value = {"id": 403984410, "path": ".github/workflows/app-bootstrap.yml", "state": "active"}
        elif path == prefix + "/actions/runs/901":
            value = self.run
        elif path.startswith(prefix + "/actions/workflows/403984410/runs?"):
            page = int(path.rsplit("=", 1)[1])
            value = {"total_count": len(self.history) if self.history_total is None else self.history_total,
                     "workflow_runs": self.history[(page - 1) * 100:page * 100]}
        elif path == prefix + "/actions/runs/901/attempts/1/jobs?per_page=100":
            value = self.jobs
        elif path == prefix + "/actions/runs/901/approvals":
            value = self.approvals
        elif path == prefix + "/issues/5/comments?per_page=100":
            value = self.comments
        elif path.startswith(prefix + "/issues/comments/"):
            value = next(item for item in self.comments if item["id"] == int(path.rsplit("/", 1)[1]))
        else:
            raise AssertionError("relay escaped its fixed supplemental read scope")
        return self.status.get(path, 200), self.raw.get(path, json.dumps(value).encode()), self.headers.get(path, {})


class SupplementalProtocolTests(unittest.TestCase):
    def setUp(self):
        self.module = load("native_trial_protocol")
        self.protocol = self.module.load(ROOT)

    def test_original_goal_and_full_spent_allocation_are_preserved(self):
        original = json.loads((ROOT / "config/native-positive-trial.json").read_text())
        spec = self.protocol["spec"]
        accounting = spec["accounting"]
        self.assertEqual(spec["objective"], original["objective"])
        self.assertEqual(spec["operation_key"], original["operation_key"])
        self.assertEqual(accounting["charged_prior_limits"], original["limits"])
        self.assertEqual(accounting["additional_limits"], original["limits"])
        self.assertEqual(accounting["aggregate_limits"], {
            "operations": 2, "wall_time_ms": 720000, "reads": 384, "rollbacks": 0,
        })
        self.assertEqual(accounting["predecessor"]["run_id"], 41526436188)
        self.assertEqual(accounting["predecessor"]["journal_id"], "8e89b70f6dfe4afbb7ee4829cbbab208")

    def test_allowance_command_explicitly_selects_one_extra_operation_and_actual_run(self):
        command = self.module.allowance_command(self.protocol, CONTEXT)
        self.assertIn("additional_operations=1", command)
        self.assertIn("aggregate_operations=2", command)
        self.assertIn(CONTEXT["source"], command)
        self.assertIn("41526436188", command)
        self.assertIn(self.protocol["profile"]["accounting_digest"], command)
        self.assertNotIn("\n", command)
        for changed in ({"run_id": 902}, {"source": "a" * 40}):
            self.assertNotEqual(command, self.module.allowance_command(self.protocol, {**CONTEXT, **changed}))

    def test_changed_fixed_manifest_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="supplement-manifest-") as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            value = copy.deepcopy(self.protocol["spec"])
            value["accounting"]["charged_prior_limits"]["operations"] = 0
            (root / "config/native-supplemental-trial.json").write_text(json.dumps(value))
            with self.assertRaises(Exception):
                self.module.load(root)


class SupplementalRelayTests(unittest.TestCase):
    def setUp(self):
        self.module = load("native_trial_protocol")
        self.protocol = self.module.load(ROOT)
        self.relay = load("native_trial_relay")
        self.timer = Clock()
        self.backend = Backend(self.relay, self.module, self.protocol)
        self.client = self.make_client()

    def make_client(self):
        return self.relay.Relay(
            TOKEN, CONTEXT, protocol=self.protocol, sender=self.backend.sender,
            clock=self.timer.now, monotonic=self.timer.mono, sleep=self.timer.sleep,
        )

    def approve(self):
        self.client.check_host()
        return self.client.check_supplemental_allowance()

    def test_exact_predecessor_and_owner_environment_comment_authorize_only_allocation(self):
        receipt = self.approve()
        self.assertEqual(receipt["status"], "approved")
        self.assertEqual(receipt["context"], CONTEXT)
        self.assertEqual(receipt["reviewer_id"], 1679024)
        self.assertEqual(receipt["environment_id"], 26032127012)
        self.assertEqual(receipt["accounting"], self.protocol["spec"]["accounting"])
        self.assertEqual(receipt["accounting_digest"], self.protocol["profile"]["accounting_digest"])
        self.assertEqual(receipt["command"], self.module.allowance_command(self.protocol, CONTEXT))
        self.assertEqual(receipt["command_digest"], "sha256:" + hashlib.sha256(receipt["command"].encode()).hexdigest())
        self.assertEqual(self.module.validate_allocation(
            receipt, profile=self.protocol["profile"], spec=self.protocol["spec"], context=CONTEXT), receipt)
        self.assertNotIn(TOKEN, json.dumps(receipt))
        self.assertTrue(self.backend.calls[-1].endswith("/actions/runs/901/approvals"))

    def test_plain_environment_approval_does_not_grant_supplemental_capacity(self):
        for comment in (None, "", "approved"):
            with self.subTest(comment=comment):
                self.setUp()
                self.backend.approvals[0]["comment"] = comment
                self.client.check_host()
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_supplemental_allowance()

    def test_only_surrounding_ascii_whitespace_is_ignored_in_owner_comment(self):
        canonical = self.backend.approvals[0]["comment"]
        self.backend.approvals[0]["comment"] = " \t\r\n" + canonical + "\n\r\t "
        receipt = self.approve()
        self.assertEqual(receipt["command"], canonical)
        self.assertEqual(receipt["command_digest"], "sha256:" + hashlib.sha256(canonical.encode()).hexdigest())

    def test_extra_text_second_command_and_interior_whitespace_never_change_selected_scope(self):
        original = self.backend.approvals[0]["comment"]
        for text in (original + "\nI also authorize another operation", original + "\n" + original,
                     original.replace("source=", " source="), "\u00a0" + original):
            with self.subTest(comment_digest=hashlib.sha256(text.encode()).hexdigest()):
                self.setUp()
                self.backend.approvals[0]["comment"] = text
                self.client.check_host()
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_supplemental_allowance()

    def test_wrong_owner_environment_state_or_duplicate_approval_is_refused(self):
        mutations = (
            lambda a: a[0].update(state="rejected"),
            lambda a: a[0]["user"].update(id=1),
            lambda a: a[0]["user"].update(type="Bot"),
            lambda a: a[0]["environments"][0].update(id=1),
            lambda a: a[0]["environments"].append({"id": 2, "name": "other"}),
            lambda a: a.append(copy.deepcopy(a[0])),
            lambda a: a.clear(),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.setUp()
                mutate(self.backend.approvals)
                self.client.check_host()
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_supplemental_allowance()

    def test_approval_for_different_run_source_or_budget_is_refused(self):
        original = self.backend.approvals[0]["comment"]
        commands = [
            self.module.allowance_command(self.protocol, {**CONTEXT, "run_id": 902}),
            self.module.allowance_command(self.protocol, {**CONTEXT, "source": "a" * 40}),
            original.replace("additional_operations=1", "additional_operations=2"),
            original.replace("aggregate_operations=2", "aggregate_operations=3"),
            original.replace("41526436188", "41526436189"),
        ]
        for command in commands:
            with self.subTest(command_digest=hashlib.sha256(command.encode()).hexdigest()):
                self.setUp()
                self.backend.approvals[0]["comment"] = command
                self.client.check_host()
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_supplemental_allowance()

    def test_missing_or_altered_consumed_predecessor_is_never_refunded(self):
        mutations = (
            lambda b: b.history.remove(b.predecessor),
            lambda b: b.predecessor.update(head_sha="a" * 40),
            lambda b: b.predecessor.update(run_attempt=2),
            lambda b: b.predecessor.update(conclusion="cancelled"),
            lambda b: b.predecessor.update(status="in_progress", conclusion=None),
            lambda b: b.predecessor.update(display_title="renamed-native-run"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.setUp()
                mutate(self.backend)
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_host()

    def test_any_third_native_attempt_blocks_even_cancelled_concurrent_or_renamed(self):
        changes = (
            {"status": "completed", "conclusion": "failure"},
            {"status": "completed", "conclusion": "cancelled"},
            {"status": "queued", "conclusion": None},
            {"status": "in_progress", "conclusion": None},
            {"head_sha": "a" * 40, "head_branch": "other-source"},
            {"run_attempt": 2},
            {"display_title": "canary-bootstrap:native-positive-successor:pr-5"},
        )
        for change in changes:
            with self.subTest(change=change):
                self.setUp()
                extra = copy.deepcopy(self.backend.run)
                extra.update(id=902, run_number=22, **change)
                self.backend.history.append(extra)
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_host()

    def test_deleted_prior_dispatch_cannot_hide_its_consumed_run_number(self):
        self.backend.run["run_number"] = 13
        with self.assertRaises(self.relay.RelayStopped):
            self.client.check_host()

    def test_incomplete_duplicate_or_changed_total_history_is_refused(self):
        for mode in ("partial", "duplicate", "bool"):
            with self.subTest(mode=mode):
                self.setUp()
                if mode == "partial":
                    self.backend.history_total = len(self.backend.history) + 1
                elif mode == "duplicate":
                    self.backend.history.append(copy.deepcopy(self.backend.predecessor))
                else:
                    self.backend.history_total = True
                with self.assertRaises(self.relay.RelayStopped):
                    self.client.check_host()

    def test_late_concurrent_dispatch_is_detected_before_effect_recheck(self):
        self.approve()
        extra = copy.deepcopy(self.backend.run)
        extra.update(id=902, run_number=22, status="queued")
        self.backend.history.append(extra)
        reads = self.client.reads
        with self.assertRaises(self.relay.RelayStopped):
            self.client.recheck_host()
        self.assertGreater(self.client.reads, reads)

    def test_export_restore_retains_allocation_clocks_and_total_read_count(self):
        receipt = self.approve()
        state = self.client.export_state()
        self.timer.seconds = 20
        restored = self.relay.Relay.restore(
            TOKEN, CONTEXT, state, protocol=self.protocol, sender=self.backend.sender,
            clock=self.timer.now, monotonic=self.timer.mono, sleep=self.timer.sleep,
        )
        self.assertEqual(restored.reads, self.client.reads)
        restored_state = restored.export_state()
        stable_before = {k: v for k, v in state["payload"].items() if k not in {"last_at", "last_monotonic"}}
        stable_after = {k: v for k, v in restored_state["payload"].items() if k not in {"last_at", "last_monotonic"}}
        self.assertEqual(stable_after, stable_before)
        self.assertEqual(restored_state["payload"]["last_monotonic"], 20)
        self.assertEqual(restored_state["payload"]["last_at"], "2026-11-03T14:00:20.000000Z")
        self.assertIn(receipt["accounting_digest"], json.dumps(state))
        restored.recheck_host()
        self.assertGreater(restored.reads, self.client.reads)
        self.assertNotIn(TOKEN, json.dumps(restored.export_state()))

    def test_checkpoint_tampering_or_legacy_restore_cannot_drop_consumption(self):
        self.approve()
        state = self.client.export_state()
        changed = copy.deepcopy(state)
        changed["payload"]["reads"] = 0
        with self.assertRaises(self.relay.RelayStopped):
            self.relay.Relay.restore(TOKEN, CONTEXT, changed, protocol=self.protocol)
        with self.assertRaises(self.relay.RelayStopped):
            self.relay.Relay.restore(TOKEN, CONTEXT, state)

    def test_altered_allocation_cannot_be_made_valid_by_rehashing_the_command(self):
        receipt = self.approve()
        changes = (
            lambda a: a["accounting"]["charged_prior_limits"].update(operations=0),
            lambda a: a["accounting"]["additional_limits"].update(operations=2),
            lambda a: a["context"].update(run_id=902),
            lambda a: a.update(reviewer_id=1),
            lambda a: a.update(environment_id=1),
            lambda a: a.update(status="proposed"),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(index=index):
                selected = copy.deepcopy(receipt)
                mutate(selected)
                selected["command_digest"] = "sha256:" + hashlib.sha256(selected["command"].encode()).hexdigest()
                with self.assertRaises(Exception):
                    self.module.validate_allocation(
                        selected, profile=self.protocol["profile"], spec=self.protocol["spec"], context=CONTEXT)

    def test_equal_boolean_or_float_budget_projection_cannot_claim_selected_digest(self):
        receipt = self.approve()
        for scope in ("charged_prior_limits", "additional_limits"):
            for value in (True, 1.0):
                with self.subTest(scope=scope, value_type=type(value).__name__):
                    selected = copy.deepcopy(receipt)
                    selected["accounting"][scope]["operations"] = value
                    # Python equality alone cannot distinguish these contents;
                    # the selected canonical accounting digest must still hold.
                    self.assertEqual(selected["accounting"], self.protocol["spec"]["accounting"])
                    with self.assertRaises(Exception):
                        self.module.validate_allocation(
                            selected, profile=self.protocol["profile"],
                            spec=self.protocol["spec"], context=CONTEXT)

    def test_allowance_endpoint_is_confined_to_current_run(self):
        self.client.check_host()
        before = len(self.backend.calls)
        with self.assertRaises(self.relay.RelayStopped):
            self.client._get(self.relay.PREFIX + "/actions/runs/902/approvals")
        self.assertEqual(len(self.backend.calls), before)


class SupplementalNativePacketTests(unittest.TestCase):
    def setUp(self):
        self.module = load("native_trial_protocol")
        self.protocol = self.module.load(ROOT)
        self.packets = load("native_trial_packets")
        temporary = tempfile.TemporaryDirectory(prefix="supplemental-packets-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.private = self.directory / "private"
        self.core = Path(os.environ.get(
            "EXACLY_NATIVE_SUPPLEMENTAL_TEST_CORE", ROOT.parent / "readiness-predicate-diagnostics"))

    def allocation(self):
        command = self.module.allowance_command(self.protocol, CONTEXT)
        return {
            "schema_version": "0.1.0", "kind": "owner-approved-supplemental-native-allocation",
            "status": "approved", "context": copy.deepcopy(CONTEXT),
            "accounting": copy.deepcopy(self.protocol["spec"]["accounting"]),
            "accounting_digest": self.protocol["profile"]["accounting_digest"],
            "reviewer_id": 1679024, "environment_id": 26032127012,
            "command": command, "command_digest": "sha256:" + hashlib.sha256(command.encode()).hexdigest(),
            "observed_at": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        }

    def prepare(self, *, allocation, profile=None):
        return self.packets.prepare(
            self.private, copy.deepcopy(self.protocol["spec"]), copy.deepcopy(CONTEXT),
            self.core, "controlled-supplemental-app-token-never-publish", 177653055,
            now=NOW, profile=self.protocol["profile"] if profile is None else profile, allocation=allocation,
        )

    def test_missing_or_altered_allocation_precedes_native_import_key_and_journal(self):
        original = self.allocation()
        changed = []
        for field, value in (("reviewer_id", 1), ("status", "proposed"),
                             ("accounting_digest", "sha256:" + "0" * 64)):
            selected = copy.deepcopy(original)
            selected[field] = value
            changed.append(selected)
        selected = copy.deepcopy(original)
        selected["accounting"]["charged_prior_limits"]["operations"] = 0
        changed.append(selected)
        selected = copy.deepcopy(original)
        selected["context"]["run_id"] = 902
        changed.append(selected)
        for index, allocation in enumerate([None, *changed]):
            with self.subTest(index=index), patch.object(self.packets, "_load_native") as native:
                with patch.object(self.packets, "_make_private") as private:
                    with self.assertRaises(Exception):
                        self.prepare(allocation=allocation)
                native.assert_not_called()
                private.assert_not_called()
                self.assertFalse(self.private.exists())

    def test_changed_explicit_runtime_profile_cannot_authorize_another_source(self):
        for field, value in (("core_revision", "0" * 40), ("spec_digest", "sha256:" + "0" * 64),
                             ("accounting_digest", "sha256:" + "0" * 64)):
            with self.subTest(field=field), patch.object(self.packets, "_load_native") as native:
                changed = {**self.protocol["profile"], field: value}
                with self.assertRaises(Exception):
                    self.prepare(allocation=self.allocation(), profile=changed)
                native.assert_not_called()
                self.assertFalse(self.private.exists())

    def test_actual_fixed_runtime_and_controlled_provider_keep_original_goal_and_receipt_binding(self):
        if not self.core.is_dir():
            self.fail("set EXACLY_NATIVE_SUPPLEMENTAL_TEST_CORE to the exact fixed runtime checkout")
        # Reuse the full legacy local-storage/controlled-provider integration and
        # select its explicit supplemental branch with this immutable manifest.
        from test_native_trial_packets import NATIVE_INTEGRATION

        runtime_names = {
            "PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy",
            "https_proxy", "all_proxy", "no_proxy",
        }
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", NATIVE_INTEGRATION,
             str(ROOT / "tools/native_trial_packets.py"), str(self.core),
             str(ROOT / "config/native-supplemental-trial.json"), str(self.private)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=180, check=False, env={key: value for key, value in os.environ.items() if key in runtime_names},
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout), {
            "prepared": True, "controlled_native_reads": 58, "controlled_native_writes": 2,
            "observer_bound": True, "same_job_restore": True, "socket_attempts": 0,
        })


class SupplementalCoordinatorTests(unittest.TestCase):
    """Real protocol/relay/checkpoints with controlled packet and effect boundaries."""

    def setUp(self):
        import test_native_positive_trial as legacy

        self.legacy = legacy
        self.coordinator = load("native_positive_trial")
        self.module = load("native_trial_protocol")
        self.protocol = self.module.load(ROOT)
        self.actual_relay = load("native_trial_relay")
        self.timer = Clock()
        self.backend = Backend(self.actual_relay, self.module, self.protocol)
        temporary = tempfile.TemporaryDirectory(prefix="supplemental-coordinator-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.private = self.directory / "native-positive-901-1"
        self.control = self.private.with_name(self.private.name + "-allocation")
        self.core = self.directory / "controlled-core"
        self.core.mkdir()
        self.events = []
        self.receipts = []
        self.output = io.StringIO()
        outer = self

        class Client(self.actual_relay.Relay):
            def __init__(self, token, context, **options):
                options.update(sender=outer.backend.sender, clock=outer.timer.now,
                               monotonic=outer.timer.mono, sleep=outer.timer.sleep)
                super().__init__(token, context, **options)

            def wait(self, selected, *, plan=None, expires_at=None):
                outer.events.append(("owner-wait", selected["phase"]))
                result = super().wait(selected, plan=plan, expires_at=expires_at)
                outer.receipts.append(result)
                return result

        self.relays = SimpleNamespace(
            Relay=Client, approval_command=self.actual_relay.approval_command,
            deny_command=self.actual_relay.deny_command, receipts=self.receipts,
        )
        self.packets = legacy.Packets(self.events)
        prepare = self.packets.prepare
        restore = self.packets.restore
        build_observer = self.packets.build_observer

        def selected_prepare(*args, profile=None, allocation=None, **options):
            self.assertEqual(profile, self.protocol["profile"])
            self.module.validate_allocation(
                allocation, profile=profile, spec=self.protocol["spec"], context=CONTEXT)
            self.assertFalse(self.private.exists())
            self.assertTrue((self.control / "allocation-consumed.json").is_file())
            self.events.append(("allocation-before-private-material",))
            result = prepare(*args, **options)
            result["runtime_profile"] = copy.deepcopy(profile)
            result["supplemental_allocation"] = copy.deepcopy(allocation)
            result["proposal"].update(runtime_profile=copy.deepcopy(profile),
                                      supplemental_allocation=copy.deepcopy(allocation))
            return result

        def selected_restore(*args, profile=None):
            self.assertEqual(profile, self.protocol["profile"])
            return restore(*args)

        def selected_observer(*args, profile=None, **options):
            self.assertEqual(profile, self.protocol["profile"])
            return build_observer(*args, **options)

        self.packets.prepare = selected_prepare
        self.packets.restore = selected_restore
        self.packets.build_observer = selected_observer
        self.execution = legacy.Execution(self.events, self.relays)
        for method in ("execute", "offline_replay", "observe"):
            selected = getattr(self.execution, method)

            def call(*args, profile=None, _selected=selected, **options):
                self.assertEqual(profile, self.protocol["profile"])
                return _selected(*args, **options)

            setattr(self.execution, method, call)
        environment = {
            "CANARY_INSTALLATION_ID": "177653055", "RUNNER_TEMP": str(self.directory),
            "CANARY_APP_TOKEN": legacy.APP_TOKEN, "CANARY_RELAY_TOKEN": TOKEN,
        }
        patcher = patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def phase(self, phase):
        with redirect_stdout(io.StringIO()):
            return self.coordinator.run(
                phase, self.private, self.core, packets=self.packets, relays=self.relays,
                execution=self.execution, ctx=CONTEXT,
                app_token="" if phase == "authorize" else self.legacy.APP_TOKEN,
                relay_token=TOKEN, now=self.timer.now, protocol=self.protocol,
            )

    def main_phase(self, phase, *, helper_error=None):
        modules = {
            "native_trial_protocol": self.module, "native_trial_packets": self.packets,
            "native_trial_relay": self.relays, "native_trial_execution": self.execution,
        }
        argv = ["native_positive_trial.py", phase, "--private", str(self.private), "--core-source", str(self.core)]
        actual_run = self.coordinator.run

        def fixed_clock_run(*args, **options):
            options["now"] = self.timer.now
            return actual_run(*args, **options)

        def selected_helper(name):
            if name == helper_error:
                raise RuntimeError(self.legacy.SECRET_ERROR + self.legacy.APP_TOKEN + TOKEN)
            return modules[name]

        with patch.object(sys, "argv", argv), patch.object(self.coordinator, "context", return_value=CONTEXT), \
             patch.object(self.coordinator, "load_helper", side_effect=selected_helper), \
             patch.object(self.coordinator, "run", side_effect=fixed_clock_run), redirect_stdout(self.output):
            return self.coordinator.main()

    def comment(self, selected, identifier):
        body = self.actual_relay.approval_command(selected)
        timestamp = self.timer.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.backend.comments = [{
            "id": identifier, "body": body, "created_at": timestamp, "updated_at": timestamp,
            "user": {"id": 1679024, "login": "p1c2u", "type": "User"},
            "url": self.actual_relay.API + self.actual_relay.PREFIX + "/issues/comments/" + str(identifier),
            "html_url": "https://github.com/" + CONTEXT["repository"] + "/pull/5#issuecomment-" + str(identifier),
            "issue_url": self.actual_relay.API + self.actual_relay.PREFIX + "/issues/5",
        }]

    def test_authorize_has_no_app_credential_or_operator_material(self):
        result = self.phase("authorize")
        self.assertEqual(result["status"], "supplemental_allocation_approved")
        self.assertFalse(self.private.exists())
        self.assertEqual({p.name for p in self.control.iterdir()}, {"allocation.json", "allocation-checkpoint.json"})
        self.assertEqual(self.events, [])
        reads = len(self.backend.calls)
        with self.assertRaises(Exception):
            self.phase("authorize")
        self.assertEqual(len(self.backend.calls), reads)
        self.assertFalse(self.private.exists())

    def test_absent_allowance_comment_stops_before_app_mint_or_journal_creation(self):
        self.backend.approvals[0]["comment"] = ""
        with self.assertRaises(Exception):
            self.phase("authorize")
        self.assertFalse(self.private.exists())
        self.assertFalse(self.control.exists())
        self.assertEqual(self.events, [])

    def test_prepare_cannot_skip_authorize_or_replay_consumed_allocation(self):
        with self.assertRaises(Exception):
            self.phase("prepare")
        self.assertFalse(self.private.exists())
        self.phase("authorize")
        self.assertEqual(self.phase("prepare")["status"], "proposed")
        original = (self.private / "journal.json").read_bytes()
        with self.assertRaises(Exception):
            self.phase("prepare")
        self.assertEqual((self.private / "journal.json").read_bytes(), original)
        self.assertEqual(sum(e[0] == "packet-prepare" for e in self.events), 1)

    def test_changed_private_allocation_checkpoint_cannot_initialize_operator(self):
        self.phase("authorize")
        path = self.control / "allocation.json"
        allocation = self.coordinator.read_private(path)
        allocation["accounting"]["charged_prior_limits"]["operations"] = 0
        path.write_bytes(self.coordinator.canonical(allocation))
        with self.assertRaises(Exception):
            self.phase("prepare")
        self.assertFalse(self.private.exists())
        self.assertEqual(self.events, [])

    def test_four_phase_flow_binds_allocation_and_separate_owner_selections(self):
        self.phase("authorize")
        self.phase("prepare")
        selected = self.packets.prepared["selection"]
        self.comment(selected, 71)
        result = self.phase("merge")
        self.assertEqual(result["status"], "applied_and_replayed")
        observer = self.coordinator.read_private(self.private / "observer-state.json")
        self.comment(observer["selection"], 72)
        result = self.phase("observe")
        self.assertEqual(result["status"], "positive_trial_completed")
        self.assertFalse(result["runner_loss_recovery_verified"])
        self.assertEqual([e[0] for e in self.events if e[0] in {"execute", "offline-replay", "observe"}],
                         ["execute", "offline-replay", "observe"])
        self.assertEqual([r["selection"]["phase"] for r in self.receipts], ["merge", "observe"])

    def test_concurrent_dispatch_after_owner_selection_stops_before_actual_effect(self):
        self.phase("authorize")
        self.phase("prepare")
        self.comment(self.packets.prepared["selection"], 71)
        original = (self.private / "journal.json").read_bytes()

        def dispatch(path):
            if path.endswith("/issues/comments/71"):
                extra = copy.deepcopy(self.backend.run)
                extra.update(id=902, run_number=13, status="queued")
                self.backend.history.append(extra)

        self.backend.on_request = dispatch
        with self.assertRaises(Exception):
            self.phase("merge")
        self.assertFalse(any(e[0] == "execute" for e in self.events))
        self.assertEqual((self.private / "journal.json").read_bytes(), original)
        with self.assertRaises(Exception):
            self.phase("merge")
        self.assertFalse(any(e[0] == "execute" for e in self.events))

    def test_cli_failure_after_applied_preserves_known_effect_and_hides_exception_details(self):
        # main() selects the real fixed supplemental protocol. The replay error
        # must occur after the controlled effect, not during helper loading.
        self.phase("authorize")
        self.phase("prepare")
        self.comment(self.packets.prepared["selection"], 71)
        self.execution.replay_error = RuntimeError(self.legacy.SECRET_ERROR + self.legacy.APP_TOKEN + TOKEN)
        self.assertEqual(self.main_phase("merge"), 1)
        report = self.coordinator.read_private(self.private / "trial-report.json")
        self.assertEqual(report["native_effect"], "applied")
        self.assertFalse(report["resend_allowed"])
        self.assertEqual(self.coordinator.read_private(self.private / "merge-result.json"), self.execution.merge_report)
        self.assertEqual([e[0] for e in self.events if e[0] in {"execute", "offline-replay", "observe"}],
                         ["execute", "offline-replay"])
        serialized = self.output.getvalue() + json.dumps(report)
        for secret in (self.legacy.APP_TOKEN, TOKEN, self.legacy.SECRET_ERROR):
            self.assertNotIn(secret, serialized)

    def test_preparation_failure_is_redacted_and_never_claims_a_native_attempt(self):
        self.phase("authorize")
        with patch.object(self.packets, "prepare", side_effect=RuntimeError(self.legacy.SECRET_ERROR + TOKEN)) as prepare:
            self.assertEqual(self.main_phase("prepare"), 1)
        prepare.assert_called_once()
        self.assertEqual(prepare.call_args.kwargs["profile"], self.protocol["profile"])
        result = json.loads(self.output.getvalue().splitlines()[-1])
        self.assertEqual(result["native_effect"], "not_attempted")
        self.assertFalse(result["resend_allowed"])
        self.assertFalse(self.private.exists())
        self.assertTrue((self.control / "allocation-consumed.json").is_file())
        self.assertFalse(any(e[0] == "execute" for e in self.events))
        for secret in (self.legacy.APP_TOKEN, TOKEN, self.legacy.SECRET_ERROR):
            self.assertNotIn(secret, self.output.getvalue())

    def test_already_applied_effect_is_retained_when_protocol_loading_fails(self):
        self.phase("authorize")
        self.phase("prepare")
        self.comment(self.packets.prepared["selection"], 71)
        self.assertEqual(self.phase("merge")["status"], "applied_and_replayed")
        original = (self.private / "merge-result.json").read_bytes()
        before = [e[0] for e in self.events]
        self.assertEqual(self.main_phase("observe", helper_error="native_trial_protocol"), 1)
        report = self.coordinator.read_private(self.private / "trial-report.json")
        self.assertEqual(report["native_effect"], "applied")
        self.assertFalse(report["resend_allowed"])
        self.assertEqual((self.private / "merge-result.json").read_bytes(), original)
        self.assertEqual([e[0] for e in self.events], before)
        self.assertFalse((self.private / "observer-approval-receipt.json").exists())
        serialized = self.output.getvalue() + json.dumps(report)
        for secret in (self.legacy.APP_TOKEN, TOKEN, self.legacy.SECRET_ERROR):
            self.assertNotIn(secret, serialized)

    def test_workflow_verifies_explicit_allocation_before_official_mint(self):
        import yaml

        job = yaml.safe_load((ROOT / ".github/workflows/app-bootstrap.yml").read_text())["jobs"]["native-positive-trial"]
        steps = job["steps"]
        authorize = next(i for i, step in enumerate(steps) if "native_positive_trial.py authorize" in step.get("run", ""))
        mint = next(i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/create-github-app-token@"))
        prepare = next(i for i, step in enumerate(steps) if "native_positive_trial.py prepare" in step.get("run", ""))
        self.assertLess(authorize, mint)
        self.assertLess(mint, prepare)
        self.assertNotIn("CANARY_APP_TOKEN", steps[authorize].get("env", {}))
        self.assertEqual(job["environment"]["name"], "canary-merger-diagnostic")


if __name__ == "__main__":
    unittest.main()
