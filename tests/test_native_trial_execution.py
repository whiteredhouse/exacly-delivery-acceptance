"""Offline wrapper contracts; fake children never contact GitHub or mint tokens."""

import copy
from contextlib import contextmanager
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "native_trial_execution", ROOT / "tools/native_trial_execution.py"
)
execution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(execution)
SECRET = "fixture-native-token-must-remain-private"


def encoded(value):
    return execution.canonical(value)


def put(path, value):
    path.write_bytes(value if isinstance(value, bytes) else encoded(value))
    path.chmod(0o600)


class NativeExecutionFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="native-execution-tests-")
        self.root = Path(self.tmp.name) / "private"
        self.root.mkdir(mode=0o700)
        self.core = Path(self.tmp.name) / "core"
        package = self.core / "python/src/exacly"
        package.mkdir(parents=True)
        pins = {}
        for name in ("automatic_merge.py", "github_merge.py"):
            content = ("# controlled source fixture " + name + "\n").encode()
            (package / name).write_bytes(content)
            pins[name] = hashlib.sha256(content).hexdigest()
        bound = self.core / "python/tests/test_automatic_merge_live.py"
        bound.parent.mkdir(parents=True)
        bound.write_bytes(b"# controlled bound test fixture\n")
        source_pins = patch.object(execution, "PINS", pins)
        bound_pin = patch.object(
            execution,
            "BOUND_TEST_DIGEST",
            hashlib.sha256(bound.read_bytes()).hexdigest(),
        )
        source_pins.start()
        bound_pin.start()
        self.addCleanup(source_pins.stop)
        self.addCleanup(bound_pin.stop)
        self.paths = {
            name: str(self.root / (name + ".json"))
            for name in (
                "journal",
                "key",
                "config",
                "policy",
                "request",
                "payload",
                "approval",
                "identity",
                "mint",
                "objective",
                "limits",
                "native_limits",
                "proposal",
            )
        }
        put(Path(self.paths["journal"]), b"actual-fixture-journal-bytes")
        put(Path(self.paths["key"]), b"actual-fixture-key-bytes")
        now = dt.datetime.now(dt.UTC)
        timestamp = lambda value: value.isoformat().replace("+00:00", "Z")
        approval = {
            "kind": "delivery-approval",
            "issuer": "p1c2u",
            "approval_id": "owner-merge",
            "not_before": timestamp(now - dt.timedelta(minutes=1)),
            "expires_at": timestamp(now + dt.timedelta(minutes=30)),
            "adapter": {"configuration_digest": "sha256:" + "d" * 64},
        }
        config = {
            "actor": {
                "token_digest": "sha256:" + hashlib.sha256(SECRET.encode()).hexdigest()
            },
            "key": {"path": self.paths["key"], "id": "k" * 32},
            "call_limits": {
                "reconcile": {
                    "write_calls": 0,
                    "read_calls": 64,
                    "wall_time_ms": 120000,
                }
            },
        }
        self.spec = {"fixed": "offline-fixture", "objective": {"id": "fixture-objective"},
                     "limits": {"reads": 192}}
        values = {
            "config": config,
            "policy": {"fixed": "policy"},
            "request": {"operation_key": "sha256:" + "a" * 64},
            "payload": {"fixed": "payload"},
            "approval": approval,
            "identity": {"fixed": "identity"},
            "mint": {"fixed": "attestation"},
            "objective": {"fixed": "objective"},
            "limits": {"reads": 192},
            "native_limits": {"read_calls": 64},
        }
        for name, value in values.items():
            put(Path(self.paths[name]), value)
        inventory = [
            {
                "path": path.relative_to(self.core).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted((self.core / "python/src/exacly").rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts
        ]
        info = Path(self.paths["journal"]).stat()
        key_info = Path(self.paths["key"]).stat()
        python = str(Path(sys.executable).absolute())
        proposal = {
            "configuration": config,
            "policy": values["policy"],
            "request": values["request"],
            "payload": values["payload"],
            "native_limits": values["native_limits"],
            "operation_approval": approval,
            "identity_decision": values["identity"],
            "mint_attestation": values["mint"],
            "context": {"run_id": 123, "run_attempt": 1},
            "spec_digest": execution.digest(self.spec),
            "storage": {
                "private_dir": str(self.root),
                "journal": {
                    "path": self.paths["journal"],
                    "id": "j" * 32,
                    "device": info.st_dev,
                    "inode": info.st_ino,
                },
                "key": {
                    **config["key"],
                    "device": key_info.st_dev,
                    "inode": key_info.st_ino,
                    "owner": key_info.st_uid,
                    "mode": 0o600,
                },
            },
            "core": {
                "revision": execution.CORE,
                "source": str(self.core),
                "python": python,
                "python_realpath": str(Path(python).resolve()),
                "python_sha256": hashlib.sha256(Path(python).read_bytes()).hexdigest(),
                "source_inventory_digest": execution.digest(inventory),
            },
            "documents": {
                name: {"path": self.paths[name], "digest": execution.digest(value)}
                for name, value in values.items()
            },
        }
        selection = {
            "phase": "merge",
            "run_id": 123,
            "run_attempt": 1,
            "challenge": "1" * 64,
            "packet_digest": execution.digest(proposal),
            "identity_digest": execution.digest(values["identity"]),
            "issuer": "p1c2u",
            "approval_id": "owner-merge",
            "approval_digest": execution.digest(approval),
        }
        put(Path(self.paths["proposal"]), proposal)
        self.prepared = {
            "private_dir": str(self.root),
            "proposal": proposal,
            "paths": self.paths,
            "selection": selection,
            "spec": self.spec,
            "core_source": str(self.core),
            "context": proposal["context"],
            "journal_id": "j" * 32,
            "python": python,
            "_token": SECRET,
        }
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def receipt(self, selection=None, comment=50):
        selection = selection or self.prepared["selection"]
        now = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "schema_version": "0.1.0",
            "kind": "fixed-pr-owner-selection",
            "selection": copy.deepcopy(selection),
            "repository_id": 1442278205,
            "pull_request": 5,
            "comment_id": comment,
            "owner_id": 1679024,
            "owner_login": "p1c2u",
            "created_at": now,
            "updated_at": now,
            "verified_at": now,
            "command_digest": "sha256:"
            + hashlib.sha256(execution._command(selection).encode("ascii")).hexdigest(),
        }

    def report(self, status="applied", historical=False):
        intent = {
            "request": self.prepared["proposal"]["request"],
            "kind": "fixture-intent",
        }
        intent["id"] = execution.digest(intent)
        receipt = {"kind": "fixture-receipt", "stage": "merge", "outcome": status}
        receipt["id"] = execution.digest(receipt)
        return {
            "schema_version": "0.1.0",
            "profile": "product-delivery-v1",
            "kind": "delivery-report",
            "status": status,
            "historical": historical,
            "live_checked": not historical,
            "journal": {
                "path": self.paths["journal"],
                "id": self.prepared["journal_id"],
            },
            "operation_key": self.prepared["proposal"]["request"]["operation_key"],
            "request_digest": execution.digest(self.prepared["proposal"]["request"]),
            "intent": intent,
            "receipt": receipt,
        }

    def run_fake(self, statuses=("applied",)):
        statuses = iter(statuses)

        def child(command, root, name, **kwargs):
            self.calls.append((command, name, kwargs))
            report = self.report(next(statuses))
            return (0 if report["status"] == "applied" else 1), encoded(report), b""

        with patch.object(execution, "_run", side_effect=child):
            return execution.execute(self.prepared, self.receipt(), token=SECRET)

    def save_applied(self):
        report = self.report()
        put(self.root / "execution-report.json", report)
        put(self.root / "execution-attempt.json", {"selection_receipt": self.receipt()})
        return report

    def observer(self):
        report = self.save_applied()
        approval = {"kind": "delivery-read-recovery", "fixed": "current-read-scope"}
        selection = {
            "phase": "observe",
            "run_id": 123,
            "run_attempt": 1,
            "challenge": "2" * 64,
            "packet_digest": "sha256:" + "0" * 64,
            "issuer": "p1c2u",
            "approval_id": "owner-observe",
            "approval_digest": execution.digest(approval),
        }
        packet = {
            "read_approval": approval,
            "read_approval_pin": {
                "issuer": "p1c2u",
                "approval_id": "owner-observe",
                "digest": execution.digest(approval),
            },
            "journal": report["journal"],
            "operation_key": report["operation_key"],
            "intent_id": report["intent"]["id"],
            "receipt_id": report["receipt"]["id"],
            "original_configuration": self.prepared["proposal"]["configuration"],
            "original_approval_pin": {
                "issuer": "p1c2u",
                "approval_id": "owner-merge",
                "digest": self.prepared["selection"]["approval_digest"],
            },
            "maximum_calls": 1,
            "limits": {"write_calls": 0, "read_calls": 64, "wall_time_ms": 120000},
            "output_bundle": str(self.root / "observer-bundle"),
            "observation_id": "b" * 32,
        }
        selection["packet_digest"] = execution.digest(packet)
        path = self.root / "observer-packet.json"
        put(path, packet)
        return {
            "selection": selection,
            "proposal": {"packet": packet},
            "paths": {"packet": str(path), "output_bundle": packet["output_bundle"]},
        }

    def fake_offline(
        self, *, network=False, mutate=False, fail=False, wrong_receipt=False
    ):
        report = self.report(historical=True)
        if wrong_receipt:
            report["receipt"]["id"] = "sha256:" + "f" * 64

        def child(command, root, name, **kwargs):
            self.calls.append((command, name, kwargs))
            self.assertNotIn(execution.TOKEN, kwargs["env"])
            if name == "socket-control":
                trace = Path(command[command.index("-o") + 1])
                put(trace, b"123 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n")
                return 0, b"", b""
            if name == "audit-control":
                put(
                    self.root / "audit-control.json",
                    {
                        "audit_hook_installed": True,
                        "network_events": 1,
                        "canonical_token_present": False,
                    },
                )
                return 0, b"", b""
            self.assertEqual(name, "offline")
            self.assertFalse(Path(self.paths["key"]).exists())
            if fail:
                raise execution.ExecutionStopped("native_trial_child_unresolved")
            put(
                self.root / "offline-audit.json",
                {
                    "audit_hook_installed": True,
                    "network_events": int(network),
                    "canonical_token_present": False,
                },
            )
            put(
                self.root / "offline.trace",
                b"" if not network else b"123 socket(AF_INET, SOCK_STREAM, 0) = 3\n",
            )
            if mutate:
                put(Path(self.paths["journal"]), b"changed-journal")
            return 0, encoded(report), b""

        return child

    def fake_observer(
        self, observer, *, skipped=False, bad_receipt=False, mutate=False, exit_code=0
    ):
        def child(command, root, name, **kwargs):
            self.calls.append((command, name, kwargs))
            self.assertEqual(name, "observer")
            self.assertIn(
                "test_live_github_exact_merge_with_original_authority_and_authenticated_marker",
                command[-2],
            )
            self.assertEqual(
                kwargs["env"]["EXACLY_DELIVERY_MERGE_LIVE_PROOF_DIGEST"],
                observer["selection"]["packet_digest"],
            )
            put(
                self.root / "observer-junit.xml",
                b'<testsuites><testsuite tests="1"><testcase name="bound">'
                + (b"<skipped/>" if skipped else b"")
                + b"</testcase></testsuite></testsuites>",
            )
            packet = observer["proposal"]["packet"]
            bundle = Path(packet["output_bundle"])
            bundle.mkdir(mode=0o700)
            result = {"outcome": "applied", "fixed": "actual-child-fixture"}
            receipt = {
                "schema_version": "0.1.0",
                "kind": "delivery-merge-live-observation-receipt",
                "source": "github-atomic-merge-default-https-v1",
                "accepted": not bad_receipt,
                "provider_writes": 0,
                "original_effect_budget_charged": False,
                "packet_digest": observer["selection"]["packet_digest"],
                "intent_id": packet["intent_id"],
                "original_receipt_id": packet["receipt_id"],
                "observation_id": packet["observation_id"],
                "limits": packet["limits"],
                "read_approval_digest": observer["selection"]["approval_digest"],
                "result_digest": execution.digest(result),
            }
            receipt["id"] = execution.digest(receipt)
            put(bundle / "receipt.json", receipt)
            put(bundle / "result.json", result)
            if mutate:
                put(Path(self.paths["journal"]), b"changed-observer-journal")
            return exit_code, b"1 passed", b""

        return child


class NativeExecutionTests(NativeExecutionFixture, unittest.TestCase):
    def test_exact_selected_invoke_uses_actual_public_cli_once(self):
        result = self.run_fake()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(len(self.calls), 1)
        command, name, kwargs = self.calls[0]
        self.assertEqual(name, "invoke")
        self.assertIn("--apply", command)
        self.assertEqual(
            command[command.index("--approved-approval-digest") + 1],
            self.prepared["selection"]["approval_digest"],
        )
        self.assertEqual(kwargs["env"][execution.TOKEN], SECRET)
        self.assertEqual(execution._json(self.root / "execution-report.json"), result)
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.execute(self.prepared, self.receipt(), token=SECRET)
        run.assert_not_called()

    def test_uncertain_can_only_reconcile_once_with_original_scope(self):
        result = self.run_fake(("uncertain", "applied"))
        self.assertEqual(result["status"], "applied")
        self.assertEqual([call[1] for call in self.calls], ["invoke", "reconcile"])
        self.assertNotIn("--apply", self.calls[1][0])
        self.assertIn("--operation-key", self.calls[1][0])
        self.assertEqual(
            execution._json(self.root / "invoke-report.json")["status"], "uncertain"
        )

    def test_rejected_does_not_reconcile_or_reinvoke(self):
        self.assertEqual(self.run_fake(("rejected",))["status"], "rejected")
        self.assertEqual(len(self.calls), 1)

    def test_unknown_child_outcome_cannot_be_reinvoked(self):
        with patch.object(execution, "_run", side_effect=RuntimeError(SECRET)) as run:
            with self.assertRaises(execution.ExecutionStopped) as raised:
                execution.execute(self.prepared, self.receipt(), token=SECRET)
            self.assertNotIn(SECRET, str(raised.exception))
            with self.assertRaises(execution.ExecutionStopped):
                execution.execute(self.prepared, self.receipt(), token=SECRET)
            self.assertEqual(run.call_count, 1)

    def test_reconcile_failure_keeps_original_uncertainty(self):
        calls = iter(
            [
                (1, encoded(self.report("uncertain")), b""),
                execution.ExecutionStopped("native_trial_child_unresolved"),
            ]
        )

        def child(*args, **kwargs):
            value = next(calls)
            if isinstance(value, Exception):
                raise value
            return value

        with patch.object(execution, "_run", side_effect=child) as run:
            report = execution.execute(self.prepared, self.receipt(), token=SECRET)
        self.assertEqual(report["status"], "uncertain")
        self.assertEqual(run.call_count, 2)
        self.assertFalse(
            execution._json(self.root / "reconcile-unresolved.json")["resend_allowed"]
        )

    def test_missing_or_altered_external_pin_stops_before_child(self):
        for field, value in (
            ("owner_id", 1),
            ("repository_id", 1),
            ("pull_request", 6),
            ("command_digest", "sha256:" + "0" * 64),
            ("updated_at", "2000-01-01T00:00:00Z"),
        ):
            with self.subTest(field=field):
                receipt = self.receipt()
                receipt[field] = value
                with (
                    patch.object(execution, "_run") as run,
                    self.assertRaises(execution.ExecutionStopped),
                ):
                    execution.execute(self.prepared, receipt, token=SECRET)
                run.assert_not_called()
        self.assertFalse((self.root / "execution-attempt.json").exists())

    def test_changed_document_and_replaced_journal_stop_before_child(self):
        original = Path(self.paths["request"]).read_bytes()
        put(Path(self.paths["request"]), {"operation_key": "sha256:" + "f" * 64})
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.execute(self.prepared, self.receipt(), token=SECRET)
        run.assert_not_called()
        put(Path(self.paths["request"]), original)
        prior = Path(self.paths["journal"])
        replacement = self.root / "replacement"
        put(replacement, prior.read_bytes())
        os.replace(replacement, prior)
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.execute(self.prepared, self.receipt(), token=SECRET)
        run.assert_not_called()

    def test_wrong_token_cannot_consume_invocation(self):
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.execute(
                self.prepared, self.receipt(), token="different-fixture-token"
            )
        run.assert_not_called()
        self.assertFalse((self.root / "execution-attempt.json").exists())

    def test_changed_native_source_or_bound_test_stops_before_child(self):
        bound = self.core / "python/tests/test_automatic_merge_live.py"
        bound.write_bytes(bound.read_bytes() + b"# changed\n")
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.execute(self.prepared, self.receipt(), token=SECRET)
        run.assert_not_called()

    def test_byte_identical_key_replacement_stops_before_child(self):
        key = Path(self.paths["key"])
        replacement = self.root / "replacement-key"
        put(replacement, key.read_bytes())
        os.replace(replacement, key)
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.execute(self.prepared, self.receipt(), token=SECRET)
        run.assert_not_called()

    def test_malformed_child_report_consumes_single_invocation_without_reconcile(self):
        with patch.object(execution, "_run", return_value=(0, b"{}", b"")) as run:
            with self.assertRaises(execution.ExecutionStopped):
                execution.execute(self.prepared, self.receipt(), token=SECRET)
            self.assertEqual(run.call_count, 1)
        self.assertTrue((self.root / "execution-attempt.json").exists())
        self.assertFalse((self.root / "reconcile-attempt.json").exists())

    def test_environment_excludes_other_credentials_and_user_code(self):
        values = {
            "GITHUB_TOKEN": SECRET,
            "GH_TOKEN": SECRET,
            "CANARY_APP_TOKEN": SECRET,
            "MERGER_PRIVATE_KEY": SECRET,
            "RELAY_TOKEN": SECRET,
            "PYTHONPATH": SECRET,
            "PYTEST_ADDOPTS": SECRET,
            "LD_PRELOAD": SECRET,
            "HTTPS_PROXY": "https://fixture-proxy.invalid",
            "SSL_CERT_FILE": "/fixture-ca",
        }
        with patch.dict(os.environ, values):
            env = execution._environment("canonical-fixture-token")
        for name in values.keys() - {"HTTPS_PROXY", "SSL_CERT_FILE"}:
            self.assertNotIn(name, env)
        self.assertEqual(env["HTTPS_PROXY"], values["HTTPS_PROXY"])
        self.assertEqual(env["SSL_CERT_FILE"], values["SSL_CERT_FILE"])
        self.assertEqual(env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"], "1")
        self.assertEqual(env[execution.TOKEN], "canonical-fixture-token")
        self.assertNotIn(execution.TOKEN, execution._environment())

    def test_real_private_child_capture_never_returns_token_output(self):
        command = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import os; print(os.environ['EXACLY_DELIVERY_MERGE_TOKEN'])",
        ]
        with self.assertRaises(execution.ExecutionStopped) as raised:
            execution._run(
                command,
                self.root,
                "unsafe-output",
                env=execution._environment(SECRET),
                timeout=5,
                token=SECRET,
            )
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertEqual(
            (self.root / "unsafe-output.stdout").stat().st_mode & 0o777, 0o600
        )

    def test_real_private_child_timeout_and_output_are_bounded(self):
        command = [sys.executable, "-I", "-B", "-c", "import time; time.sleep(5)"]
        with self.assertRaises(execution.ExecutionStopped):
            execution._run(
                command,
                self.root,
                "timeout",
                env=execution._environment(),
                timeout=0.05,
                token=SECRET,
            )
        command = [sys.executable, "-I", "-B", "-c", "import os; os.write(1,b'x'*4096)"]
        with (
            patch.object(execution, "MAX_OUTPUT", 1024),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution._run(
                command,
                self.root,
                "overflow",
                env=execution._environment(),
                timeout=5,
                token=SECRET,
            )
        self.assertLessEqual((self.root / "overflow.stdout").stat().st_size, 1024)

    def test_offline_replay_checks_real_receipt_key_inode_and_zero_network(self):
        applied = self.save_applied()
        inode = Path(self.paths["key"]).stat().st_ino
        with (
            patch.object(execution, "_run", side_effect=self.fake_offline()),
            patch.object(execution.shutil, "which", return_value="/usr/bin/strace"),
        ):
            proof = execution.offline_replay(self.prepared, applied, token=SECRET)
        self.assertEqual(proof["network_syscalls"], 0)
        self.assertEqual(Path(self.paths["key"]).stat().st_ino, inode)
        self.assertTrue(proof["strace_socket_control_detected"])
        self.assertEqual(
            [call[1] for call in self.calls],
            ["socket-control", "audit-control", "offline"],
        )

    def test_failed_offline_child_restores_original_key_inode(self):
        applied = self.save_applied()
        before = Path(self.paths["key"]).stat().st_ino
        with (
            patch.object(execution, "_run", side_effect=self.fake_offline(fail=True)),
            patch.object(execution.shutil, "which", return_value="/usr/bin/strace"),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.offline_replay(self.prepared, applied, token=SECRET)
        self.assertEqual(Path(self.paths["key"]).stat().st_ino, before)

    def test_offline_network_attempt_or_journal_change_is_not_a_pass(self):
        applied = self.save_applied()
        with (
            patch.object(
                execution, "_run", side_effect=self.fake_offline(network=True)
            ),
            patch.object(execution.shutil, "which", return_value="/usr/bin/strace"),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.offline_replay(self.prepared, applied, token=SECRET)
        self.assertFalse((self.root / "offline-proof.json").exists())

    def test_offline_no_receipt_substitution(self):
        applied = self.save_applied()
        with (
            patch.object(
                execution, "_run", side_effect=self.fake_offline(wrong_receipt=True)
            ),
            patch.object(execution.shutil, "which", return_value="/usr/bin/strace"),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.offline_replay(self.prepared, applied, token=SECRET)

    def test_offline_original_journal_bytes_must_remain_identical(self):
        applied = self.save_applied()
        with (
            patch.object(execution, "_run", side_effect=self.fake_offline(mutate=True)),
            patch.object(execution.shutil, "which", return_value="/usr/bin/strace"),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.offline_replay(self.prepared, applied, token=SECRET)
        self.assertFalse((self.root / "offline-proof.json").exists())

    def test_missing_tracer_cannot_be_replaced_by_a_simulated_proof(self):
        applied = self.save_applied()
        before = Path(self.paths["key"]).stat().st_ino
        with (
            patch.object(execution.shutil, "which", return_value=None),
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.offline_replay(self.prepared, applied, token=SECRET)
        run.assert_not_called()
        self.assertEqual(Path(self.paths["key"]).stat().st_ino, before)

    def test_real_strace_socket_control_and_python_audit_denial(self):
        tracer = shutil.which("strace", path=os.defpath)
        self.assertIsNotNone(
            tracer, "Reviewed test runtime must install strace before token minting"
        )
        trace = self.root / "real-control.trace"
        code, _, _ = execution._run(
            [
                tracer,
                "-f",
                "-qq",
                "-e",
                "trace=network",
                "-o",
                str(trace),
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import socket; s=socket.socket(); s.close()",
            ],
            self.root,
            "real-control",
            env=execution._environment(),
            timeout=10,
            token=SECRET,
        )
        self.assertEqual(code, 0)
        self.assertIn(b"socket(", trace.read_bytes())
        audit = self.root / "real-audit.json"
        code, _, _ = execution._run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                execution.BOOTSTRAP,
                "audit-control",
                str(audit),
            ],
            self.root,
            "real-audit",
            env=execution._environment(),
            timeout=10,
            token=SECRET,
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            execution._json(audit),
            {
                "audit_hook_installed": True,
                "network_events": 1,
                "canonical_token_present": False,
            },
        )

    def test_actual_bound_observer_is_run_once_with_no_skip_and_verified_receipt(self):
        observer = self.observer()
        receipt = self.receipt(observer["selection"], comment=51)
        with patch.object(execution, "_run", side_effect=self.fake_observer(observer)):
            proof = execution.observe(self.prepared, observer, receipt, token=SECRET)
        self.assertEqual(proof["tests_passed"], 1)
        self.assertEqual(proof["tests_skipped"], 0)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("pytest.main", self.calls[0][0][4])
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.observe(self.prepared, observer, receipt, token=SECRET)
        run.assert_not_called()

    def test_observer_rejects_missing_external_selection_before_child(self):
        observer = self.observer()
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.observe(self.prepared, observer, self.receipt(), token=SECRET)
        run.assert_not_called()
        self.assertFalse((self.root / "observer-attempt.json").exists())

    def test_observer_cannot_reuse_original_owner_comment(self):
        observer = self.observer()
        with (
            patch.object(execution, "_run") as run,
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.observe(
                self.prepared,
                observer,
                self.receipt(observer["selection"], 50),
                token=SECRET,
            )
        run.assert_not_called()

    def test_observer_skip_does_not_establish_acceptance(self):
        observer = self.observer()
        with (
            patch.object(
                execution,
                "_run",
                side_effect=self.fake_observer(observer, skipped=True),
            ),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.observe(
                self.prepared,
                observer,
                self.receipt(observer["selection"], 51),
                token=SECRET,
            )
        self.assertFalse((self.root / "observer-proof.json").exists())

    def test_observer_false_receipt_does_not_establish_acceptance(self):
        observer = self.observer()
        with (
            patch.object(
                execution,
                "_run",
                side_effect=self.fake_observer(observer, bad_receipt=True),
            ),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.observe(
                self.prepared,
                observer,
                self.receipt(observer["selection"], 51),
                token=SECRET,
            )

    def test_observer_cannot_modify_original_journal(self):
        observer = self.observer()
        with (
            patch.object(
                execution, "_run", side_effect=self.fake_observer(observer, mutate=True)
            ),
            self.assertRaises(execution.ExecutionStopped),
        ):
            execution.observe(
                self.prepared,
                observer,
                self.receipt(observer["selection"], 51),
                token=SECRET,
            )


class NativeDiagnosticRetentionTests(NativeExecutionFixture, unittest.TestCase):
    def call(self, method, number, *, retained=True, boundary=False):
        result = None
        if retained:
            provenance = {"method": method, "private_fact": SECRET}
            if boundary:
                provenance = {"kind": "delivery-engine-boundary-v1", "reason_code": "native-outcome-unresolved"}
            result = {"reason": SECRET, "provenance": provenance}
            result.update({"ready": True} if method == "inspect" else {"outcome": "uncertain"})
        receipt = None if result is None or method == "inspect" else {
            "id": execution.digest({"fixture_receipt": number}),
            "provenance_digest": execution.digest(result["provenance"]),
        }
        return {"id": execution.digest({"fixture_call": number}), "method": method,
                "result": result, "receipt": receipt}

    def snapshot(self, calls):
        proposal = self.prepared["proposal"]
        return {
            "metadata": {"objective": self.spec["objective"], "limits": self.spec["limits"],
                         "native_limits": proposal["native_limits"]},
            "operations": {proposal["request"]["operation_key"]: {
                "intent": {"request": proposal["request"]}, "payload": proposal["payload"],
                "approval": proposal["operation_approval"], "calls": calls,
            }},
        }

    def modules(self, snapshot, *, legacy=False, change_projection=None):
        events = []
        proposal = self.prepared["proposal"]

        def validate_payload(request, payload, configuration, policy):
            self.assertEqual((request, payload, configuration, policy),
                             tuple(proposal[name] for name in ("request", "payload", "configuration", "policy")))
            events.append("payload")

        def validate_result(method, request, payload, result, *, configuration, policy):
            validate_payload(request, payload, configuration, policy)
            events.append("validate:" + method)
            if result["provenance"].get("kind") == "delivery-engine-boundary-v1":
                raise ValueError(SECRET)
            self.assertEqual(result["provenance"]["method"], method)
            return copy.deepcopy(result)

        def project(method, result):
            self.assertEqual(events[-1], "validate:" + method)
            events.append("project:" + method)
            value = {
                "schema_version": "0.1.0", "profile": "github-atomic-merge-diagnostics-v1",
                "method": method, "provenance_digest": execution.digest(result["provenance"]),
                "diagnostic_available": False, "write_started": method == "invoke",
                "marker_object": None, "preparation_object": None, "diagnostic": None,
            }
            if change_projection is not None:
                change_projection(value)
            return value

        native = SimpleNamespace(validate_payload=validate_payload, validate_result=validate_result,
                                 configuration_digest=lambda *args: "sha256:" + "d" * 64)
        if not legacy:
            native.project_result_diagnostics = project

        @contextmanager
        def opened(path, journal_id, *, write, lock_timeout):
            self.assertEqual(path, Path(self.paths["journal"]))
            self.assertEqual(journal_id, self.prepared["journal_id"])
            self.assertIs(write, False)
            self.assertEqual(lock_timeout, 0.25)
            events.append("read-only-open")
            yield SimpleNamespace(read=lambda: copy.deepcopy(snapshot))

        return (native, SimpleNamespace(opened=opened)), events

    def diagnostic_artifact(self):
        path = self.root / "native-call-diagnostics.json"
        value = execution._json(path)
        self.assertEqual(set(value), {"schema_version", "kind", "authority_granted", "resend_allowed", "wrapper", "journal"})
        self.assertEqual(value["kind"], "native-call-diagnostics")
        self.assertIs(value["authority_granted"], False)
        self.assertIs(value["resend_allowed"], False)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        serialized = json.dumps(value)
        for private in (SECRET, str(self.root), str(self.core), "actual-fixture-journal-bytes",
                        "actual-fixture-key-bytes", "private-provider-response"):
            self.assertNotIn(private, serialized)
        return value

    def test_applied_result_retains_separate_diagnostics_without_changing_native_result(self):
        put(self.root / "invoke.stdout", b"private-provider-response" + SECRET.encode())
        put(self.root / "invoke.stderr", SECRET.encode())
        with patch.object(execution, "_diagnostic_native", return_value=(SimpleNamespace(), None)):
            result = self.run_fake()
        self.assertEqual(result, execution._json(self.root / "execution-report.json"))
        value = self.diagnostic_artifact()
        self.assertEqual(value["wrapper"]["invoke"], {"status": "returned", "report_status": "applied", "code": None})
        self.assertEqual(value["wrapper"]["reconcile"], {"status": "not_started", "report_status": None, "code": None})
        self.assertEqual(value["journal"], {"status": "legacy_unavailable", "code": "native_diagnostics_legacy_runtime",
                                            "total_calls": None, "selected_calls": []})
        self.assertEqual(len(self.calls), 1)

    def test_unresolved_invoke_is_retained_without_inferring_that_no_write_started(self):
        with patch.object(execution, "_run", side_effect=RuntimeError(SECRET)) as run:
            with self.assertRaises(execution.ExecutionStopped):
                execution.execute(self.prepared, self.receipt(), token=SECRET)
            value = self.diagnostic_artifact()
            self.assertEqual(value["wrapper"]["invoke"], {"status": "unresolved", "report_status": None,
                                                         "code": "native_child_unresolved"})
            self.assertIsNone(value["journal"]["total_calls"])
            self.assertEqual(value["journal"]["selected_calls"], [])
            with self.assertRaises(execution.ExecutionStopped):
                execution.execute(self.prepared, self.receipt(), token=SECRET)
            self.assertEqual(run.call_count, 1)

    def test_failed_reconciliation_retains_the_original_uncertainty_and_both_wrapper_stages(self):
        values = iter([(1, encoded(self.report("uncertain")), b""),
                       execution.ExecutionStopped(SECRET)])

        def child(*args, **kwargs):
            value = next(values)
            if isinstance(value, Exception):
                raise value
            return value

        with patch.object(execution, "_run", side_effect=child) as run:
            result = execution.execute(self.prepared, self.receipt(), token=SECRET)
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual(execution._json(self.root / "execution-report.json"), result)
        value = self.diagnostic_artifact()
        self.assertEqual(value["wrapper"]["invoke"], {"status": "returned", "report_status": "uncertain", "code": None})
        self.assertEqual(value["wrapper"]["reconcile"], {"status": "unresolved", "report_status": None,
                                                       "code": "native_child_unresolved"})
        self.assertEqual(run.call_count, 2)

    def test_collector_validates_latest_per_method_on_original_read_only_snapshot(self):
        calls = [self.call("inspect", 1), self.call("inspect", 2),
                 self.call("invoke", 3), self.call("reconcile", 4)]
        modules, events = self.modules(self.snapshot(calls))
        before = Path(self.paths["journal"]).read_bytes()
        with patch.object(execution, "_diagnostic_native", return_value=modules), patch.object(execution, "_run") as run:
            value = execution._collect_native_diagnostics(self.prepared)
        self.assertEqual(value["status"], "collected")
        self.assertEqual(value["total_calls"], 4)
        self.assertEqual([item["call_id"] for item in value["selected_calls"]], [call["id"] for call in calls[1:]])
        self.assertEqual([item["validation_status"] for item in value["selected_calls"]], ["validated"] * 3)
        self.assertEqual([event for event in events if event.startswith("project:")],
                         ["project:inspect", "project:invoke", "project:reconcile"])
        self.assertEqual(Path(self.paths["journal"]).read_bytes(), before)
        self.assertNotIn(SECRET, json.dumps(value))
        run.assert_not_called()

    def test_missing_result_stays_unknown_instead_of_claiming_readiness_or_outcome(self):
        modules, events = self.modules(self.snapshot([self.call("invoke", 1, retained=False)]))
        with patch.object(execution, "_diagnostic_native", return_value=modules):
            value = execution._collect_native_diagnostics(self.prepared)
        selected = value["selected_calls"][0]
        self.assertIs(selected["result_retained"], False)
        self.assertEqual(selected["validation_status"], "not_retained")
        for field in ("ready", "outcome", "receipt_id", "provenance_digest", "projection"):
            self.assertIsNone(selected[field])
        self.assertFalse(any(event.startswith("project:") for event in events))

    def test_engine_boundary_reconcile_does_not_erase_the_valid_invocation_summary(self):
        calls = [self.call("invoke", 1), self.call("reconcile", 2, boundary=True)]
        modules, _ = self.modules(self.snapshot(calls))
        with patch.object(execution, "_diagnostic_native", return_value=modules):
            value = execution._collect_native_diagnostics(self.prepared)
        self.assertEqual(value["status"], "partial")
        invoke, reconcile = value["selected_calls"]
        self.assertEqual(invoke["validation_status"], "validated")
        self.assertEqual(invoke["outcome"], "uncertain")
        self.assertIs(invoke["projection"]["write_started"], True)
        self.assertEqual(reconcile["validation_status"], "unavailable")
        self.assertEqual(reconcile["receipt_id"], calls[1]["receipt"]["id"])
        for field in ("ready", "outcome", "projection"):
            self.assertIsNone(reconcile[field])
        self.assertNotIn(SECRET, json.dumps(value))

    def test_scope_changed_receipt_and_snapshot_capacity_are_not_treated_as_native_evidence(self):
        mutations = (
            lambda s: s["metadata"].update(objective={"id": "another-objective"}),
            lambda s: s["metadata"].update(limits={"reads": 1}),
            lambda s: next(iter(s["operations"].values()))["intent"].update(request={}),
            lambda s: next(iter(s["operations"].values())).update(payload={}),
            lambda s: next(iter(s["operations"].values())).update(approval={}),
            lambda s: next(iter(s["operations"].values()))["calls"][0]["receipt"].update(provenance_digest="sha256:" + "0" * 64),
            lambda s: next(iter(s["operations"].values())).update(calls=[self.call("invoke", 1)] * 10001),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(change=index):
                snapshot = self.snapshot([self.call("invoke", 1)])
                mutate(snapshot)
                modules, _ = self.modules(snapshot)
                with patch.object(execution, "_diagnostic_native", return_value=modules), self.assertRaises(Exception):
                    execution._collect_native_diagnostics(self.prepared)

    def test_bad_projection_is_marked_unavailable_without_copying_its_payload(self):
        changes = (
            lambda p: p.update(method="reconcile"),
            lambda p: p.update(provenance_digest="sha256:" + "0" * 64),
            lambda p: p.update(provider_response=SECRET),
        )
        for index, change in enumerate(changes):
            with self.subTest(change=index):
                modules, _ = self.modules(self.snapshot([self.call("invoke", 1)]), change_projection=change)
                with patch.object(execution, "_diagnostic_native", return_value=modules):
                    value = execution._collect_native_diagnostics(self.prepared)
                self.assertEqual(value["status"], "partial")
                self.assertIsNone(value["selected_calls"][0]["projection"])
                self.assertNotIn(SECRET, json.dumps(value))

    def test_legacy_projector_absence_does_not_open_or_guess_from_the_journal(self):
        modules, events = self.modules(self.snapshot([self.call("invoke", 1)]), legacy=True)
        with patch.object(execution, "_diagnostic_native", return_value=modules):
            value = execution._collect_native_diagnostics(self.prepared)
        self.assertEqual(value["status"], "legacy_unavailable")
        self.assertIsNone(value["total_calls"])
        self.assertEqual(events, [])

    def test_replaced_or_oversized_original_journal_stops_before_native_loading(self):
        journal = Path(self.paths["journal"])
        with patch.object(execution, "MAX_JOURNAL", 1), patch.object(execution, "_diagnostic_native") as native:
            with self.assertRaises(execution.ExecutionStopped):
                execution._collect_native_diagnostics(self.prepared)
        native.assert_not_called()
        replacement = self.root / "replacement-journal"
        put(replacement, journal.read_bytes())
        os.replace(replacement, journal)
        with patch.object(execution, "_diagnostic_native") as native, self.assertRaises(execution.ExecutionStopped):
            execution._collect_native_diagnostics(self.prepared)
        native.assert_not_called()

    def test_collection_or_artifact_write_failure_cannot_change_applied_effect_or_resend(self):
        accesses = []

        class Sensitive(RuntimeError):
            def __str__(self):
                accesses.append("str")
                raise AssertionError("diagnostic failure details were inspected")

        with patch.object(execution, "_collect_native_diagnostics", side_effect=Sensitive(SECRET)):
            report = self.run_fake()
        self.assertEqual(report["status"], "applied")
        self.assertEqual(self.diagnostic_artifact()["journal"]["status"], "unavailable")
        self.assertEqual(accesses, [])
        self.assertEqual(execution._json(self.root / "execution-report.json"), report)
        with patch.object(execution, "_run") as run, self.assertRaises(execution.ExecutionStopped):
            execution.execute(self.prepared, self.receipt(), token=SECRET)
        run.assert_not_called()

    def test_collector_failure_keeps_uncertain_native_results_and_both_attempts(self):
        with patch.object(execution, "_collect_native_diagnostics", side_effect=ValueError(SECRET)):
            report = self.run_fake(("uncertain", "uncertain"))
        self.assertEqual(report["status"], "uncertain")
        self.assertEqual(execution._json(self.root / "execution-report.json"), report)
        value = self.diagnostic_artifact()
        self.assertEqual(value["journal"]["status"], "unavailable")
        self.assertEqual([value["wrapper"][method]["report_status"] for method in ("invoke", "reconcile")],
                         ["uncertain", "uncertain"])
        self.assertEqual(len(self.calls), 2)

    def test_unexpected_retainer_exception_cannot_replace_the_native_result(self):
        with patch.object(execution, "_retain_native_diagnostics", side_effect=RuntimeError(SECRET)):
            report = self.run_fake()
        self.assertEqual(report["status"], "applied")
        self.assertEqual(execution._json(self.root / "execution-report.json"), report)
        self.assertEqual(len(self.calls), 1)

    def test_diagnostic_file_is_create_only_and_write_failure_preserves_result(self):
        path = self.root / "native-call-diagnostics.json"
        put(path, b"previous-private-diagnostic")
        before = path.read_bytes()
        report = self.run_fake()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(report, execution._json(self.root / "execution-report.json"))
        self.assertEqual(len(self.calls), 1)

    def test_diagnostic_symlink_is_not_followed_or_overwritten(self):
        target = self.root / "unrelated-private-evidence"
        put(target, b"unrelated-private-evidence")
        (self.root / "native-call-diagnostics.json").symlink_to(target)
        report = self.run_fake()
        self.assertEqual(report["status"], "applied")
        self.assertEqual(target.read_bytes(), b"unrelated-private-evidence")
        self.assertTrue((self.root / "native-call-diagnostics.json").is_symlink())


if __name__ == "__main__":
    unittest.main()
