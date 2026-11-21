"""Cumulative allowance checks use pure, controlled documents only.

Re-pinning below is confined to a fresh in-memory module so semantic guards are
tested independently of the production manifest digest. It grants no authority,
touches no provider and creates no operator installation or credential.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
OLD_SPEC_DIGEST = "sha256:57adffb6987860d94bf05f5b657880ab23efba41056ef291d81d291bb7de2c0c"
OLD_ACCOUNTING_DIGEST = "sha256:e24eff58d035b15e9fbfb5375c465209c2e4cf4a976ad538fa9a18ccf3f20f3e"
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


class CumulativeAllowanceAccountingTests(unittest.TestCase):
    def setUp(self):
        selected = importlib.util.spec_from_file_location(
            "accounting_test_protocol", ROOT / "tools/native_trial_protocol.py")
        self.module = importlib.util.module_from_spec(selected)
        selected.loader.exec_module(self.module)
        self.protocol = self.module.load(ROOT)

    def assert_semantically_refused(self, mutate):
        spec = copy.deepcopy(self.protocol["spec"])
        mutate(spec["accounting"])
        profile = copy.deepcopy(self.protocol["profile"])
        profile.update(spec_digest=self.module.digest(spec),
                       accounting_digest=self.module.digest(spec["accounting"]))
        with patch.multiple(self.module, PROFILE=profile,
                            SPEC_DIGEST=profile["spec_digest"],
                            ACCOUNTING_DIGEST=profile["accounting_digest"]):
            with self.assertRaises(ValueError):
                self.module.validate_protocol({"profile": profile, "spec": spec})

    def receipt(self):
        command = self.module.allowance_command(self.protocol, CONTEXT)
        return {
            "schema_version": "0.1.0", "kind": "owner-approved-supplemental-native-allocation",
            "status": "approved", "context": copy.deepcopy(CONTEXT),
            "accounting": copy.deepcopy(self.protocol["spec"]["accounting"]),
            "accounting_digest": self.protocol["profile"]["accounting_digest"],
            "reviewer_id": 1679024, "environment_id": 26032127012,
            "command": command,
            "command_digest": "sha256:" + hashlib.sha256(command.encode()).hexdigest(),
            "observed_at": "2026-11-21T10:00:00.000000Z",
        }

    def validate_receipt(self, receipt, *, context=CONTEXT):
        return self.module.validate_allocation(
            receipt, profile=self.protocol["profile"], spec=self.protocol["spec"], context=context)

    def old_accounting_and_command(self):
        accounting = self.protocol["spec"]["accounting"]
        first = copy.deepcopy(accounting["consumed_allocations"][0])
        first.pop("charged_limits")
        old = {name: copy.deepcopy(accounting[name]) for name in (
            "kind", "original_objective", "operation_key", "additional_limits",
            "authorization", "accounting_scope",
        )}
        old.update(
            schema_version="0.1.0", predecessor=first,
            charged_prior_limits=copy.deepcopy(accounting["additional_limits"]),
            aggregate_limits={"operations": 2, "wall_time_ms": 720000, "reads": 384, "rollbacks": 0},
            history_baseline=copy.deepcopy(accounting["history_baseline"][:-1]),
        )
        self.assertEqual(self.module.digest(old), OLD_ACCOUNTING_DIGEST)
        fields = [
            ("run", CONTEXT["run_id"]), ("attempt", 1), ("source", CONTEXT["source"]),
            ("manifest", OLD_SPEC_DIGEST), ("accounting", OLD_ACCOUNTING_DIGEST),
            ("original_goal", old["original_objective"]["original_goal"]),
            ("predecessor", 41526436188), ("additional_operations", 1),
            ("additional_wall_time_ms", 360000), ("additional_reads", 192),
            ("aggregate_operations", 2), ("aggregate_wall_time_ms", 720000),
            ("aggregate_reads", 384), ("rollbacks", 0),
        ]
        command = "/exacly-native-trial supplement " + " ".join(
            name + "=" + str(value) for name, value in fields)
        return old, command

    def test_consumed_records_cannot_be_dropped_duplicated_or_reordered(self):
        changes = (
            lambda a: a["consumed_allocations"].pop(0),
            lambda a: a["consumed_allocations"].pop(1),
            lambda a: a["consumed_allocations"].clear(),
            lambda a: a["consumed_allocations"].append(copy.deepcopy(a["consumed_allocations"][0])),
            lambda a: a["consumed_allocations"].reverse(),
        )
        for number, mutate in enumerate(changes):
            with self.subTest(change=number):
                self.assert_semantically_refused(mutate)

    def test_each_consumed_charge_is_full_even_when_totals_are_rebalanced(self):
        for index in (0, 1):
            for key in ("operations", "wall_time_ms", "reads", "rollbacks"):
                with self.subTest(allocation=index, budget=key):
                    def mutate(accounting, index=index, key=key):
                        charge = accounting["consumed_allocations"][index]["charged_limits"]
                        charge[key] = charge[key] - 1 if charge[key] else 1
                        for name in accounting["charged_prior_limits"]:
                            prior = sum(item["charged_limits"][name]
                                        for item in accounting["consumed_allocations"])
                            accounting["charged_prior_limits"][name] = prior
                            accounting["aggregate_limits"][name] = prior + accounting["additional_limits"][name]
                    self.assert_semantically_refused(mutate)

    def test_consumed_charges_are_integers_not_equal_booleans_or_floats(self):
        for index in (0, 1):
            for value in (True, 1.0):
                with self.subTest(allocation=index, value_type=type(value).__name__):
                    self.assert_semantically_refused(
                        lambda a, index=index, value=value:
                        a["consumed_allocations"][index]["charged_limits"].update(operations=value))

    def test_prior_total_is_derived_from_all_charges_even_when_aggregate_matches(self):
        def mutate(accounting):
            accounting["charged_prior_limits"] = copy.deepcopy(accounting["additional_limits"])
            accounting["aggregate_limits"] = {
                key: accounting["charged_prior_limits"][key] + value
                for key, value in accounting["additional_limits"].items()
            }
        self.assert_semantically_refused(mutate)

    def test_aggregate_cannot_omit_any_prior_charge(self):
        for replacement in ("charged_prior_limits", "additional_limits"):
            with self.subTest(replacement=replacement):
                self.assert_semantically_refused(
                    lambda a, replacement=replacement:
                    a.update(aggregate_limits=copy.deepcopy(a[replacement])))

    def test_every_consumed_identity_matches_its_exact_native_history_tuple(self):
        changes = {
            "run_id": 999, "run_attempt": 2, "source": "a" * 40,
            "workflow_id": 1, "title": "renamed-native-trial",
            "status": "in_progress", "conclusion": "cancelled",
        }
        for index in (0, 1):
            for name, value in changes.items():
                with self.subTest(allocation=index, field=name):
                    self.assert_semantically_refused(
                        lambda a, index=index, name=name, value=value:
                        a["consumed_allocations"][index].update({name: value}))

    def test_native_history_and_consumed_allocations_cover_each_other_exactly(self):
        def remove_native(accounting):
            consumed_id = accounting["consumed_allocations"][1]["run_id"]
            accounting["history_baseline"] = [
                item for item in accounting["history_baseline"] if item["run_id"] != consumed_id]

        def add_unaccounted_native(accounting):
            extra = copy.deepcopy(accounting["history_baseline"][-1])
            extra["run_id"] = 999
            accounting["history_baseline"].append(extra)

        changes = (
            remove_native, add_unaccounted_native,
            lambda a: a["history_baseline"].append(copy.deepcopy(a["history_baseline"][0])),
            lambda a: a["history_baseline"][-1].update(title="canary-bootstrap:diagnostic:pr-5"),
        )
        for number, mutate in enumerate(changes):
            with self.subTest(change=number):
                self.assert_semantically_refused(mutate)

    def test_exact_reviewed_history_cannot_be_changed_by_document_tampering(self):
        changes = (
            lambda a: a["history_baseline"].pop(0),
            lambda a: a["history_baseline"].reverse(),
            lambda a: a["history_baseline"][0].update(source="a" * 40),
            lambda a: a["history_baseline"].append(copy.deepcopy(a["history_baseline"][0])),
        )
        for number, mutate in enumerate(changes):
            with self.subTest(change=number):
                selected = copy.deepcopy(self.protocol)
                mutate(selected["spec"]["accounting"])
                with self.assertRaises(ValueError):
                    self.module.validate_protocol(selected)

    def test_every_historical_run_is_refused_as_current_allocation_context(self):
        for historical in self.protocol["spec"]["accounting"]["history_baseline"]:
            with self.subTest(run=historical["run_id"]):
                with self.assertRaises(ValueError):
                    self.module.allowance_command(
                        self.protocol, {**CONTEXT, "run_id": historical["run_id"]})

    def test_old_command_accounting_and_receipt_cannot_select_new_capacity(self):
        old_accounting, old_command = self.old_accounting_and_command()
        self.assertNotEqual(old_command, self.receipt()["command"])
        changes = (
            {"command": old_command},
            {"accounting": old_accounting, "accounting_digest": OLD_ACCOUNTING_DIGEST},
            {"command": old_command, "accounting": old_accounting,
             "accounting_digest": OLD_ACCOUNTING_DIGEST},
        )
        for number, changed in enumerate(changes):
            with self.subTest(replay=number):
                receipt = self.receipt()
                receipt.update(changed)
                receipt["command_digest"] = "sha256:" + hashlib.sha256(receipt["command"].encode()).hexdigest()
                with self.assertRaises(ValueError):
                    self.validate_receipt(receipt)

    def test_rebinding_current_receipt_to_a_spent_run_does_not_restore_authority(self):
        for consumed in self.protocol["spec"]["accounting"]["consumed_allocations"]:
            with self.subTest(run=consumed["run_id"]):
                receipt = self.receipt()
                context = {**CONTEXT, "run_id": consumed["run_id"]}
                receipt["context"] = context
                with self.assertRaises(ValueError):
                    self.validate_receipt(receipt, context=context)


if __name__ == "__main__":
    unittest.main()
