"""Pinned supplemental allocation; constructing these documents grants no authority.

The old journals cannot be restored or credited. The coordinator separately
verifies the complete run history and the owner's exact environment-review
comment before allocating a new private installation under the same objective.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import re
import stat
from pathlib import Path


SPEC_PATH = "config/native-supplemental-trial.json"
SPEC_DIGEST = "sha256:e91e24afa1af0d12798542f6b7872f1d0adbce1815e0e30c2ade343cd730ac4c"
ACCOUNTING_DIGEST = "sha256:09670e7d79f6f56e4428e18023a110fe85689a733e624ab8116e28250c42936e"
PROFILE = {
    "core_revision": "bd60d9d58c44390089a435d075a77f132cb684da",
    "spec_digest": SPEC_DIGEST,
    "native_pins": {
        "automatic_merge.py": "e6646012de31fb473f298861fa482bc7741e4592bd84375feaa1ebed1f9356b7",
        "github_merge.py": "207ac9bc6df50f8baf8ceafb7568163a26ccb02b2ee79da86707404298587d28",
    },
    "accounting_digest": ACCOUNTING_DIGEST,
}
REPOSITORY = "whiteredhouse/exacly-delivery-acceptance"
REPOSITORY_ID, OWNER_ID, ENVIRONMENT_ID = 1442278205, 1679024, 26032127012
REF = "refs/heads/codex/preflight-diagnostics"
WORKFLOW = ".github/workflows/app-bootstrap.yml"
JOB = "native-positive-trial"
MAX_DOCUMENT = 1024 * 1024
ALLOCATION_LIMITS = {"operations": 1, "wall_time_ms": 360000, "reads": 192, "rollbacks": 0}
NATIVE_TITLE = "canary-bootstrap:native-positive-trial:pr-5"
HISTORY_FIELDS = {"run_id", "run_attempt", "source", "title", "status", "conclusion", "workflow_id"}


def require(value):
    if not value:
        raise ValueError("supplemental native allocation refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _unique(items):
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value


def _context(context, accounting):
    historical = {item["run_id"] for item in accounting["history_baseline"]}
    historical.update(item["run_id"] for item in accounting["consumed_allocations"])
    require(isinstance(context, dict)
            and set(context) == {"repository", "repository_id", "source", "run_id", "run_attempt",
                                 "workflow_ref", "ref", "job"}
            and context["repository"] == REPOSITORY
            and type(context["repository_id"]) is int and context["repository_id"] == REPOSITORY_ID
            and isinstance(context["source"], str) and re.fullmatch(r"[0-9a-f]{40}", context["source"])
            and type(context["run_id"]) is int and 0 < context["run_id"] < 2**63
            and context["run_id"] not in historical
            and type(context["run_attempt"]) is int and context["run_attempt"] == 1
            and context["workflow_ref"] == REPOSITORY + "/" + WORKFLOW + "@" + REF
            and context["ref"] == REF and context["job"] == JOB)


def validate_profile(profile, spec=None):
    """Validate the source-selected profile; private state never selects it."""
    require(isinstance(profile, dict) and profile == PROFILE)
    if spec is None:
        return copy.deepcopy(profile)
    require(isinstance(spec, dict) and digest(spec) == SPEC_DIGEST
            and spec.get("kind") == "fixed-native-supplemental-trial"
            and spec.get("core_revision") == profile["core_revision"])
    accounting = spec.get("accounting")
    require(isinstance(accounting, dict) and set(accounting) == {
        "schema_version", "kind", "original_objective", "operation_key", "consumed_allocations",
        "charged_prior_limits", "additional_limits", "aggregate_limits", "authorization",
        "accounting_scope", "history_baseline",
    } and digest(accounting) == ACCOUNTING_DIGEST
            and accounting.get("schema_version") == "0.2.0"
            and accounting["kind"] == "supplemental-native-trial-allocation"
            and accounting["original_objective"] == spec["objective"]
            and accounting["operation_key"] == spec["operation_key"]
            and accounting["additional_limits"] == spec["limits"] == ALLOCATION_LIMITS
            and all(type(number) is int for number in spec["limits"].values()))
    keys = {"operations", "wall_time_ms", "reads", "rollbacks"}
    for name in ("charged_prior_limits", "additional_limits", "aggregate_limits"):
        require(isinstance(accounting[name], dict) and set(accounting[name]) == keys
                and all(type(number) is int and number >= 0 for number in accounting[name].values()))
    history, consumed = accounting["history_baseline"], accounting["consumed_allocations"]
    require(isinstance(history, list) and history and isinstance(consumed, list) and consumed)
    for item in history:
        require(isinstance(item, dict) and set(item) == HISTORY_FIELDS
                and type(item["run_id"]) is int and 0 < item["run_id"] < 2**63
                and type(item["run_attempt"]) is int and item["run_attempt"] == 1
                and isinstance(item["source"], str) and re.fullmatch(r"[0-9a-f]{40}", item["source"])
                and isinstance(item["title"], str) and item["title"]
                and item["status"] == "completed"
                and isinstance(item["conclusion"], str) and item["conclusion"]
                and type(item["workflow_id"]) is int and 0 < item["workflow_id"] < 2**63)
    require(len({item["run_id"] for item in history}) == len(history))
    native_history = [item for item in history if item["title"] == NATIVE_TITLE]
    require(len(consumed) == len(native_history))
    consumed_ids = []
    for allocation, historical in zip(consumed, native_history):
        require(isinstance(allocation, dict) and HISTORY_FIELDS <= set(allocation)
                and all(type(allocation[key]) is type(historical[key]) for key in HISTORY_FIELDS)
                and {key: allocation[key] for key in HISTORY_FIELDS} == historical
                and isinstance(allocation.get("charged_limits"), dict)
                and set(allocation["charged_limits"]) == keys
                and all(type(number) is int and number >= 0
                        for number in allocation["charged_limits"].values())
                and allocation["charged_limits"] == ALLOCATION_LIMITS)
        consumed_ids.append(allocation["run_id"])
    require(len(set(consumed_ids)) == len(consumed_ids))
    require(all(accounting["charged_prior_limits"][key]
                == sum(item["charged_limits"][key] for item in consumed)
                for key in keys))
    require(all(accounting["aggregate_limits"][key]
                == accounting["charged_prior_limits"][key] + accounting["additional_limits"][key]
                for key in keys))
    return copy.deepcopy(profile)


def load(root):
    """Load only the fixed supplemental manifest from this reviewed checkout."""
    require(isinstance(root, Path) and root.is_absolute() and root.resolve() == root)
    path = root / SPEC_PATH
    require(path.resolve() == path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_DOCUMENT)
        data = os.read(descriptor, MAX_DOCUMENT + 1)
        after = os.fstat(descriptor)
        require(len(data) == info.st_size
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    finally:
        os.close(descriptor)
    spec = json.loads(data, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid manifest")))
    validate_profile(PROFILE, spec)
    return {"profile": copy.deepcopy(PROFILE), "spec": spec}


def validate_protocol(protocol):
    require(isinstance(protocol, dict) and set(protocol) == {"profile", "spec"})
    validate_profile(protocol["profile"], protocol["spec"])
    return copy.deepcopy(protocol)


def allowance_command(protocol, context):
    """Exact comment required in the owner's actual environment approval."""
    selected = validate_protocol(protocol)
    accounting = selected["spec"]["accounting"]
    _context(context, accounting)
    prior = accounting["charged_prior_limits"]
    additional, aggregate = accounting["additional_limits"], accounting["aggregate_limits"]
    fields = [
        ("run", context["run_id"]), ("attempt", context["run_attempt"]),
        ("source", context["source"]), ("manifest", selected["profile"]["spec_digest"]),
        ("accounting", selected["profile"]["accounting_digest"]),
        ("original_goal", accounting["original_objective"]["original_goal"]),
        ("consumed_runs", ",".join(str(item["run_id"]) for item in accounting["consumed_allocations"])),
        ("charged_prior_operations", prior["operations"]),
        ("charged_prior_wall_time_ms", prior["wall_time_ms"]), ("charged_prior_reads", prior["reads"]),
        ("charged_prior_rollbacks", prior["rollbacks"]),
        ("additional_operations", additional["operations"]),
        ("additional_wall_time_ms", additional["wall_time_ms"]), ("additional_reads", additional["reads"]),
        ("aggregate_operations", aggregate["operations"]),
        ("aggregate_wall_time_ms", aggregate["wall_time_ms"]), ("aggregate_reads", aggregate["reads"]),
        ("rollbacks", aggregate["rollbacks"]),
    ]
    return "/exacly-native-trial supplement " + " ".join(key + "=" + str(value) for key, value in fields)


def validate_allocation(receipt, *, profile, spec, context):
    """Check a retained projection; the relay separately verifies its provider origin."""
    validate_profile(profile, spec)
    _context(context, spec["accounting"])
    require(isinstance(receipt, dict) and set(receipt) == {
        "schema_version", "kind", "status", "context", "accounting", "accounting_digest",
        "reviewer_id", "environment_id", "command", "command_digest", "observed_at",
    })
    command = allowance_command({"profile": profile, "spec": spec}, context)
    _context(receipt["context"], spec["accounting"])
    require(receipt["schema_version"] == "0.1.0"
            and receipt["kind"] == "owner-approved-supplemental-native-allocation"
            and receipt["status"] == "approved" and receipt["context"] == context
            and receipt["accounting"] == spec["accounting"]
            and digest(receipt["accounting"]) == profile["accounting_digest"]
            and receipt["accounting_digest"] == profile["accounting_digest"]
            and type(receipt["reviewer_id"]) is int and receipt["reviewer_id"] == OWNER_ID
            and type(receipt["environment_id"]) is int and receipt["environment_id"] == ENVIRONMENT_ID
            and receipt["command"] == command
            and receipt["command_digest"] == "sha256:" + hashlib.sha256(command.encode("ascii")).hexdigest())
    require(isinstance(receipt["observed_at"], str))
    try:
        observed = dt.datetime.fromisoformat(receipt["observed_at"])
        require(observed.utcoffset() == dt.timedelta(0)
                and observed.isoformat(timespec="microseconds").replace("+00:00", "Z") == receipt["observed_at"])
    except (ValueError, TypeError):
        raise ValueError("supplemental native allocation refused") from None
    return copy.deepcopy(receipt)
