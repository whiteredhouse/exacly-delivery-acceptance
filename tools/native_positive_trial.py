"""Three one-shot steps on the original hosted filesystem; no implicit approval."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "whiteredhouse/exacly-delivery-acceptance"
REF = "refs/heads/codex/preflight-diagnostics"
MAX_DOCUMENT = 1024 * 1024
UTC = dt.timezone.utc


class Stopped(ValueError):
    """Only fixed local codes may reach the public report."""


def require(value, code="coordinator_validation_failed"):
    if not value:
        raise Stopped(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(data):
    require(len(data) <= MAX_DOCUMENT)
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Stopped()))


def private_parent(path):
    require(path.is_absolute() and path.parent.resolve() == path.parent)
    info = path.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700)
    return os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def read_private(path):
    parent = private_parent(path)
    fd = -1
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= MAX_DOCUMENT)
        data = os.read(fd, MAX_DOCUMENT + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and len(data) == before.st_size)
        value = decode(data)
        require(canonical(value) == data)
        return value
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def create_private(path, value, credentials):
    data = canonical(value)
    require(len(data) <= MAX_DOCUMENT and all(secret.encode() not in data for secret in credentials))
    parent = private_parent(path)
    fd = -1
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            require(written > 0)
            offset += written
        os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def load_helper(name):
    path = ROOT / "tools" / (name + ".py")
    require(path.resolve() == path)
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context():
    fixed = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
             "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REPOSITORY_ID": "1442278205",
             "GITHUB_REF": REF, "GITHUB_JOB": "native-positive-trial", "GITHUB_RUN_ATTEMPT": "1",
             "GITHUB_ACTOR_ID": "1679024",
             "GITHUB_WORKFLOW_REF": REPOSITORY + "/.github/workflows/app-bootstrap.yml@" + REF}
    require(all(os.environ.get(key) == value for key, value in fixed.items()), "wrong_host_context")
    source, run = os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[1-9][0-9]*", run),
            "wrong_host_context")
    env = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull}
    base = ["git", "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull,
            "-c", "core.fsmonitor=false", "-C", str(ROOT)]
    head = subprocess.run([*base, "rev-parse", "--verify", "HEAD"], env=env, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=5, check=False)
    clean = subprocess.run([*base, "status", "--porcelain", "--untracked-files=all"], env=env,
                           capture_output=True, stdin=subprocess.DEVNULL, timeout=5, check=False)
    require(head.returncode == clean.returncode == 0 and head.stdout.strip().decode("ascii") == source
            and clean.stdout == b"", "source_changed")
    return {"repository": REPOSITORY, "repository_id": 1442278205, "source": source,
            "run_id": int(run), "run_attempt": 1, "workflow_ref": fixed["GITHUB_WORKFLOW_REF"],
            "ref": REF, "job": "native-positive-trial"}


def private_path(value, ctx):
    parent = Path(os.environ.get("RUNNER_TEMP", ""))
    require(parent.is_absolute() and parent.resolve() == parent)
    expected = parent / ("native-positive-" + str(ctx["run_id"]) + "-1")
    require(value == expected and ".." not in value.parts, "wrong_private_path")
    return expected


def timestamp(value):
    require(isinstance(value, dt.datetime) and value.utcoffset() == dt.timedelta(0))
    return value.isoformat().replace("+00:00", "Z")


def date(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.utcoffset() == dt.timedelta(0))
    return result


def instructions(prepared, item, relay, packets, now):
    phase = item["selection"]["phase"]
    name = "merge" if phase == "merge" else "observer"
    lease = date(prepared["proposal"]["configuration"]["actor"]["grant"]["not_after"])
    decision = (item["proposal"]["operation_approval"] if phase == "merge"
                else item["proposal"]["packet"]["read_approval"])
    plan = relay.plan_wait(item["selection"], credential_expires_at=min(lease, date(decision["expires_at"])))
    require(plan["phase"] == phase and plan["selection_digest"] == digest(item["selection"]),
            "wait_plan_changed")
    document = {"schema_version": "0.1.0", "kind": "proposed-owner-selection-instructions",
                "status": "proposed", "authority_granted": False, "selection": item["selection"],
                "owner": {"id": 1679024, "login": "p1c2u"},
                "comment_destination": "https://github.com/" + REPOSITORY + "/pull/5",
                "approve_command": relay.approval_command(item["selection"]),
                "deny_command": relay.deny_command(item["selection"]),
                "proposal_issued_at": plan["issued_at"], "expires_at": plan["submit_by"],
                "verification_expires_at": plan["verify_by"], "wait_plan": plan,
                "review": "Read the complete proposal before manually posting the exact single approval line on PR5.",
                "retention": prepared["spec"]["retention"]}
    packets.write_safe(Path(prepared["private_dir"]) / (name + "-approval-instructions.json"),
                       document, prepared["_token"])
    return document


def checkpoint(path, phase, ctx, prepared, relay_state, expires, credentials, *, wait_plan, **extra):
    require(isinstance(wait_plan, dict) and wait_plan.get("submit_by") == expires, "wait_plan_changed")
    value = {"schema_version": "0.1.0", "kind": "same-job-coordinator-checkpoint", "phase": phase,
             "context": ctx, "private_dir": prepared["private_dir"],
             "prepared_manifest_digest": digest(read_private(path.parent / "prepared-state.json")),
             "merge_selection_digest": digest(prepared["selection"]),
             "relay": relay_state, "selection_expires_at": expires, "wait_plan": wait_plan, **extra}
    create_private(path, value, credentials)
    return value


def consume(path, expected_phase, ctx, prepared, credentials):
    previous = read_private(path)
    require(previous.get("kind") == "same-job-coordinator-checkpoint"
            and previous.get("schema_version") == "0.1.0"
            and previous.get("phase") == expected_phase and previous.get("context") == ctx
            and previous.get("private_dir") == prepared["private_dir"]
            and previous.get("merge_selection_digest") == digest(prepared["selection"])
            and previous.get("prepared_manifest_digest") == digest(read_private(path.parent / "prepared-state.json"))
            and isinstance(previous.get("wait_plan"), dict)
            and previous.get("selection_expires_at") == previous["wait_plan"].get("submit_by"),
            "checkpoint_changed")
    return previous


def summary(document):
    # The exact command is also in the already complete artifact, never a secret.
    print(json.dumps({"phase": document["selection"]["phase"], "status": "waiting_for_owner_selection",
                      "expires_at": document["expires_at"], "verification_expires_at": document["verification_expires_at"],
                      "approve_command": document["approve_command"]}), flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write("Review the complete proposal artifact, then manually post this exact line on PR #5.\n\n")
            stream.write("```text\n" + document["approve_command"] + "\n```\n\n")
            stream.write("Submit the selection before " + document["expires_at"] + ". Verification must finish by "
                         + document["verification_expires_at"] + ". The job retains its original private filesystem.\n")


def run(phase, private, core, *, packets, relays, execution, ctx, app_token, relay_token, now, protocol=None):
    credentials = tuple(value for value in (app_token, relay_token) if value)
    require(app_token != relay_token, "credential_roles_collide")
    selected = {}
    relay_options = {}
    protocols = None
    if protocol is not None:
        protocols = load_helper("native_trial_protocol")
        require(protocol == protocols.load(ROOT), "supplemental_protocol_changed")
        selected = {"profile": protocol["profile"]}
        relay_options = {"protocol": protocol}
    control = private.with_name(private.name + "-allocation")
    if phase == "authorize":
        require(protocol is not None and not app_token and relay_token, "wrong_allocation_context")
        require(not private.exists() and not control.exists(), "private_runtime_already_exists")
        relay = relays.Relay(relay_token, ctx, **relay_options)
        relay.check_host()
        allocation = relay.check_supplemental_allowance()
        protocols.validate_allocation(allocation, profile=protocol["profile"], spec=protocol["spec"], context=ctx)
        control.mkdir(mode=0o700)
        create_private(control / "allocation.json", allocation, credentials)
        create_private(control / "allocation-checkpoint.json", {
            "schema_version": "0.1.0", "kind": "pre-mint-supplemental-allocation-checkpoint",
            "context": ctx, "private_dir": str(private), "protocol_digest": digest(protocol),
            "allocation_digest": digest(allocation), "relay": relay.export_state(),
        }, credentials)
        return {"status": "supplemental_allocation_approved", "native_effect": "not_attempted"}
    require(app_token and relay_token, "missing_preparation_credential")
    if phase == "prepare":
        require(not private.exists(), "private_runtime_already_exists")
        allocation_options = {}
        if protocol is None:
            relay = relays.Relay(relay_token, ctx)
            relay.check_host()
            spec_path = ROOT / "config/native-positive-trial.json"
            require(spec_path.resolve() == spec_path)
            spec = decode(spec_path.read_bytes())
        else:
            allocation = read_private(control / "allocation.json")
            previous = read_private(control / "allocation-checkpoint.json")
            require(previous.get("schema_version") == "0.1.0"
                    and previous.get("kind") == "pre-mint-supplemental-allocation-checkpoint"
                    and previous.get("context") == ctx and previous.get("private_dir") == str(private)
                    and previous.get("protocol_digest") == digest(protocol)
                    and previous.get("allocation_digest") == digest(allocation), "allocation_checkpoint_changed")
            protocols.validate_allocation(allocation, profile=protocol["profile"], spec=protocol["spec"], context=ctx)
            create_private(control / "allocation-consumed.json", {
                "context": ctx, "protocol_digest": digest(protocol), "allocation_digest": digest(allocation),
            }, credentials)
            relay = relays.Relay.restore(relay_token, ctx, previous["relay"], **relay_options)
            relay.recheck_host()
            spec = protocol["spec"]
            allocation_options = {"allocation": allocation}
        installed = os.environ.get("CANARY_INSTALLATION_ID", "")
        require(installed == "177653055", "wrong_installation")
        prepared = packets.prepare(private, spec, ctx, core, app_token, int(installed), now=now(),
                                   **selected, **allocation_options)
        packets.save_private(prepared)
        create_private(private / "prepare-consumed.json", {"context": ctx, "phase": phase}, credentials)
        display = instructions(prepared, prepared, relay, packets, now())
        checkpoint(private / "coordinator-prepared.json", phase, ctx, prepared, relay.export_state(),
                   display["expires_at"], credentials, wait_plan=display["wait_plan"])
        summary(display)
        return {"status": "proposed", "native_effect": "not_attempted"}

    prepared = packets.restore(private, core, app_token, **selected)
    require(prepared["context"] == ctx, "wrong_host_context")
    require(os.environ.get("CANARY_INSTALLATION_ID") == "177653055", "wrong_installation")
    prior_name, prior_phase = (("coordinator-prepared.json", "prepare") if phase == "merge"
                              else ("coordinator-merged.json", "merge"))
    previous = consume(private / prior_name, prior_phase, ctx, prepared, credentials)
    create_private(private / (phase + "-consumed.json"),
                   {"context": ctx, "phase": phase, "checkpoint_digest": digest(previous)}, credentials)
    relay = relays.Relay.restore(relay_token, ctx, previous["relay"], **relay_options)
    if phase == "merge":
        receipt = relay.wait(prepared["selection"], plan=previous["wait_plan"])
        packets.write_safe(private / "merge-approval-receipt.json", receipt, app_token)
        if protocol is not None:
            relay.recheck_host()
        report = execution.execute(prepared, receipt, token=app_token, **selected)
        packets.write_safe(private / "merge-result.json", report, app_token)
        require(report.get("status") == "applied", "native_merge_not_applied_do_not_resend")
        replay = execution.offline_replay(prepared, report, token=app_token, **selected)
        require(replay.get("status") == "passed" and replay.get("journal_unchanged") is True
                and type(replay.get("network_syscalls")) is int
                and replay["network_syscalls"] == 0, "offline_replay_not_proved")
        packets.write_safe(private / "offline-replay.json", replay, app_token)
        observer = packets.build_observer(prepared, report, now=now(), **selected)
        display = instructions(prepared, observer, relay, packets, now())
        journal = Path(prepared["paths"]["journal"])
        checkpoint(private / "coordinator-merged.json", phase, ctx, prepared, relay.export_state(),
                   display["expires_at"], credentials, wait_plan=display["wait_plan"],
                   observer_selection_digest=digest(observer["selection"]),
                   applied_report_digest=digest(report), journal_sha256=hashlib.sha256(journal.read_bytes()).hexdigest())
        summary(display)
        return {"status": "applied_and_replayed", "native_effect": "applied"}

    observer = prepared.get("observer")
    require(isinstance(observer, dict) and digest(observer["selection"]) == previous.get("observer_selection_digest"),
            "observer_checkpoint_changed")
    report = read_private(private / "merge-result.json")
    require(report.get("status") == "applied" and digest(report) == previous.get("applied_report_digest")
            and hashlib.sha256(Path(prepared["paths"]["journal"]).read_bytes()).hexdigest() == previous.get("journal_sha256"),
            "applied_history_changed")
    receipt = relay.wait(observer["selection"], plan=previous["wait_plan"])
    packets.write_safe(private / "observer-approval-receipt.json", receipt, app_token)
    if protocol is not None:
        relay.recheck_host()
    proof = execution.observe(prepared, observer, receipt, token=app_token, **selected)
    require(proof.get("status") == "passed"
            and all(type(proof.get(key)) is int for key in ("tests_passed", "tests_skipped", "observer_calls"))
            and proof.get("tests_passed") == 1
            and proof.get("tests_skipped") == 0 and proof.get("observer_calls") == 1
            and proof.get("journal_unchanged") is True, "authentic_observer_not_proved")
    packets.write_safe(private / "observer-result.json", proof, app_token)
    checkpoint(private / "coordinator-observed.json", phase, ctx, prepared, relay.export_state(),
               previous["selection_expires_at"], credentials, wait_plan=previous["wait_plan"])
    result = {"status": "positive_trial_completed", "native_effect": "applied", "offline_replay": "passed",
              "observer": "passed", "runner_loss_recovery_verified": False,
              "source": ctx["source"], "run_id": ctx["run_id"], "run_attempt": 1}
    packets.write_safe(private / "trial-report.json", result, app_token)
    return result


def _diagnostic(error, relays):
    fallback = {"component": "unknown", "code": "unclassified_failure"}
    if relays is None:
        return fallback
    try:
        if type(error) is not relays.RelayStopped or type(error.code) is not relays.RelayStopCode:
            return fallback
        expected = {"component": "relay", "code": error.code.value}
        projected = relays.safe_diagnostic(error)
        if type(projected) is dict and projected == expected:
            return expected
    except Exception:
        pass
    return fallback


def failure_report(phase, private, *, error=None, relays=None):
    effect = "not_attempted"
    if phase != "prepare" and private is not None and private.is_dir():
        if (private / "execution-attempt.json").exists():
            effect = "inspect_original_journal"
        for name in ("merge-result.json", "execution-report.json"):
            try:
                if read_private(private / name).get("status") == "applied":
                    effect = "applied"
            except Exception:
                pass
    return {"status": "stopped", "phase": phase, "resend_allowed": False,
            "native_effect": effect, "error_code": "native_positive_trial_stopped",
            "diagnostic": _diagnostic(error, relays)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("authorize", "prepare", "merge", "observe"))
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--core-source", type=Path, required=True)
    args = parser.parse_args()
    phase = args.phase
    try:
        ctx = context()
        private = private_path(args.private, ctx)
        require(args.core_source.is_absolute() and args.core_source.resolve() == args.core_source)
        app_token = os.environ.get("CANARY_APP_TOKEN", "")
        relay_token = os.environ.get("CANARY_RELAY_TOKEN", "")
        require(relay_token and ((phase == "authorize" and not app_token)
                or (phase != "authorize" and re.fullmatch(r"[A-Za-z0-9_.-]{20,1024}", app_token))))
        protocol = load_helper("native_trial_protocol").load(ROOT)
        packets = load_helper("native_trial_packets")
        relays = load_helper("native_trial_relay")
        execution = load_helper("native_trial_execution")
        result = run(phase, private, args.core_source, packets=packets, relays=relays,
                     execution=execution, ctx=ctx, app_token=app_token, relay_token=relay_token,
                     now=lambda: dt.datetime.now(UTC), protocol=protocol)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        # Never emit an exception string, child output, credentials or private state.
        result = failure_report(phase, locals().get("private"), error=error, relays=locals().get("relays"))
        try:
            if "private" in locals() and private.is_dir():
                credentials = tuple(value for value in (locals().get("app_token"), locals().get("relay_token"))
                                    if value)
                create_private(private / "trial-report.json", result, credentials)
        except Exception:
            pass
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
