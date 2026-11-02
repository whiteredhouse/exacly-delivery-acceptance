"""Run one externally selected native merge and its separately selected observation.

The installed Exacly CLI owns effects and durable accounting. This wrapper never
retries an invocation, replaces the journal, or promotes a model lifecycle.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

CORE = "9a5cd90b8d3c3b2acc2a00e7e68e175558025432"
TOKEN = "EXACLY_DELIVERY_MERGE_TOKEN"
MAX_OUTPUT = 2 * 1024 * 1024
MAX_DOCUMENT = 2 * 1024 * 1024
MAX_JOURNAL = 64 * 1024 * 1024
BOUND_TEST_DIGEST = "1fbc93d0635e9faf78c6da77be9e7c6df21b3e34ce62a4a58b9b0f5fbb21313b"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
PINS = {
    "automatic_merge.py": "d8dce24220ba7ad8bb74c6b8bfab8996401c8973744754ae858a25eecfbb706f",
    "github_merge.py": "4108698fedad4c57f6362481f2f271c1aadc0b17e69d7b07abeaefbde6d944b9",
}
TRANSPORT_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "LD_LIBRARY_PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "HOME",
)

# The packet builder uses these same fixed imports before fingerprinting. All
# pytest built-in plugins are loaded before native ELF identity is calculated;
# arbitrary third-party plugins and conftests are never loaded.
BOOTSTRAP = r"""
import atexit, importlib, json, os, runpy, sys
mode, audit_path = sys.argv[1:3]
arguments = sys.argv[3:]
events = [0]
if mode in ("offline", "audit-control"):
    def deny_network(event, args):
        if event.startswith("socket."):
            events[0] += 1
            raise RuntimeError("offline_network_denied")
    sys.addaudithook(deny_network)
    def audit_receipt():
        value = {"audit_hook_installed": True, "network_events": events[0],
                 "canonical_token_present": "EXACLY_DELIVERY_MERGE_TOKEN" in os.environ}
        fd = os.open(audit_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush(); os.fsync(stream.fileno())
    atexit.register(audit_receipt)
if mode == "audit-control":
    import socket
    try:
        socket.socket()
    except RuntimeError as error:
        if str(error) != "offline_network_denied": raise
    else:
        raise RuntimeError("audit_control_failed")
else:
    import pytest
    from _pytest.config import default_plugins
    for name in default_plugins:
        importlib.import_module("_pytest." + name)
    for name in ("_pytest.junitxml", "xml.etree.ElementTree", "exacly.cli", "exacly.automatic_merge_live"):
        importlib.import_module(name)
    if mode == "observe":
        node, junit = arguments
        raise SystemExit(pytest.main(["-q", "-c", os.devnull, "--noconftest", "-p", "no:cacheprovider",
                                     "--junitxml=" + junit, node]))
    if mode not in ("cli", "offline"):
        raise RuntimeError("invalid_native_mode")
    sys.argv = ["exacly", *arguments]
    runpy.run_module("exacly", run_name="__main__", alter_sys=True)
"""


class ExecutionStopped(RuntimeError):
    """Only fixed, credential-free error codes may cross the wrapper boundary."""


def require(value, code="native_trial_validation_failed"):
    if not value:
        raise ExecutionStopped(code)


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "native_trial_invalid_json")
        value[key] = item
    return value


def _decode(data):
    try:
        require(len(data) <= MAX_DOCUMENT, "native_trial_output_bound")
        value = json.loads(
            data,
            object_pairs_hook=_unique,
            parse_constant=lambda _: require(False, "native_trial_invalid_json"),
        )
        require(isinstance(value, dict), "native_trial_invalid_json")
        canonical(value)
        return value
    except ExecutionStopped:
        raise
    except Exception:  # noqa: BLE001 -- never expose candidate bytes in decoding errors
        raise ExecutionStopped("native_trial_invalid_json") from None


def _path(value):
    require(isinstance(value, str), "native_trial_unsafe_path")
    path = Path(value)
    require(
        path.is_absolute() and str(path) == value and ".." not in path.parts,
        "native_trial_unsafe_path",
    )
    return path


def _read(path, maximum=MAX_DOCUMENT):
    path = _path(str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and before.st_mode & 0o077 == 0
            and before.st_size <= maximum,
            "native_trial_unsafe_private_file",
        )
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= maximum, "native_trial_output_bound")
        after = os.fstat(fd)
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            "native_trial_file_changed",
        )
        return b"".join(chunks), before
    finally:
        os.close(fd)


def _json(path):
    return _decode(_read(path)[0])


def _source_hash(path, maximum):
    selected = path.resolve(strict=True)
    fd = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
            "native_trial_runtime_changed",
        )
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        require(
            len(data) == before.st_size <= maximum
            and (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            "native_trial_runtime_changed",
        )
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)


def _write(path, value, token):
    data = canonical(value)
    require(
        len(data) <= MAX_DOCUMENT and (not token or token.encode() not in data),
        "native_trial_unsafe_output",
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _time(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value),
        "native_trial_invalid_time",
    )
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        raise ExecutionStopped("native_trial_invalid_time") from None


def _command(selection):
    fields = [
        ("phase", selection["phase"]),
        ("run", selection["run_id"]),
        ("attempt", selection["run_attempt"]),
        ("challenge", selection["challenge"]),
        ("packet", selection["packet_digest"]),
    ]
    if selection["phase"] == "merge":
        fields.append(("identity", selection["identity_digest"]))
    fields.extend(
        (
            ("issuer", selection["issuer"]),
            ("approval", selection["approval_id"]),
            ("approval-digest", selection["approval_digest"]),
        )
    )
    return "/exacly-native-trial approve " + " ".join(
        key + "=" + str(item) for key, item in fields
    )


def _selected(prepared, selection, receipt, phase):
    keys = {
        "phase",
        "run_id",
        "run_attempt",
        "challenge",
        "packet_digest",
        "issuer",
        "approval_id",
        "approval_digest",
    } | ({"identity_digest"} if phase == "merge" else set())
    require(
        isinstance(selection, dict)
        and set(selection) == keys
        and selection["phase"] == phase,
        "native_trial_selection_invalid",
    )
    require(
        type(selection["run_id"]) is int
        and selection["run_id"] > 0
        and type(selection["run_attempt"]) is int
        and selection["run_attempt"] == 1
        and selection["run_id"] == prepared["context"]["run_id"]
        and selection["run_attempt"] == prepared["context"]["run_attempt"]
        and selection["issuer"] == "p1c2u"
        and isinstance(selection["approval_id"], str)
        and WORD.fullmatch(selection["approval_id"])
        and isinstance(selection["challenge"], str)
        and re.fullmatch(r"[0-9a-f]{64}", selection["challenge"]),
        "native_trial_selection_invalid",
    )
    for name in (
        "packet_digest",
        "approval_digest",
        *(["identity_digest"] if phase == "merge" else []),
    ):
        require(
            isinstance(selection[name], str) and DIGEST.fullmatch(selection[name]),
            "native_trial_selection_invalid",
        )
    receipt_keys = {
        "schema_version",
        "kind",
        "selection",
        "repository_id",
        "pull_request",
        "comment_id",
        "owner_id",
        "owner_login",
        "created_at",
        "updated_at",
        "verified_at",
        "command_digest",
    }
    require(
        isinstance(receipt, dict)
        and set(receipt) == receipt_keys
        and receipt["schema_version"] == "0.1.0"
        and receipt["kind"] == "fixed-pr-owner-selection"
        and receipt["selection"] == selection
        and receipt["repository_id"] == 1442278205
        and receipt["pull_request"] == 5
        and receipt["owner_id"] == 1679024
        and receipt["owner_login"] == "p1c2u"
        and type(receipt["comment_id"]) is int
        and receipt["comment_id"] > 0
        and receipt["created_at"] == receipt["updated_at"]
        and receipt["command_digest"]
        == "sha256:" + hashlib.sha256(_command(selection).encode("ascii")).hexdigest(),
        "native_trial_selection_invalid",
    )
    require(
        _time(receipt["created_at"])
        <= _time(receipt["verified_at"])
        <= dt.datetime.now(dt.UTC),
        "native_trial_selection_invalid",
    )


def _integrity(prepared):
    root = _path(prepared["private_dir"])
    info = root.lstat()
    require(
        root.resolve(strict=True) == root
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_mode & 0o077 == 0,
        "native_trial_unsafe_private_directory",
    )
    proposal, paths = prepared["proposal"], prepared["paths"]
    require(_json(paths["proposal"]) == proposal, "native_trial_packet_changed")
    require(
        digest(proposal) == prepared["selection"]["packet_digest"],
        "native_trial_packet_changed",
    )
    documents = proposal["documents"]
    required = {
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
    }
    require(
        isinstance(documents, dict) and set(documents) == required,
        "native_trial_packet_changed",
    )
    for name, selected in documents.items():
        path = _path(paths[name])
        require(
            path.parent == root
            and selected == {"path": str(path), "digest": digest(_json(path))},
            "native_trial_packet_changed",
        )
    for name, field in (
        ("config", "configuration"),
        ("policy", "policy"),
        ("request", "request"),
        ("payload", "payload"),
        ("approval", "operation_approval"),
        ("identity", "identity_decision"),
        ("mint", "mint_attestation"),
    ):
        require(_json(paths[name]) == proposal[field], "native_trial_packet_changed")
    storage = proposal["storage"]
    journal = _path(paths["journal"])
    _, journal_info = _read(journal, MAX_JOURNAL)
    require(
        storage["private_dir"] == str(root)
        and journal.parent == root
        and storage["journal"]
        == {
            "path": str(journal),
            "id": prepared["journal_id"],
            "device": journal_info.st_dev,
            "inode": journal_info.st_ino,
        },
        "native_trial_journal_changed",
    )
    key_data, key_info = _read(paths["key"])
    key = storage["key"]
    require(
        {name: key[name] for name in ("path", "id")} == proposal["configuration"]["key"]
        and paths["key"] == key["path"]
        and _path(paths["key"]).parent == root
        and set(key) == {"path", "id", "device", "inode", "owner", "mode"}
        and (key["device"], key["inode"], key["owner"], key["mode"])
        == (
            key_info.st_dev,
            key_info.st_ino,
            key_info.st_uid,
            stat.S_IMODE(key_info.st_mode),
        )
        and key_data,
        "native_trial_key_changed",
    )
    core = _path(str(prepared["core_source"]))
    require(
        core.resolve(strict=True) == core
        and proposal["core"]["revision"] == CORE
        and proposal["core"]["source"] == str(core)
        and proposal["core"]["python"] == str(prepared["python"]),
        "native_trial_runtime_changed",
    )
    python = _path(str(prepared["python"]))
    python_digest = "sha256:" + _source_hash(python, 32 * 1024 * 1024)
    require(
        str(python.resolve(strict=True)) == proposal["core"]["python_realpath"]
        and proposal["core"]["python_sha256"] in (python_digest, python_digest[7:]),
        "native_trial_runtime_changed",
    )
    inventory = []
    for path in sorted((core / "python/src/exacly").rglob("*")):
        if "__pycache__" in path.parts:
            continue
        require(not path.is_symlink(), "native_trial_runtime_changed")
        if path.is_file():
            require(len(inventory) < 512, "native_trial_runtime_changed")
            inventory.append(
                {
                    "path": path.relative_to(core).as_posix(),
                    "sha256": _source_hash(path, MAX_DOCUMENT),
                }
            )
    require(
        inventory and digest(inventory) == proposal["core"]["source_inventory_digest"],
        "native_trial_runtime_changed",
    )
    for name, expected in PINS.items():
        require(
            _source_hash(core / "python/src/exacly" / name, MAX_DOCUMENT) == expected,
            "native_trial_runtime_changed",
        )
    require(
        _source_hash(core / "python/tests/test_automatic_merge_live.py", MAX_DOCUMENT)
        == BOUND_TEST_DIGEST,
        "native_trial_runtime_changed",
    )
    require(
        proposal["spec_digest"] == digest(prepared["spec"]),
        "native_trial_packet_changed",
    )
    require(proposal["context"] == prepared["context"], "native_trial_packet_changed")
    return root


def _environment(token=None):
    # Copy selectors without exposing their values. Arbitrary GitHub/relay/App
    # credentials, PYTHONPATH, user plugins and PYTEST_ADDOPTS never enter a child.
    env = {key: os.environ[key] for key in TRANSPORT_ENV if key in os.environ}
    env.update(
        PATH=os.defpath,
        LANG="C.UTF-8",
        LC_ALL="C.UTF-8",
        PYTHONNOUSERSITE="1",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
    )
    if token is not None:
        require(
            isinstance(token, str) and token and "\x00" not in token,
            "native_trial_token_required",
        )
        env[TOKEN] = token
    return env


def _run(command, root, name, *, env, timeout, token):
    """Drain bounded private pipes; unknown exits never expose child diagnostics."""
    descriptors = []
    child = None
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        for suffix in ("stdout", "stderr"):
            fd = os.open(
                root / (name + "." + suffix),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            os.fchmod(fd, 0o600)
            descriptors.append(fd)
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=root,
            env=env,
            start_new_session=True,
            umask=0o077,
        )
        expires = time.monotonic() + timeout
        with selectors.DefaultSelector() as ready:
            for index, pipe in enumerate((child.stdout, child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                ready.register(
                    pipe, selectors.EVENT_READ, (index, ("stdout", "stderr")[index])
                )
            while ready.get_map():
                require(time.monotonic() < expires, "native_trial_child_unresolved")
                for key, _ in ready.select(
                    min(0.1, max(0.0, expires - time.monotonic()))
                ):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        ready.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    index, stream = key.data
                    require(
                        len(captured[stream]) + len(chunk) <= MAX_OUTPUT,
                        "native_trial_output_bound",
                    )
                    captured[stream].extend(chunk)
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(descriptors[index], chunk[offset:])
        code = child.wait(timeout=max(0.01, expires - time.monotonic()))
        require(
            not token or all(token.encode() not in data for data in captured.values()),
            "native_trial_unsafe_child_output",
        )
        return code, bytes(captured["stdout"]), bytes(captured["stderr"])
    except ExecutionStopped:
        raise
    except Exception:  # noqa: BLE001 -- child failures may contain credential bytes
        raise ExecutionStopped("native_trial_child_unresolved") from None
    finally:
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if child is not None:
            for pipe in (child.stdout, child.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        for fd in descriptors:
            os.fsync(fd)
            os.close(fd)


def _arguments(prepared, selection, *, reconcile=False):
    paths = prepared["paths"]
    args = [
        "delivery",
        "reconcile" if reconcile else "merge",
        "--journal",
        paths["journal"],
        "--journal-id",
        prepared["journal_id"],
        "--config",
        paths["config"],
        "--policy",
        paths["policy"],
        "--approval",
        paths["approval"],
        "--approved-approval-digest",
        selection["approval_digest"],
        "--issuer",
        selection["issuer"],
        "--approval-id",
        selection["approval_id"],
    ]
    if reconcile:
        args += ["--operation-key", prepared["proposal"]["request"]["operation_key"]]
    else:
        args += [
            "--request",
            paths["request"],
            "--payload",
            paths["payload"],
            "--apply",
        ]
    return [*args, "--json"]


def _report(value, prepared):
    require(
        value.get("schema_version") == "0.1.0"
        and value.get("profile") == "product-delivery-v1"
        and value.get("kind") == "delivery-report"
        and value.get("status")
        in {
            "applied",
            "rejected",
            "uncertain",
            "blocked",
            "prepared",
            "approval_required",
            "missing",
        }
        and value.get("journal")
        == {"path": prepared["paths"]["journal"], "id": prepared["journal_id"]}
        and value.get("operation_key")
        == prepared["proposal"]["request"]["operation_key"]
        and value.get("request_digest") == digest(prepared["proposal"]["request"])
        and type(value.get("historical")) is bool
        and type(value.get("live_checked")) is bool,
        "native_trial_invalid_report",
    )
    if value["status"] == "applied":
        for name in ("intent", "receipt"):
            doc = value.get(name)
            require(
                isinstance(doc, dict)
                and doc.get("id")
                == digest({k: v for k, v in doc.items() if k != "id"}),
                "native_trial_invalid_report",
            )
    return value


def _cli(prepared, selection, root, name, token, *, reconcile=False):
    command = [
        str(prepared["python"]),
        "-I",
        "-B",
        "-c",
        BOOTSTRAP,
        "cli",
        "-",
        *_arguments(prepared, selection, reconcile=reconcile),
    ]
    timeout = 150 if reconcile else 270
    code, output, _ = _run(
        command, root, name, env=_environment(token), timeout=timeout, token=token
    )
    require(code in (0, 1), "native_trial_child_unresolved")
    report = _report(_decode(output), prepared)
    require(
        (report["status"] == "applied") == (code == 0), "native_trial_invalid_report"
    )
    return report


def execute(prepared, selection_receipt, *, token):
    """Consume one selected invocation; uncertainty permits only one same-scope read."""
    try:
        root = _integrity(prepared)
        selection = prepared["selection"]
        _selected(prepared, selection, selection_receipt, "merge")
        require(
            isinstance(token, str)
            and token
            and prepared["proposal"]["configuration"]["actor"]["token_digest"]
            == "sha256:" + hashlib.sha256(token.encode()).hexdigest(),
            "native_trial_token_mismatch",
        )
        approval = prepared["proposal"]["operation_approval"]
        require(
            selection["approval_digest"] == digest(approval)
            and selection["identity_digest"]
            == digest(prepared["proposal"]["identity_decision"])
            and approval["issuer"] == selection["issuer"]
            and approval["approval_id"] == selection["approval_id"],
            "native_trial_packet_changed",
        )
        _write(
            root / "execution-attempt.json",
            {"kind": "one-native-invocation", "selection_receipt": selection_receipt},
            token,
        )
        report = _cli(prepared, selection, root, "invoke", token)
        _write(root / "invoke-report.json", report, token)
        if report["status"] == "uncertain":
            bounds = prepared["proposal"]["configuration"]["call_limits"]["reconcile"]
            now = dt.datetime.now(dt.UTC)
            if (
                bounds["write_calls"] == 0
                and approval.get("kind") == "delivery-approval"
                and _time(approval["not_before"]) <= now < _time(approval["expires_at"])
            ):
                _integrity(prepared)
                _write(
                    root / "reconcile-attempt.json",
                    {
                        "kind": "one-same-scope-read-reconciliation",
                        "approval_digest": selection["approval_digest"],
                    },
                    token,
                )
                try:
                    report = _cli(
                        prepared, selection, root, "reconcile", token, reconcile=True
                    )
                    _write(root / "reconcile-report.json", report, token)
                except ExecutionStopped:
                    _write(
                        root / "reconcile-unresolved.json",
                        {"status": "uncertain", "resend_allowed": False},
                        token,
                    )
        _write(root / "execution-report.json", report, token)
        return report
    except ExecutionStopped:
        raise
    except Exception:  # noqa: BLE001 -- public boundary emits only fixed safe codes
        raise ExecutionStopped("native_trial_execution_stopped") from None


def _applied(prepared, report):
    require(
        _json(Path(prepared["private_dir"]) / "execution-report.json") == report
        and _report(report, prepared)["status"] == "applied",
        "native_trial_applied_report_required",
    )


def _journal_unchanged(path, original, info):
    current, after = _read(path, MAX_JOURNAL)
    require(
        current == original
        and (after.st_dev, after.st_ino) == (info.st_dev, info.st_ino),
        "native_trial_journal_changed",
    )


def offline_replay(prepared, applied_report, *, token):
    """Replay the actual terminal CLI with the key absent and two network controls."""
    try:
        root = _integrity(prepared)
        _applied(prepared, applied_report)
        _write(
            root / "offline-attempt.json",
            {"kind": "one-offline-terminal-replay"},
            token,
        )
        journal, info = _read(prepared["paths"]["journal"], MAX_JOURNAL)
        tracer = shutil.which("strace", path=os.defpath)
        require(tracer is not None, "native_trial_strace_required")
        env = _environment()
        control = root / "socket-control.trace"
        code, _, _ = _run(
            [
                tracer,
                "-f",
                "-qq",
                "-e",
                "trace=network",
                "-o",
                str(control),
                str(prepared["python"]),
                "-I",
                "-B",
                "-c",
                "import socket; connection=socket.socket(); connection.close()",
            ],
            root,
            "socket-control",
            env=env,
            timeout=15,
            token=token,
        )
        require(code == 0, "native_trial_trace_control_failed")
        # strace creates with the inherited umask; restrict before reading.
        os.chmod(control, 0o600)
        control_data, _ = _read(control)
        require(
            re.search(rb"\bsocket\(", control_data), "native_trial_trace_control_failed"
        )
        audit_control = root / "audit-control.json"
        code, _, _ = _run(
            [
                str(prepared["python"]),
                "-I",
                "-B",
                "-c",
                BOOTSTRAP,
                "audit-control",
                str(audit_control),
            ],
            root,
            "audit-control",
            env=env,
            timeout=15,
            token=token,
        )
        require(
            code == 0
            and _json(audit_control)
            == {
                "audit_hook_installed": True,
                "network_events": 1,
                "canonical_token_present": False,
            },
            "native_trial_audit_control_failed",
        )
        key = _path(prepared["paths"]["key"])
        key_bytes, key_info = _read(key)
        held = root / "offline-key-held"
        require(not held.exists() and not held.is_symlink(), "native_trial_key_changed")
        audit, trace = root / "offline-audit.json", root / "offline.trace"
        os.rename(key, held)
        try:
            require(not key.exists(), "native_trial_key_not_absent")
            command = [
                tracer,
                "-f",
                "-qq",
                "-e",
                "trace=network",
                "-o",
                str(trace),
                str(prepared["python"]),
                "-I",
                "-B",
                "-c",
                BOOTSTRAP,
                "offline",
                str(audit),
                *_arguments(prepared, prepared["selection"]),
            ]
            code, output, _ = _run(
                command, root, "offline", env=env, timeout=60, token=token
            )
        finally:
            unexpected_key = key.exists() or key.is_symlink()
            # Restore the original inode even when replay fails. An unexpected
            # replacement is refused after restoring the selected key entry.
            os.replace(held, key)
            require(not unexpected_key, "native_trial_key_changed")
        restored, restored_info = _read(key)
        require(
            restored == key_bytes
            and (restored_info.st_dev, restored_info.st_ino)
            == (key_info.st_dev, key_info.st_ino),
            "native_trial_key_changed",
        )
        require(code == 0, "native_trial_offline_replay_failed")
        replay = _report(_decode(output), prepared)
        require(
            replay["status"] == "applied"
            and replay["historical"] is True
            and replay["live_checked"] is False
            and replay["receipt"] == applied_report["receipt"]
            and replay["intent"] == applied_report["intent"],
            "native_trial_offline_replay_failed",
        )
        require(
            _json(audit)
            == {
                "audit_hook_installed": True,
                "network_events": 0,
                "canonical_token_present": False,
            },
            "native_trial_offline_network_attempt",
        )
        os.chmod(trace, 0o600)
        trace_bytes, _ = _read(trace)
        require(not trace_bytes.strip(), "native_trial_offline_network_attempt")
        _journal_unchanged(prepared["paths"]["journal"], journal, info)
        proof = {
            "status": "passed",
            "kind": "actual-offline-terminal-replay",
            "receipt_id": replay["receipt"]["id"],
            "journal_unchanged": True,
            "journal_identity_unchanged": True,
            "journal_digest": "sha256:" + hashlib.sha256(journal).hexdigest(),
            "key_absent_during_replay": True,
            "key_original_inode_restored": True,
            "canonical_token_absent": True,
            "python_network_audit_events": 0,
            "network_syscalls": 0,
            "strace_socket_control_detected": True,
            "audit_socket_control_denied": True,
            "provider_writes": 0,
        }
        _write(root / "offline-proof.json", proof, token)
        return proof
    except ExecutionStopped:
        raise
    except Exception:  # noqa: BLE001 -- public boundary emits only fixed safe codes
        raise ExecutionStopped("native_trial_offline_stopped") from None


def observe(prepared, observer, selection_receipt, *, token):
    """Run the actual bound live test exactly once, then verify its retained receipt."""
    try:
        root = _integrity(prepared)
        applied = _json(root / "execution-report.json")
        _applied(prepared, applied)
        selection = observer["selection"]
        _selected(prepared, selection, selection_receipt, "observe")
        original_selection = _json(root / "execution-attempt.json")["selection_receipt"]
        report_time = dt.datetime.fromtimestamp(
            int((root / "execution-report.json").stat().st_mtime), dt.UTC
        )
        require(
            selection["approval_id"] != prepared["selection"]["approval_id"]
            and selection["challenge"] != prepared["selection"]["challenge"]
            and selection_receipt["comment_id"] != original_selection["comment_id"]
            and _time(selection_receipt["created_at"]) >= report_time,
            "native_trial_separate_read_selection_required",
        )
        require(
            _path(observer["paths"]["packet"]).parent == root,
            "native_trial_observer_changed",
        )
        packet = _json(observer["paths"]["packet"])
        require(
            packet == observer["proposal"]["packet"]
            and digest(packet) == selection["packet_digest"]
            and packet["read_approval_pin"]
            == {
                "issuer": selection["issuer"],
                "approval_id": selection["approval_id"],
                "digest": selection["approval_digest"],
            }
            and digest(packet["read_approval"]) == selection["approval_digest"]
            and packet["read_approval"]["kind"] == "delivery-read-recovery"
            and packet["journal"] == applied["journal"]
            and packet["operation_key"] == applied["operation_key"]
            and packet["intent_id"] == applied["intent"]["id"]
            and packet["receipt_id"] == applied["receipt"]["id"]
            and packet["original_configuration"]
            == prepared["proposal"]["configuration"]
            and packet["original_approval_pin"]
            == {
                "issuer": prepared["selection"]["issuer"],
                "approval_id": prepared["selection"]["approval_id"],
                "digest": prepared["selection"]["approval_digest"],
            }
            and packet["maximum_calls"] == 1
            and packet["limits"]["write_calls"] == 0
            and packet["output_bundle"] == observer["paths"]["output_bundle"],
            "native_trial_observer_changed",
        )
        bundle = _path(packet["output_bundle"])
        require(
            bundle.parent == root and not bundle.exists() and not bundle.is_symlink(),
            "native_trial_observer_already_consumed",
        )
        _write(
            root / "observer-attempt.json",
            {
                "kind": "one-authentic-bound-test",
                "selection_receipt": selection_receipt,
            },
            token,
        )
        original, info = _read(prepared["paths"]["journal"], MAX_JOURNAL)
        junit = root / "observer-junit.xml"
        target = str(
            Path(prepared["core_source"]) / "python/tests/test_automatic_merge_live.py"
        )
        target += "::test_live_github_exact_merge_with_original_authority_and_authenticated_marker"
        env = _environment(token)
        env["EXACLY_DELIVERY_MERGE_LIVE_PROOF"] = observer["paths"]["packet"]
        env["EXACLY_DELIVERY_MERGE_LIVE_PROOF_DIGEST"] = selection["packet_digest"]
        command = [
            str(prepared["python"]),
            "-I",
            "-B",
            "-c",
            BOOTSTRAP,
            "observe",
            "-",
            target,
            str(junit),
        ]
        code, _, _ = _run(command, root, "observer", env=env, timeout=150, token=token)
        require(code == 0, "native_trial_authentic_observation_failed")
        os.chmod(junit, 0o600)
        suites = ET.fromstring(_read(junit)[0])
        cases = list(suites.iter("testcase"))
        require(
            len(cases) == 1
            and not any(
                list(case.iter(tag))
                for case in cases
                for tag in ("skipped", "failure", "error")
            ),
            "native_trial_authentic_observation_failed",
        )
        receipt, result = _json(bundle / "receipt.json"), _json(bundle / "result.json")
        require(
            receipt.get("kind") == "delivery-merge-live-observation-receipt"
            and receipt.get("schema_version") == "0.1.0"
            and receipt.get("source") == "github-atomic-merge-default-https-v1"
            and receipt.get("id")
            == digest({k: v for k, v in receipt.items() if k != "id"})
            and receipt.get("accepted") is True
            and receipt.get("provider_writes") == 0
            and receipt.get("original_effect_budget_charged") is False
            and receipt.get("packet_digest") == selection["packet_digest"]
            and receipt.get("observation_id") == packet["observation_id"]
            and receipt.get("limits") == packet["limits"]
            and receipt.get("intent_id") == applied["intent"]["id"]
            and receipt.get("original_receipt_id") == applied["receipt"]["id"]
            and receipt.get("read_approval_digest") == selection["approval_digest"]
            and receipt.get("result_digest") == digest(result),
            "native_trial_invalid_observer_receipt",
        )
        _journal_unchanged(prepared["paths"]["journal"], original, info)
        proof = {
            "status": "passed",
            "kind": "actual-bound-authentic-observation",
            "tests_passed": 1,
            "tests_skipped": 0,
            "observer_calls": 1,
            "journal_unchanged": True,
            "journal_identity_unchanged": True,
            "receipt": receipt,
            "provider_writes": 0,
            "original_effect_budget_charged": False,
        }
        _write(root / "observer-proof.json", proof, token)
        return proof
    except ExecutionStopped:
        raise
    except Exception:  # noqa: BLE001 -- public boundary emits only fixed safe codes
        raise ExecutionStopped("native_trial_observer_stopped") from None
