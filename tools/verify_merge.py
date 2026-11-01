"""Read-only verification of one independently selected canary merge.

Run this trusted copy with python3 -I -B. Candidate Git objects are data only.
An unsigned report is not a GitHub check, independent approval or merge grant.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

SHA = re.compile(r"[0-9a-f]{40}\Z")
PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_FILES = 64
MAX_FILE_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_COMMAND_BYTES = 256 * 1024
MAX_GIT_CALLS = 96
TIMEOUT_SECONDS = 20
CANARY = "canary.txt"
APP = "canary_app.py"
TESTS = "tests/test_canary_app.py"
SELF = "tools/verify_merge.py"
FIXED_CASES = (
    "test_empty_invoice_has_no_amount_due",
    "test_mixed_invoice_matches_the_hand_calculated_total",
    "test_free_items_do_not_change_the_amount_due",
    "test_large_invoice_keeps_exact_integer_cents",
    "test_line_items_can_be_consumed_once",
    "test_invalid_prices_are_rejected",
    "test_invalid_quantities_are_rejected",
)

# Only previously measured trusted bytes enter these two fixed module names.
# No path from the candidate repository is added to sys.path or imported.
RUN_TESTS = r"""
import base64, collections.abc, json, sys, types, unittest
payload = json.loads(base64.b64decode(sys.argv[1], validate=True))
app = types.ModuleType('canary_app')
sys.modules['canary_app'] = app
exec(compile(base64.b64decode(payload['app'], validate=True), '<trusted:canary_app.py>', 'exec'), app.__dict__)
tests = types.ModuleType('trusted_canary_tests')
exec(compile(base64.b64decode(payload['tests'], validate=True), '<trusted:tests/test_canary_app.py>', 'exec'), tests.__dict__)
suite = unittest.TestSuite(tests.InvoiceTotalTests(name) for name in payload['cases'])
result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() and result.testsRun == 7 and not result.skipped and not result.expectedFailures else 1)
"""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def safe_path(value: object) -> str:
    require(isinstance(value, str), "invalid inventory path")
    require(bool(re.fullmatch(r"[A-Za-z0-9._/-]{1,240}", value)), "invalid inventory path")
    require(all(part not in ("", ".", "..", ".git") for part in value.split("/")), "unsafe inventory path")
    return value


def safe_ref(value: str) -> str:
    require(isinstance(value, str), "invalid branch ref")
    require(bool(re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,150}", value)), "invalid branch ref")
    require(not any(text in value for text in ("..", "//", "@{", ".lock")), "unsafe branch ref")
    require(not value.endswith(("/", ".")), "unsafe branch ref")
    return value


def open_directory(path: Path) -> int:
    """Open a canonical directory without following any path-component link."""
    require(path.is_absolute() and ".." not in path.parts, "absolute canonical directory required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_file(root: Path, relative: str, limit: int) -> bytes:
    descriptor = open_directory(root)
    try:
        parts = safe_path(relative).split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            info = os.fstat(file)
            require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o111, "regular nonexecutable source required")
            require(info.st_size <= limit, "source file exceeds byte bound")
            result = bytearray()
            while True:
                chunk = os.read(file, min(65536, limit + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                require(len(result) <= limit, "source file exceeds byte bound")
            return bytes(result)
        finally:
            os.close(file)
    finally:
        os.close(descriptor)


def command(args: list[str], *, environment: dict[str, str], deadline: float) -> tuple[bytes, bytes]:
    """Bound actual process time and combined output without a shell or hooks."""
    require(deadline > time.monotonic(), "verification deadline expired")
    process = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, start_new_session=True, close_fds=True,
    )
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "verification deadline expired")
                events = selector.select(min(remaining, 0.1))
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(sum(map(len, output.values())) <= MAX_COMMAND_BYTES, "process output exceeds byte bound")
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(process.returncode == 0, "bounded subprocess rejected the selected input")
        return bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
        process.stdout.close()
        process.stderr.close()


class Git:
    def __init__(self, repository: Path, deadline: float):
        descriptor = open_directory(repository)
        os.close(descriptor)
        self.repository, self.deadline = repository, deadline
        self.executable = shutil.which("git", path=os.defpath)
        require(self.executable is not None, "system Git is unavailable")
        self.calls = 0
        self.cache: dict[tuple[str, str], bytes] = {}
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.environment.update({
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_GRAFT_FILE": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "",
        })

    def read(self, *arguments: str) -> bytes:
        self.calls += 1
        require(self.calls <= MAX_GIT_CALLS, "Git read budget exhausted")
        result, _ = command([
            self.executable, "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull,
            "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-C", str(self.repository), *arguments,
        ], environment=self.environment, deadline=min(self.deadline, time.monotonic() + 3))
        return result

    def ref(self, name: str) -> str:
        result = self.read("show-ref", "--verify", "--hash", safe_ref(name)).decode("ascii").strip()
        require(bool(SHA.fullmatch(result)), "branch ref is not an exact commit identity")
        return result

    def object(self, kind: str, oid: str, limit: int = MAX_FILE_BYTES) -> bytes:
        require(bool(SHA.fullmatch(oid)), "invalid Git object identity")
        key = (kind, oid)
        if key not in self.cache:
            data = self.read("cat-file", kind, oid)
            require(len(data) <= limit, "Git object exceeds byte bound")
            actual = hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()
            require(actual == oid, "Git object bytes differ from selected identity")
            self.cache[key] = data
        return self.cache[key]

    def commit(self, oid: str) -> tuple[str, list[str]]:
        headers = self.object("commit", oid, 16384).split(b"\n\n", 1)[0].splitlines()
        trees = [line[5:].decode("ascii") for line in headers if line.startswith(b"tree ")]
        parents = [line[7:].decode("ascii") for line in headers if line.startswith(b"parent ")]
        require(len(trees) == 1 and bool(SHA.fullmatch(trees[0])), "invalid commit tree identity")
        require(all(SHA.fullmatch(parent) for parent in parents), "invalid commit parent identity")
        return trees[0], parents

    def inventory(self, tree: str) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        directories = 0

        def visit(oid: str, prefix: str, depth: int) -> None:
            nonlocal directories
            directories += 1
            require(depth <= 8 and directories <= 16, "Git tree exceeds directory bound")
            data = self.object("tree", oid, 32768)
            offset = 0
            while offset < len(data):
                separator, ending = data.index(b" ", offset), data.index(b"\0", offset)
                require(separator < ending and ending + 21 <= len(data), "malformed Git tree")
                mode = data[offset:separator].decode("ascii")
                name = data[separator + 1:ending].decode("ascii")
                require("/" not in name, "malformed Git tree name")
                path = safe_path(prefix + name)
                child = data[ending + 1:ending + 21].hex()
                offset = ending + 21
                if mode == "40000":
                    visit(child, path + "/", depth + 1)
                else:
                    require(mode == "100644", "Git links, submodules and executable modes are unsupported")
                    require(path not in result, "duplicate Git tree path")
                    require(len(result) < MAX_FILES, "Git file inventory exceeds bound")
                    contents = self.object("blob", child)
                    result[path] = {"mode": mode, "blob": child, "sha256": digest(contents)}

        visit(tree, "", 0)
        return dict(sorted(result.items()))


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate manifest key")
        result[key] = value
    return result


def manifest(path: Path, pin: str, repository: Path) -> dict:
    require(path.is_absolute() and ".." not in path.parts, "absolute external manifest path required")
    require(path != repository and repository not in path.parents, "manifest must be outside candidate repository")
    require(bool(PIN.fullmatch(pin)), "independently selected manifest SHA256 pin required")
    data = read_file(path.parent, path.name, MAX_MANIFEST_BYTES)
    require(digest(data) == pin, "manifest differs from independently selected pin")
    value = json.loads(data, object_pairs_hook=unique_object)
    require(isinstance(value, dict) and set(value) == {"kind", "schema_version", "base_ref", "base_revision", "files"}, "invalid manifest fields")
    require(value["kind"] == "exacly-canary-trusted-base" and value["schema_version"] == "1", "unsupported manifest kind")
    require(isinstance(value["base_revision"], str) and bool(SHA.fullmatch(value["base_revision"])), "invalid manifest base")
    safe_ref(value["base_ref"])
    files = value["files"]
    require(isinstance(files, dict) and 0 < len(files) <= MAX_FILES, "invalid manifest inventory")
    for path, item in files.items():
        safe_path(path)
        require(isinstance(item, dict) and set(item) == {"mode", "blob", "sha256"}, "invalid manifest file fields")
        require(item["mode"] == "100644" and isinstance(item["blob"], str) and bool(SHA.fullmatch(item["blob"])), "invalid manifest file identity")
        require(isinstance(item["sha256"], str) and bool(PIN.fullmatch(item["sha256"])), "invalid manifest source digest")
    require({CANARY, APP, TESTS, SELF, "README.md", ".github/workflows/ci.yml"} <= set(files), "required trusted source is absent")
    return value


def trusted_sources(root: Path, inventory: dict[str, dict[str, str]]) -> dict[str, bytes]:
    actual = set()
    entries = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            entries += 1
            require(entries <= 128, "trusted source inventory exceeds bound")
            require(not (Path(directory) / name).is_symlink(), "trusted source links are unsupported")
        directories[:] = [name for name in directories if name != "__pycache__" and not (Path(directory) == root and name == ".git")]
        for name in files:
            if Path(directory) == root and name == ".git":
                continue
            actual.add(safe_path(str((Path(directory) / name).relative_to(root))))
    require(actual == set(inventory), "trusted source has missing or unexpected files")
    contents = {}
    for path, item in inventory.items():
        data = read_file(root, path, MAX_FILE_BYTES)
        require(digest(data) == item["sha256"], "trusted source bytes differ from reviewed manifest")
        contents[path] = data
    return contents


def canary_label(data: bytes) -> str:
    require(len(data) <= 40, "canary label exceeds byte bound")
    match = re.fullmatch(rb"canary=([a-z][a-z0-9-]{0,31})\n", data)
    require(match is not None, "canary data must be one bounded ASCII label")
    return match[1].decode("ascii")


def verify(arguments: argparse.Namespace) -> dict:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    repository = Path(arguments.repository).absolute()
    root = Path(__file__).absolute().parent.parent
    require(repository != root and repository not in root.parents and root not in repository.parents, "trusted source and candidate repository must be separate directories")
    require(all(SHA.fullmatch(value) for value in (arguments.base, arguments.head, arguments.merge, arguments.tree)), "exact B/H/M/tree identities required")
    require(len({arguments.base, arguments.head, arguments.merge}) == 3, "B/H/M must be distinct")
    selected = manifest(Path(arguments.manifest), arguments.manifest_sha256, repository)
    require(selected["base_revision"] == arguments.base and selected["base_ref"] == safe_ref(arguments.base_ref), "base differs from reviewed manifest")
    require(safe_ref(arguments.head_ref) != arguments.base_ref, "head and base refs must differ")
    git = Git(repository, deadline)
    require(git.ref(arguments.base_ref) == arguments.base, "current local base ref changed")
    require(git.ref(arguments.head_ref) == arguments.head, "current local head ref changed")
    base_tree, _ = git.commit(arguments.base)
    head_tree, _ = git.commit(arguments.head)
    merge_tree, parents = git.commit(arguments.merge)
    require(parents == [arguments.base, arguments.head], "merge parents differ from exact ordered B/H")
    require(merge_tree == arguments.tree, "merge tree differs from selected tree")
    base = git.inventory(base_tree)
    require(base == selected["files"], "base inventory differs from reviewed manifest")
    sources = trusted_sources(root, base)
    head, merged = git.inventory(head_tree), git.inventory(merge_tree)
    for candidate in (head, merged):
        require(set(candidate) == set(base), "candidate has missing or unexpected files")
        require(all(candidate[path] == base[path] for path in base if path != CANARY), "candidate changed protected source, tests, workflow or verifier")
    base_data = git.object("blob", base[CANARY]["blob"])
    head_data = git.object("blob", head[CANARY]["blob"])
    merge_data = git.object("blob", merged[CANARY]["blob"])
    canary_label(base_data)
    label = canary_label(merge_data)
    require(head_data == merge_data and merge_data != base_data, "only one matching head/merge canary delta is permitted")
    payload = {"app": base64.b64encode(sources[APP]).decode(), "tests": base64.b64encode(sources[TESTS]).decode(), "cases": FIXED_CASES}
    encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    require(len(encoded) <= 32768, "fixed trusted test source exceeds bound")
    stdout, stderr = command([sys.executable, "-I", "-B", "-c", RUN_TESTS, encoded], environment={"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}, deadline=min(deadline, time.monotonic() + 5))
    require(git.ref(arguments.base_ref) == arguments.base and git.ref(arguments.head_ref) == arguments.head, "local refs changed during verification")
    require(time.monotonic() < deadline, "verification deadline expired")
    return {
        "kind": "exacly-canary-local-merge-verification", "status": "verified",
        "manifest_sha256": arguments.manifest_sha256,
        "base_ref": arguments.base_ref, "head_ref": arguments.head_ref,
        "base_revision": arguments.base, "head_revision": arguments.head,
        "merge_revision": arguments.merge, "merge_tree": merge_tree, "merge_parents": parents,
        "trusted_file_sha256": {path: item["sha256"] for path, item in base.items()},
        "canary_delta": {"path": CANARY, "label": label, "before_blob": base[CANARY]["blob"], "after_blob": merged[CANARY]["blob"]},
        "trusted_tests": {"cases": 7, "result": "passed", "execution": "captured trusted base bytes in fixed isolated Python", "runner_sha256": digest(RUN_TESTS.encode()), "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "output": stdout.decode("utf-8"), "python_version": sys.version},
        "candidate_code_executed": False, "provider_writes": 0, "git_reads": git.calls,
        "limitations": ["Unsigned local content report; no GitHub check or approval is published.", "Tests executed the reviewed trusted base; candidate H/M code and inventory were compared as data.", "Fresh remote identities, server protection, reviews and authority require the separately approved producer."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "manifest", "manifest-sha256", "base-ref", "head-ref", "base", "head", "merge", "tree"):
        parser.add_argument("--" + name, required=True)
    arguments = parser.parse_args()
    try:
        result = verify(arguments)
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        # Do not echo raw Git stderr, credentials, source contents or arbitrary exception data.
        reason = str(error) if isinstance(error, ValueError) else "bounded local verification could not complete"
        print(json.dumps({"kind": "exacly-canary-local-merge-verification", "status": "rejected", "reason": reason}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
