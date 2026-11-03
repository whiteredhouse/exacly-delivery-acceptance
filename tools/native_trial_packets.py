"""Propose one fixed native trial's real private inputs; never select their authority.

All provider activity and owner acknowledgements belong to separate trusted
components. These builders initialize original storage and produce reviewable
drafts, including closed native decision documents which remain unapproved.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

CORE_REVISION = "9a5cd90b8d3c3b2acc2a00e7e68e175558025432"
SPEC_DIGEST = "sha256:7fe9884fe053ab7804e0f53ce0c121d36a8860d9ffd8f13ca8f284ecd5c88905"
NATIVE_PINS = {
    "automatic_merge.py": "d8dce24220ba7ad8bb74c6b8bfab8996401c8973744754ae858a25eecfbb706f",
    "github_merge.py": "4108698fedad4c57f6362481f2f271c1aadc0b17e69d7b07abeaefbde6d944b9",
}
PERMISSIONS = {"contents": "write", "administration": "read", "checks": "read",
               "metadata": "read", "pull_requests": "read", "statuses": "read"}
ACTION = "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
MAX_DOCUMENT = 1024 * 1024
SAFE_NAMES = frozenset(("merge-proposal.json", "observer-proposal.json", "merge-approval-receipt.json",
                        "observer-approval-receipt.json", "merge-result.json", "offline-replay.json",
                        "observer-result.json", "trial-report.json", "merge-approval-instructions.json",
                        "observer-approval-instructions.json"))
PRIVATE_NAMES = frozenset(("merge-config.json", "merge-policy.json", "merge-request.json", "merge-payload.json",
                           "merge-approval.json", "mint-identity-proposal.json", "mint-attestation.json",
                           "objective.json", "limits.json", "native-limits.json", "merge-proposal.json",
                           "prepared-state.json", "observer-packet.json", "observer-proposal.json", "observer-state.json",
                           "supplemental-allocation.json"))
DOCUMENT_KEYS = ("config", "policy", "request", "payload", "approval", "identity", "mint", "objective", "limits", "native_limits")
PROPOSAL_KEYS = dict(zip(DOCUMENT_KEYS, ("configuration", "policy", "request", "payload", "operation_approval",
                                        "identity_decision", "mint_attestation", "objective", "limits", "native_limits")))
PROPOSAL_KEYS["allocation"] = "supplemental_allocation"


class Refused(ValueError):
    """Deliberately fixed diagnostics; provider/credential contents never appear."""


def require(value):
    if not value:
        raise Refused("native trial packet preparation refused")


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(_encoded(value)).hexdigest()


def _protocol():
    path = Path(__file__).resolve().with_name("native_trial_protocol.py")
    require(path.resolve() == path)
    loaded = importlib.util.spec_from_file_location("native_trial_protocol", path)
    require(loaded is not None and loaded.loader is not None)
    module = importlib.util.module_from_spec(loaded)
    loaded.loader.exec_module(module)
    return module


def _settings(profile):
    if profile is None:
        return {"core_revision": CORE_REVISION, "spec_digest": SPEC_DIGEST, "native_pins": NATIVE_PINS}
    selected = _protocol().load(Path(__file__).resolve().parent.parent)["profile"]
    require(type(profile) is dict and profile == selected)
    return copy.deepcopy(selected)


def _allocation(allocation, *, profile, spec, context):
    if profile is None:
        require(allocation is None)
        return None
    settings = _settings(profile)
    try:
        checked = _protocol().validate_allocation(allocation, profile=settings, spec=spec, context=context)
    except ValueError:
        raise Refused("native trial supplemental allocation refused") from None
    require(type(checked) is dict and checked == allocation)
    return copy.deepcopy(checked)


def _check_allocation(prepared, profile):
    proposal = prepared["proposal"]
    if profile is None:
        require(not ({"runtime_profile", "supplemental_allocation"} & set(prepared))
                and not ({"runtime_profile", "supplemental_allocation"} & set(proposal)))
        return
    settings = _settings(profile)
    require(prepared.get("runtime_profile") == proposal.get("runtime_profile") == settings)
    checked = _allocation(prepared.get("supplemental_allocation"), profile=profile,
                          spec=prepared["spec"], context=prepared["context"])
    require(proposal.get("supplemental_allocation") == checked)


def _utc(now):
    require(type(now) is dt.datetime and now.utcoffset() == dt.timedelta(0))
    return now.isoformat().replace("+00:00", "Z")


def _path(path):
    require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts
            and path.parent.resolve() == path.parent)
    return path


def _parent(path):
    _path(path)
    info = path.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _write(path, value, token, *, safe=False):
    require(path.name in (SAFE_NAMES if safe else PRIVATE_NAMES))
    content = _encoded(value)
    require(len(content) <= MAX_DOCUMENT and isinstance(token, str) and token and token.encode() not in content)
    directory = _parent(path)
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            count = os.write(descriptor, content[offset:])
            require(count > 0)
            offset += count
        os.fsync(descriptor)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def write_safe(path, value, token):
    """Create one private, allowlisted safe artifact without publishing secrets."""
    _write(path, value, token, safe=True)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_nlink, info.st_uid)


def _read(path):
    directory = _parent(path)
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_DOCUMENT)
        content = os.read(descriptor, MAX_DOCUMENT + 1)
        require(len(content) == info.st_size and _identity(os.fstat(descriptor)) == _identity(info))
        value = json.loads(content, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused()))
        require(_encoded(value) == content)
        return value
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _git(source, *arguments):
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull}
    result = subprocess.run(["git", "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull,
                             "-c", "core.fsmonitor=false", "-C", str(source), *arguments],
                            env=environment, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=10, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 4 * MAX_DOCUMENT)
    return result.stdout


def _source_bytes(path):
    require(path.resolve() == path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 2 * MAX_DOCUMENT)
        content = os.read(descriptor, 2 * MAX_DOCUMENT + 1)
        require(len(content) == info.st_size and _identity(os.fstat(descriptor)) == _identity(info))
        return content
    finally:
        os.close(descriptor)


def _load_native(source, *, profile=None):
    """Verify the exact package checkout before importing any of its code."""
    require(isinstance(source, Path) and source.is_absolute() and source.resolve() == source)
    settings = _settings(profile)
    revision, pins = settings["core_revision"], settings["native_pins"]
    require(_git(source, "rev-parse", "--verify", "HEAD").strip().decode("ascii") == revision)
    package = source / "python/src/exacly"
    inventory = []
    expected_paths = set()
    for line in _git(source, "ls-tree", "-r", "--full-tree", revision, "--", "python/src/exacly").decode().splitlines():
        metadata, relative = line.split("\t", 1)
        mode, kind, oid = metadata.split()
        require(kind == "blob" and mode in ("100644", "100755") and re.fullmatch(r"[0-9a-f]{40}", oid))
        path = source / relative
        content = _source_bytes(path)
        require(hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest() == oid)
        expected_paths.add(path)
        inventory.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest()})
    actual_paths = {path for path in package.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
    require(expected_paths and actual_paths == expected_paths)
    for name, expected in pins.items():
        require(hashlib.sha256(_source_bytes(package / name)).hexdigest() == expected)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "python/src"))
    # Keep this exact preload synchronized with native_trial_execution.py. Native
    # fingerprints include mapped ELF objects, even when no provider is called.
    importlib.import_module("pytest")
    defaults = importlib.import_module("_pytest.config").default_plugins
    for name in defaults:
        importlib.import_module("_pytest." + name)
    for name in ("_pytest.junitxml", "xml.etree.ElementTree", "exacly.cli", "exacly.automatic_merge_live"):
        importlib.import_module(name)
    modules = {}
    for name in ("automatic_merge", "delivery_automation", "delivery_store", "delivery_key", "github_merge", "automatic_merge_live"):
        module = importlib.import_module("exacly." + name)
        require(Path(module.__file__).resolve() == package / (name + ".py"))
        modules[name] = module
    return SimpleNamespace(**modules, source_inventory_digest=digest(inventory))


def _inputs(spec, context, token, installation_id, now, *, profile=None):
    require(isinstance(spec, dict) and digest(spec) == _settings(profile)["spec_digest"])
    require(isinstance(context, dict) and set(context) == {"repository", "repository_id", "source", "run_id", "run_attempt", "workflow_ref", "ref", "job"})
    require(context["repository"] == spec["repository"]["full_name"] and type(context["repository_id"]) is int
            and context["repository_id"] == spec["repository"]["id"])
    require(isinstance(context["source"], str) and re.fullmatch(r"[0-9a-f]{40}", context["source"]))
    require(type(context["run_id"]) is int and context["run_id"] > 0
            and type(context["run_attempt"]) is int and context["run_attempt"] == 1)
    require(context["ref"] == "refs/heads/codex/preflight-diagnostics" and context["job"] == "native-positive-trial"
            and context["workflow_ref"] == context["repository"] + "/.github/workflows/app-bootstrap.yml@refs/heads/codex/preflight-diagnostics")
    require(type(installation_id) is int and installation_id == spec["installation_id"])
    require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_.-]{20,1024}", token))
    _utc(now)


def _make_private(path):
    _path(path)
    require(path.parent.is_dir())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        directory = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(directory, 0o700)
            os.fsync(directory)
            os.fsync(parent)
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def _selection(phase, context, packet, approval, *, identity=None):
    selected = {"phase": phase, "run_id": context["run_id"], "run_attempt": context["run_attempt"],
                "challenge": os.urandom(32).hex(), "packet_digest": digest(packet), "issuer": "p1c2u",
                "approval_id": approval["approval_id"], "approval_digest": digest(approval)}
    if identity is not None:
        selected["identity_digest"] = digest(identity)
    return selected


def prepare(private_dir, spec, context, core_source, token, installation_id, *, now, profile=None, allocation=None):
    """Create actual storage and complete drafts, with no provider or approval activity."""
    _inputs(spec, context, token, installation_id, now, profile=profile)
    allocation = _allocation(allocation, profile=profile, spec=spec, context=context)
    settings = _settings(profile)
    native = _load_native(core_source, profile=profile)
    spec, context = copy.deepcopy(spec), copy.deepcopy(context)
    require(core_source not in private_dir.parents and private_dir != core_source
            and Path(__file__).resolve().parent.parent not in private_dir.parents)
    _make_private(private_dir)
    names = {"journal": "delivery.sqlite3", "key": "merge.key", "config": "merge-config.json",
             "policy": "merge-policy.json", "request": "merge-request.json", "payload": "merge-payload.json",
             "approval": "merge-approval.json", "identity": "mint-identity-proposal.json", "mint": "mint-attestation.json",
             "objective": "objective.json", "limits": "limits.json", "native_limits": "native-limits.json", "proposal": "merge-proposal.json"}
    if profile is not None:
        names["allocation"] = "supplemental-allocation.json"
    paths = {key: str(private_dir / name) for key, name in names.items()}
    key_id = native.delivery_key.initialize(Path(paths["key"]))
    native_limits = copy.deepcopy(spec["call_limits"]["invoke"])
    initialized = native.delivery_store.initialize(Path(paths["journal"]), objective=spec["objective"],
                                                  limits=spec["limits"], native_limits=native_limits)
    current = Path(paths["journal"]).stat()
    key_info = Path(paths["key"]).lstat()
    journal = {"path": paths["journal"], "id": initialized["id"]}
    end = now + dt.timedelta(seconds=spec["local_grant_seconds"])
    mint = {
        "schema_version": "0.1.0", "kind": "trusted-github-actions-mint-run-attestation",
        "basis": "reviewed workflow/action inputs and observed installation-id output; not a retained mint API response",
        "context": context, "repository": spec["repository"], "exacly_source_commit": settings["core_revision"],
        "mint_action": ACTION, "app_id": spec["app_id"], "installation_id": installation_id,
        "requested_repository_ids": [spec["repository"]["id"]], "requested_permissions": PERMISSIONS,
        "token_digest": "sha256:" + hashlib.sha256(token.encode()).hexdigest(), "attested_at": _utc(now),
        "local_use_lease_seconds": spec["local_grant_seconds"], "provider_mint_response_retained": False,
        "provider_expiry_verified": False, "independent_mint_approval": False, "merge_authority": False,
    }
    candidate = {"app_id": spec["app_id"], "installation_id": installation_id, "token_digest": mint["token_digest"],
                 "credential_kind": "github-app-installation-grant-v1",
                 "grant": {"schema_version": "0.2.0", "repository_ids": [spec["repository"]["id"]],
                           "permissions": PERMISSIONS, "not_before": _utc(now), "not_after": _utc(end),
                           "mint_provenance_digest": digest(mint)}}
    native.automatic_merge.validate_installation_grant_time(candidate, now=now)
    identity = {"schema_version": "0.1.0", "kind": "proposed-native-mint-identity-decision", "status": "proposed",
                "issuer": "p1c2u", "approval_id": "native-positive-identity-" + str(context["run_id"]) + "-1",
                "context": context, "actor_candidate": candidate, "mint_attestation_digest": digest(mint),
                "independent_approval_verified": False, "merge_authority": False}
    configuration = {"schema_version": "0.1.0", "profile": "github-atomic-merge-v1", "repository": spec["repository"],
                     "token_environment": "EXACLY_DELIVERY_MERGE_TOKEN",
                     "actor": {**candidate, "identity_approval_digest": digest(identity)},
                     "key": {"path": paths["key"], "id": key_id}, "call_limits": spec["call_limits"]}
    configuration = native.automatic_merge.validate_configuration(configuration)
    policy = native.automatic_merge.validate_policy(spec["policy"])
    payload = {"schema_version": "0.1.0", "profile": "github-atomic-merge-v1", "head_ref": spec["head_ref"],
               "merge_revision": spec["merge_revision"], "merge_tree": spec["merge_tree"],
               "marker_ref": "refs/tags/exacly-delivery-operations/" + spec["operation_key"].removeprefix("sha256:"),
               "operation_profile_digest": native.automatic_merge.operation_profile_digest(configuration, policy),
               "contract_files": {category: copy.deepcopy(spec["protected_files"]) for category in policy["contract"]}}
    repository = {key: spec["repository"][key] for key in ("id", "full_name")}
    request = {"schema_version": "0.1.0", "profile": "product-delivery-v1", "kind": "delivery-request",
               "objective": spec["objective"], "operation_key": spec["operation_key"], "stage": "merge",
               "subject": {"repository": repository, "head_repository": repository, "pull_request": spec["pull_request"],
                           "head_revision": spec["head_revision"], "base_revision": spec["base_revision"],
                           "base_ref": spec["base_ref"], "method": "merge"}, "native_payload_digest": digest(payload)}
    request = native.delivery_automation.validate_request(request)
    native.automatic_merge.validate_payload(request, payload, configuration, policy)
    approval = {"schema_version": "0.1.0", "profile": "product-delivery-v1", "kind": "delivery-approval",
                "issuer": "p1c2u", "approval_id": "native-positive-merge-" + str(context["run_id"]) + "-1",
                "objective": spec["objective"], "stage": "merge", "operation_key": spec["operation_key"],
                "request_digest": digest(request), "subject_digest": digest(request["subject"]),
                "resource_key": native.delivery_automation.resource_key(request), "policy_digest": digest(policy),
                "adapter": {"id": "github-atomic-merge-v1", "configuration_digest": native.automatic_merge.configuration_digest(configuration, policy)},
                "contract": policy["contract"], "journal": journal, "limits": spec["limits"],
                "not_before": _utc(now), "expires_at": _utc(end)}
    # Closed shape validation is advisory. No ApprovalPin is fabricated here.
    importlib.import_module("jsonschema").validate(approval, native.delivery_automation.APPROVAL_SCHEMA)
    documents = dict(zip(DOCUMENT_KEYS, (configuration, policy, request, payload, approval, identity, mint,
                                       spec["objective"], spec["limits"], native_limits)))
    if profile is not None:
        documents["allocation"] = allocation
    for key, value in documents.items():
        _write(Path(paths[key]), value, token)
    python = str(Path(sys.executable).absolute())
    proposal = {
        "schema_version": "0.1.0", "kind": "proposed-native-positive-trial", "status": "proposed",
        "authority_granted": False, "independent_mint_approval": False, "pr_readiness_verified": False,
        "merge_authority": False, "context": context, "spec_digest": digest(spec), "retention": spec["retention"],
        "core": {"revision": settings["core_revision"], "source": str(core_source), "python": python,
                 "python_realpath": str(Path(python).resolve()),
                 "python_sha256": hashlib.sha256(Path(python).read_bytes()).hexdigest(),
                 "source_inventory_digest": native.source_inventory_digest, "source_pins": settings["native_pins"]},
        "storage": {"private_dir": str(private_dir), "journal": {**journal, "device": current.st_dev, "inode": current.st_ino},
                    "key": {**configuration["key"], "device": key_info.st_dev, "inode": key_info.st_ino,
                            "owner": key_info.st_uid, "mode": stat.S_IMODE(key_info.st_mode)}},
        "actor_candidate": candidate,
        **{PROPOSAL_KEYS[key]: value for key, value in documents.items()},
        "documents": {key: {"path": paths[key], "digest": digest(value)} for key, value in documents.items()},
    }
    if profile is not None:
        proposal["runtime_profile"] = settings
    _write(Path(paths["proposal"]), proposal, token)
    prepared = {"proposal": proposal, "selection": _selection("merge", context, proposal, approval, identity=identity),
                "paths": paths, "journal_id": initialized["id"], "core_source": str(core_source), "context": context,
                "spec": spec, "private_dir": str(private_dir), "python": python, "_token": token}
    if profile is not None:
        prepared.update(runtime_profile=copy.deepcopy(settings), supplemental_allocation=copy.deepcopy(allocation))
    return prepared


def _check_prepared(prepared, token, native, *, profile=None):
    _check_allocation(prepared, profile)
    settings = _settings(profile)
    proposal, paths = prepared["proposal"], prepared["paths"]
    require(proposal["schema_version"] == "0.1.0" and proposal["kind"] == "proposed-native-positive-trial"
            and proposal["status"] == "proposed" and all(proposal[name] is False for name in
                ("authority_granted", "independent_mint_approval", "pr_readiness_verified", "merge_authority")))
    _inputs(prepared["spec"], prepared["context"], token, prepared["spec"]["installation_id"],
            dt.datetime.fromisoformat(proposal["configuration"]["actor"]["grant"]["not_before"]),
            profile=profile)
    require(proposal["context"] == prepared["context"] and proposal["spec_digest"] == digest(prepared["spec"]))
    require(proposal["core"]["source"] == prepared["core_source"] and proposal["core"]["revision"] == settings["core_revision"]
            and proposal["core"]["source_inventory_digest"] == native.source_inventory_digest)
    require(proposal["core"]["source_pins"] == settings["native_pins"])
    require(prepared["python"] == str(Path(sys.executable).absolute()) == proposal["core"]["python"]
            and str(Path(prepared["python"]).resolve()) == proposal["core"]["python_realpath"]
            and hashlib.sha256(Path(prepared["python"]).read_bytes()).hexdigest() == proposal["core"]["python_sha256"])
    require(proposal["configuration"]["actor"]["token_digest"] == "sha256:" + hashlib.sha256(token.encode()).hexdigest())
    selection = prepared["selection"]
    require(selection["phase"] == "merge" and selection["packet_digest"] == digest(proposal)
            and selection["identity_digest"] == digest(proposal["identity_decision"])
            and selection["approval_digest"] == digest(proposal["operation_approval"])
            and selection["issuer"] == "p1c2u" and selection["approval_id"] == proposal["operation_approval"]["approval_id"]
            and selection["run_id"] == prepared["context"]["run_id"] and selection["run_attempt"] == 1
            and re.fullmatch(r"[0-9a-f]{64}", selection["challenge"]))
    private = Path(prepared["private_dir"])
    document_keys = DOCUMENT_KEYS + (("allocation",) if profile is not None else ())
    require(proposal["storage"]["private_dir"] == str(private) and set(proposal["documents"]) == set(document_keys))
    for key in document_keys:
        require(Path(paths[key]).parent == private and proposal["documents"][key]["path"] == paths[key])
        actual = _read(Path(paths[key]))
        require(actual == proposal[PROPOSAL_KEYS[key]] and digest(actual) == proposal["documents"][key]["digest"])
    require(_read(Path(paths["proposal"])) == proposal)
    journal = proposal["storage"]["journal"]
    key = proposal["storage"]["key"]
    require(paths["journal"] == journal["path"] and prepared["journal_id"] == journal["id"]
            and Path(paths["journal"]).parent == private and Path(paths["key"]).parent == private
            and set(key) == {"path", "id", "device", "inode", "owner", "mode"}
            and {name: key[name] for name in ("path", "id")} == proposal["configuration"]["key"]
            and paths["key"] == key["path"])
    info = Path(paths["journal"]).stat()
    require((info.st_dev, info.st_ino) == (journal["device"], journal["inode"]))
    actual_key = Path(paths["key"]).lstat()
    require(stat.S_ISREG(actual_key.st_mode) and (actual_key.st_dev, actual_key.st_ino, actual_key.st_uid,
            stat.S_IMODE(actual_key.st_mode)) == (key["device"], key["inode"], key["owner"], key["mode"])
            and key["owner"] == os.geteuid() and key["mode"] == 0o600)
    native.delivery_key.validate_key(Path(paths["key"]), proposal["configuration"]["key"]["id"])
    history = native.delivery_store.show(Path(paths["journal"]), prepared["journal_id"], prepared["spec"]["operation_key"])
    require(history["objective"] == prepared["spec"]["objective"] and history["limits"] == prepared["spec"]["limits"]
            and history["native_limits"] == proposal["native_limits"])
    require(native.automatic_merge.configuration_digest(proposal["configuration"], proposal["policy"]) == proposal["operation_approval"]["adapter"]["configuration_digest"])
    native.automatic_merge.validate_payload(proposal["request"], proposal["payload"], proposal["configuration"], proposal["policy"])
    return history


def save_private(prepared):
    """Persist only canonical non-secret state; never serialize the private token."""
    require(set(prepared) <= {"proposal", "selection", "paths", "journal_id", "core_source", "context", "spec", "private_dir", "python", "_token", "observer",
                              "runtime_profile", "supplemental_allocation"})
    state = {key: value for key, value in prepared.items() if key not in ("_token", "observer")}
    path = Path(prepared["private_dir"]) / "prepared-state.json"
    if path.exists():
        require(_read(path) == state)
    else:
        _write(path, state, prepared["_token"])
    return path


def restore(private_dir, core_source, token, *, profile=None):
    """Resume only original same-job storage and actual unchanged installed profile."""
    prepared = _read(private_dir / "prepared-state.json")
    _check_allocation(prepared, profile)
    native = _load_native(core_source, profile=profile)
    require(prepared["private_dir"] == str(private_dir) and prepared["core_source"] == str(core_source))
    prepared["_token"] = token
    history = _check_prepared(prepared, token, native, profile=profile)
    observer_path = private_dir / "observer-state.json"
    if observer_path.exists():
        observer = _read(observer_path)
        _check_observer(prepared, observer, history, native)
        prepared["observer"] = observer
    return prepared


def _check_observer(prepared, observer, history, native):
    require(set(observer) == {"proposal", "selection", "paths", "output_bundle"})
    private, wrapper, selection = Path(prepared["private_dir"]), observer["proposal"], observer["selection"]
    paths = observer["paths"]
    require(paths == {"packet": str(private / "observer-packet.json"), "proposal": str(private / "observer-proposal.json"),
                      "output_bundle": str(private / "observer-bundle")} and observer["output_bundle"] == paths["output_bundle"])
    packet = _read(Path(paths["packet"]))
    require(_read(Path(paths["proposal"])) == wrapper and packet == wrapper["packet"]
            and wrapper["context"] == prepared["context"] and wrapper["status"] == "proposed"
            and wrapper["authority_granted"] is False and wrapper["packet_digest"] == digest(packet))
    read, original = packet["read_approval"], prepared["proposal"]
    require(selection["phase"] == "observe" and selection["run_id"] == prepared["context"]["run_id"]
            and selection["run_attempt"] == 1 and selection["issuer"] == "p1c2u"
            and selection["approval_id"] == read["approval_id"] and selection["approval_digest"] == digest(read)
            and wrapper["read_approval_digest"] == digest(read) and selection["packet_digest"] == digest(packet)
            and re.fullmatch(r"[0-9a-f]{64}", selection["challenge"]))
    require(packet["configuration"] == packet["original_configuration"] == original["configuration"]
            and packet["policy"] == original["policy"] and packet["journal"] == original["operation_approval"]["journal"]
            and packet["operation_key"] == prepared["spec"]["operation_key"] and packet["output_bundle"] == paths["output_bundle"])
    operation = history.get("operation")
    require(isinstance(operation, dict) and operation["phase"] == "applied"
            and packet["intent_id"] == operation["intent"]["id"] and packet["receipt_id"] == operation["receipt"]["id"])
    jsonschema = importlib.import_module("jsonschema")
    jsonschema.validate(read, native.delivery_store.READ_RECOVERY_SCHEMA)
    jsonschema.validate(packet, native.automatic_merge_live.PACKET)


def build_observer(prepared, applied_report, *, now, profile=None):
    """Draft separate read authority from the real original applied journal only."""
    _utc(now)
    _check_allocation(prepared, profile)
    native = _load_native(Path(prepared["core_source"]), profile=profile)
    history = _check_prepared(prepared, prepared["_token"], native, profile=profile)
    proposal = prepared["proposal"]
    operation = history.get("operation")
    require(isinstance(applied_report, dict) and applied_report.get("status") == "applied"
            and applied_report.get("kind") == "delivery-report" and applied_report.get("schema_version") == "0.1.0"
            and applied_report.get("profile") == "product-delivery-v1"
            and isinstance(operation, dict) and operation.get("phase") == "applied")
    intent, receipt = operation["intent"], operation["receipt"]
    # Native pin calls the content hash 'digest'; relay selection calls it approval_digest.
    expected_pin = {"issuer": prepared["selection"]["issuer"], "approval_id": prepared["selection"]["approval_id"],
                    "digest": prepared["selection"]["approval_digest"]}
    require(intent["request"] == proposal["request"] and operation["payload"] == proposal["payload"]
            and operation["approval"] == proposal["operation_approval"] and operation["pin"] == expected_pin)
    require(applied_report.get("intent") == intent and applied_report.get("receipt") == receipt
            and applied_report.get("journal") == proposal["operation_approval"]["journal"]
            and applied_report.get("operation_key") == proposal["request"]["operation_key"]
            and applied_report.get("request_digest") == digest(proposal["request"]))
    invoked = [call for call in operation["calls"] if call["method"] == "invoke"]
    require(len(invoked) == 1 and isinstance(invoked[0].get("result"), dict))
    native.automatic_merge.validate_result("invoke", proposal["request"], proposal["payload"], invoked[0]["result"],
                                           configuration=proposal["configuration"], policy=proposal["policy"])
    facts = invoked[0]["result"]["provenance"]["facts"].get("preflight")
    native.automatic_merge.validate_ready_facts(proposal["request"], proposal["payload"], proposal["configuration"], proposal["policy"], facts)
    configuration, policy = proposal["configuration"], proposal["policy"]
    native.automatic_merge.validate_installation_grant_time(configuration["actor"], now=now)
    end = dt.datetime.fromisoformat(configuration["actor"]["grant"]["not_after"])
    require(now < end)
    read = {"schema_version": "0.1.0", "profile": "product-delivery-v1", "kind": "delivery-read-recovery",
            "issuer": "p1c2u", "approval_id": "native-positive-observe-" + str(prepared["context"]["run_id"]) + "-1",
            "objective": prepared["spec"]["objective"], "journal": proposal["operation_approval"]["journal"],
            "operation_key": prepared["spec"]["operation_key"], "intent_id": intent["id"],
            "request_digest": digest(proposal["request"]), "native_payload_digest": digest(proposal["payload"]),
            "old_configuration_digest": proposal["operation_approval"]["adapter"]["configuration_digest"],
            "new_configuration_digest": native.automatic_merge.configuration_digest(configuration, policy),
            "operation_profile_digest": proposal["payload"]["operation_profile_digest"], "policy_digest": digest(policy),
            "contract": policy["contract"], "limits": prepared["spec"]["limits"], "read_limits": configuration["call_limits"]["reconcile"],
            "not_before": _utc(now), "expires_at": _utc(end)}
    pin = {"issuer": "p1c2u", "approval_id": read["approval_id"], "digest": digest(read)}
    private = Path(prepared["private_dir"])
    packet = {"schema_version": "0.1.0", "kind": "delivery-merge-live-observation", "source": native.automatic_merge_live.SOURCE,
              "observation_id": os.urandom(16).hex(), "output_bundle": str(private / "observer-bundle"), "maximum_calls": 1,
              "limits": configuration["call_limits"]["reconcile"], "journal": read["journal"], "operation_key": read["operation_key"],
              "intent_id": intent["id"], "receipt_id": receipt["id"], "original_approval_pin": expected_pin,
              "original_configuration": configuration, "configuration": configuration, "policy": policy,
              "read_approval": read, "read_approval_pin": pin}
    jsonschema = importlib.import_module("jsonschema")
    jsonschema.validate(read, native.delivery_store.READ_RECOVERY_SCHEMA)
    jsonschema.validate(packet, native.automatic_merge_live.PACKET)
    wrapper = {"schema_version": "0.1.0", "kind": "proposed-native-positive-observer", "status": "proposed",
               "authority_granted": False, "context": prepared["context"], "packet": packet,
               "read_approval_digest": digest(read), "packet_digest": digest(packet),
               "original_journal_modified": False, "new_merge_authority": False}
    observer = {"proposal": wrapper, "selection": _selection("observe", prepared["context"], packet, read),
                "paths": {"packet": str(private / "observer-packet.json"), "proposal": str(private / "observer-proposal.json"),
                          "output_bundle": packet["output_bundle"]},
                "output_bundle": packet["output_bundle"]}
    _write(Path(observer["paths"]["packet"]), packet, prepared["_token"])
    _write(Path(observer["paths"]["proposal"]), wrapper, prepared["_token"])
    _write(private / "observer-state.json", observer, prepared["_token"])
    prepared["observer"] = observer
    return observer
