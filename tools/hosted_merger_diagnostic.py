"""Read-only diagnostics around the unchanged, pinned main merger preflight.

The caller mints and revokes the selected token. This runner performs fixed GETs
only and emits filtered facts; diagnostics never replace the original guards.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess

SOURCE = "723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8"
TREE = "104a733dbd6a504e9fb995f9c621e65ebda13798"
INSTALLATION_ID = 177653055
API = "https://api.github.com"
PREFIX = "/repos/whiteredhouse/exacly-delivery-acceptance"
PINS = {
    "tools/app_bootstrap.py": "1b1bad0bfd2f7d26b57823d4c7ca8754d091036b08f3a5193da3ff909f30f6db",
    "tools/verify_merge.py": "16de0acc0537230dcc731ee56e3cbe07c2a992a26f46a54d26016c7c9d2239fe",
}
READS = {
    PREFIX: "repository_read",
    "/installation/repositories?per_page=100": "installation_scope_read",
    PREFIX + "/git/ref/heads/main": "main_ref_read",
    PREFIX + "/branches/main/protection": "classic_protection_read",
    PREFIX + "/branches/main/protection/required_signatures": "required_signatures_read",
    PREFIX + "/rules/branches/main": "effective_rules_read",
}
CAPABILITIES = ("enforce_admins", "required_linear_history", "allow_force_pushes",
                "allow_deletions", "required_conversation_resolution", "lock_branch")
SAFE_REASONS = frozenset((
    "invalid trusted App configuration", "trusted App configuration differs from fixed canary identities",
    "minted installation ID differs from trusted role configuration",
    "trusted source HEAD differs from selected source commit", "CANARY_APP_TOKEN is required",
    "repository identity changed", "public canary repository is unavailable",
    "token must select exactly one repository", "token repository scope changed",
    "current main differs from trusted source", "merge actor is not a non-admin/non-maintainer push actor",
    "effective rulesets are unsupported by current merge profile",
    "classic protection/signature facts are unavailable", "required App check configuration changed",
    "independent review policy changed", "review bypass configuration is unknown",
    "classic protection capability changed", "GitHub rejected the bounded request",
    "GitHub request outcome is unavailable", "request is outside fixed canary API scope",
    "HTTP read/time budget exhausted", "GitHub response status is unsupported", "HTTP deadline expired",
    "duplicate JSON key", "bounded JSON response required", "nonfinite JSON value",
    "JSON response could not be decoded", "bounded bootstrap could not complete",
))
GENERIC = "bounded diagnostic could not complete"


class Stopped(Exception):
    pass


def require(condition):
    if not condition:
        raise Stopped()


def source_pin(source):
    require(source.is_absolute() and ".." not in source.parts and not source.is_symlink())
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
           "GIT_GRAFT_FILE": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
    for expression, expected in (("HEAD", SOURCE), ("HEAD^{tree}", TREE)):
        result = subprocess.run(
            ["git", "--no-optional-locks", "-c", "core.hooksPath=" + os.devnull,
             "-c", "core.fsmonitor=false", "-C", str(source), "rev-parse", "--verify", expression],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=5, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 128 and result.stdout.strip().decode("ascii") == expected)
    for path, expected in PINS.items():
        fd = os.open(source / path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode))
            data = os.read(fd, 1024 * 1024 + 1)
            require(len(data) <= 1024 * 1024 and hashlib.sha256(data).hexdigest() == expected)
        finally:
            os.close(fd)


def mapping(value):
    return value if isinstance(value, dict) else {}


def boolean(value):
    return value if type(value) is bool else None


def number(value):
    return value if type(value) is int and 0 <= value <= 1000000 else None


def count(value):
    return len(value) if isinstance(value, list) and len(value) <= 1000000 else None


class ReadOnlySender:
    def __init__(self, transport, decode):
        self.transport, self.decode = transport, decode
        self.stage, self.seen, self.observations = "helper_setup", set(), {}

    def record(self, path, value):
        data = mapping(value)
        if path == PREFIX:
            permissions = mapping(data.get("permissions"))
            self.observations["actor_permissions"] = {name: boolean(permissions.get(name)) for name in ("admin", "maintain", "push")}
        elif path == "/installation/repositories?per_page=100":
            self.observations["scope_total_count"] = number(data.get("total_count"))
        elif path == PREFIX + "/git/ref/heads/main":
            self.observations["current_main_matches_source"] = mapping(data.get("object")).get("sha") == SOURCE
        elif path == PREFIX + "/branches/main/protection":
            checks, reviews = mapping(data.get("required_status_checks")), mapping(data.get("required_pull_request_reviews"))
            self.observations["protection"] = {
                "strict": boolean(checks.get("strict")),
                "checks_expected_match": checks.get("checks") == [{"context": "exacly-generated-merge", "app_id": 5572341}],
                "review_count": number(reviews.get("required_approving_review_count")),
                **{name: boolean(reviews.get(name)) for name in ("require_last_push_approval", "dismiss_stale_reviews", "require_code_owner_reviews")},
                "bypass_counts": {name: count(mapping(reviews.get("bypass_pull_request_allowances")).get(name)) for name in ("users", "teams", "apps")},
                "capabilities": {name: boolean(mapping(data.get(name)).get("enabled")) for name in CAPABILITIES},
            }
        elif path == PREFIX + "/branches/main/protection/required_signatures":
            self.observations["required_signatures_enabled"] = boolean(data.get("enabled"))
        elif path == PREFIX + "/rules/branches/main":
            self.observations["effective_rules_count"] = count(value)

    def __call__(self, method, url, headers, payload, timeout):
        require(method == "GET" and payload is None and url.startswith(API))
        path = url[len(API):]
        require(path in READS and path not in self.seen and len(self.seen) < len(READS))
        self.stage = READS[path]
        self.seen.add(path)
        status, data = self.transport(method, url, headers, payload, timeout)
        self.record(path, self.decode(data))
        return status, data


def diagnose(source, out):
    sender = None
    stage = "trusted_source"
    try:
        source_pin(source)
        stage = "installation_identity"
        installation = os.environ.get("CANARY_INSTALLATION_ID", "")
        require(re.fullmatch(r"[1-9][0-9]*", installation) is not None and int(installation) == INSTALLATION_ID)
        helper = runpy.run_path(str(source / "tools/app_bootstrap.py"), run_name="pinned_merger_preflight")
        sender = ReadOnlySender(helper["transport"], helper["decode"])
        arguments = argparse.Namespace(command="preflight", role="merger", installation_id=INSTALLATION_ID, out=str(out))
        result = helper["execute"](arguments, sender=sender)
        require(type(result.get("provider_check_posts")) is int and result["provider_check_posts"] == 0)
        status = result.get("status")
        require(status in ("ready", "rejected", "uncertain"))
        summary = {"status": status, "role": "merger", "source_commit": SOURCE,
                   "stage": sender.stage, "provider_check_posts": 0,
                   "reads_attempted": len(sender.seen), "observations": sender.observations}
        if status != "ready":
            reason = result.get("reason")
            summary["reason"] = reason if isinstance(reason, str) and reason in SAFE_REASONS else GENERIC
            if reason == "merge actor is not a non-admin/non-maintainer push actor":
                summary["stage"] = "actor_permissions"
        return summary
    except Exception:
        return {"status": "rejected", "role": "merger", "source_commit": SOURCE,
                "stage": sender.stage if sender else stage, "reason": GENERIC,
                "provider_check_posts": 0, "reads_attempted": len(sender.seen) if sender else 0,
                "observations": sender.observations if sender else {}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    result = diagnose(arguments.trusted_source, arguments.out)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
