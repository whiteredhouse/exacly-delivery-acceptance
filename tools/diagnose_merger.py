#!/usr/bin/env python3
"""Owner-local read-only diagnostic. Requires Python 3.10+, Git and OpenSSL.

Run: python3 -I -B diagnose_merger.py /path/to/merger-private-key.pem
The key stays on this machine. Credential mint/revocation are the only API writes.
No source, check, PR, merge or protection writes are permitted.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SOURCE = "723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8"
TREE = "104a733dbd6a504e9fb995f9c621e65ebda13798"
REPOSITORY = "whiteredhouse/exacly-delivery-acceptance"
REPOSITORY_ID, APP_ID, INSTALLATION_ID = 1442278205, 5572362, 177653055
API = "https://api.github.com"
PREFIX = "/repos/" + REPOSITORY
PERMISSIONS = {"contents": "write", "checks": "read", "pull_requests": "read", "administration": "read", "metadata": "read"}
READS = {
    PREFIX: "repository_read",
    "/installation/repositories?per_page=100": "installation_scope_read",
    PREFIX + "/git/ref/heads/main": "main_ref_read",
    PREFIX + "/branches/main/protection": "classic_protection_read",
    PREFIX + "/branches/main/protection/required_signatures": "required_signatures_read",
    PREFIX + "/rules/branches/main": "effective_rules_read",
}
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
GENERIC = "local diagnostic could not complete"


class Stopped(Exception):
    pass


def require(condition):
    if not condition:
        raise Stopped()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def clean_environment():
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull}
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"):
        if key in os.environ:
            env[key] = os.environ[key]
    if "SSL_CERT_FILE" in env:
        env["GIT_SSL_CAINFO"] = env["SSL_CERT_FILE"]
    return env


def command(args, *, data=None, timeout=25):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=clean_environment(), timeout=timeout, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 16384 and len(result.stderr) <= 16384)
    return result.stdout


def trusted_source(directory):
    source = directory / "source"
    source.mkdir(mode=0o700)
    git = ["git", "-C", str(source), "-c", "core.hooksPath=" + os.devnull,
           "-c", "core.autocrlf=false", "-c", "credential.helper="]
    command(git + ["init", "--quiet"])
    command(git + ["remote", "add", "origin", "https://github.com/" + REPOSITORY + ".git"])
    command(git + ["fetch", "--quiet", "--depth=1", "origin", SOURCE], timeout=45)
    require(command(git + ["rev-parse", "FETCH_HEAD^{commit}"]).strip().decode("ascii") == SOURCE)
    require(command(git + ["rev-parse", SOURCE + "^{tree}"]).strip().decode("ascii") == TREE)
    command(git + ["checkout", "--quiet", "--detach", SOURCE])
    return source


def app_jwt(key):
    now = int(time.time())
    b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
    signing = b64(encoded({"alg": "RS256", "typ": "JWT"})) + b"." + b64(encoded({"iat": now - 60, "exp": now + 540, "iss": APP_ID}))
    signature = command(["openssl", "dgst", "-sha256", "-sign", str(key)], data=signing)
    require(128 <= len(signature) <= 1024)
    return (signing + b"." + b64(signature)).decode("ascii")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class Api:
    def __init__(self):
        self.deadline = time.monotonic() + 120
        self.calls = 0
        self.stage = "installation_identity"
        self.actor = {}
        self.account_id = None
        self.last_http_status = None
        self.mint_attempted = False

    def request(self, method, path, credential, payload=None, *, revocation=False):
        allowed = (method == "GET" and (path in READS or path == "/app/installations/" + str(INSTALLATION_ID))) or (method == "POST" and path == "/app/installations/" + str(INSTALLATION_ID) + "/access_tokens" and payload == {"repository_ids": [REPOSITORY_ID], "permissions": PERMISSIONS}) or (method == "DELETE" and path == "/installation/token" and payload is None)
        require(allowed and self.calls < 12 and (revocation or time.monotonic() < self.deadline))
        self.calls += 1
        self.last_http_status = None
        if method == "POST":
            self.mint_attempted = True
        headers = {"Authorization": "Bearer " + credential, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "exacly-owner-local-diagnostic"}
        request = urllib.request.Request(API + path, data=None if payload is None else encoded(payload), headers=headers, method=method)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
                self.last_http_status = response.status
                data = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            self.last_http_status = error.code
            error.close()
            raise Stopped() from None
        require(self.last_http_status == (201 if method == "POST" else 204 if method == "DELETE" else 200))
        require(len(data) <= 1024 * 1024)
        return self.last_http_status, data

    def sender(self, method, url, headers, payload, timeout):
        require(method == "GET" and url.startswith(API) and url[len(API):] in READS and payload is None)
        path = url[len(API):]
        self.stage = READS[path]
        bearer = headers.get("Authorization", "")
        require(bearer.startswith("Bearer "))
        status, data = self.request("GET", path, bearer[7:])
        if path == PREFIX:
            value = json.loads(data)
            require(value.get("owner", {}).get("id") == self.account_id)
            permissions = value.get("permissions", {})
            self.actor = {name: permissions.get(name) if type(permissions.get(name)) is bool else None for name in ("admin", "maintain", "push")}
        return status, data


def safe_result(result, api):
    status = result.get("status")
    summary = {"status": status if status in ("ready", "rejected", "uncertain") else "rejected",
               "role": "merger", "source_commit": SOURCE, "provider_check_posts": 0,
               "stage": api.stage, "actor_permissions": api.actor}
    if status != "ready":
        reason = result.get("reason")
        summary["reason"] = reason if isinstance(reason, str) and reason in SAFE_REASONS else GENERIC
        if reason == "merge actor is not a non-admin/non-maintainer push actor":
            summary["stage"] = "actor_permissions"
        if api.last_http_status is not None:
            summary["http_status"] = api.last_http_status
    require(result.get("provider_check_posts") == 0)
    return summary


def diagnose(key):
    api, token = Api(), None
    result = {"status": "rejected", "role": "merger", "provider_check_posts": 0, "reason": GENERIC}
    with tempfile.TemporaryDirectory(prefix="exacly-merger-diagnostic-") as work:
        os.chmod(work, 0o700)
        directory = Path(work)
        try:
            api.stage = "trusted_source"
            source = trusted_source(directory)
            helper = runpy.run_path(str(source / "tools/app_bootstrap.py"), run_name="owner_local_bootstrap")
            api.stage = "installation_identity"
            jwt = app_jwt(key)
            _, data = api.request("GET", "/app/installations/" + str(INSTALLATION_ID), jwt)
            installation = json.loads(data)
            account = installation.get("account", {})
            require(installation.get("id") == INSTALLATION_ID and installation.get("app_id") == APP_ID and account.get("login") == "whiteredhouse" and account.get("type") == "Organization" and type(account.get("id")) is int and account["id"] > 0)
            api.account_id = account["id"]
            api.stage = "token_mint"
            _, data = api.request("POST", "/app/installations/" + str(INSTALLATION_ID) + "/access_tokens", jwt, {"repository_ids": [REPOSITORY_ID], "permissions": PERMISSIONS})
            minted = json.loads(data)
            token = minted.get("token")
            require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,1024}", token))
            require(minted.get("permissions") == PERMISSIONS)
            old = os.environ.get("CANARY_APP_TOKEN")
            try:
                os.environ["CANARY_APP_TOKEN"] = token
                args = argparse.Namespace(command="preflight", role="merger", installation_id=INSTALLATION_ID, out=str(directory / "evidence"))
                result = safe_result(helper["execute"](args, sender=api.sender), api)
            finally:
                if old is None:
                    os.environ.pop("CANARY_APP_TOKEN", None)
                else:
                    os.environ["CANARY_APP_TOKEN"] = old
        except Exception:
            result = {"status": "rejected", "role": "merger", "provider_check_posts": 0, "reason": GENERIC, "stage": api.stage, "actor_permissions": api.actor}
            if api.last_http_status is not None:
                result["http_status"] = api.last_http_status
        finally:
            if token is not None:
                try:
                    api.request("DELETE", "/installation/token", token, revocation=True)
                    result["token_revoked"] = True
                except Exception:
                    result["token_revoked"] = False
                    result["status"] = "rejected"
            else:
                result["token_revoked"] = None
            result["token_mint_attempted"] = api.mint_attempted
    return result


def main():
    try:
        require(len(sys.argv) == 2)
        key = Path(sys.argv[1]).expanduser().resolve(strict=True)
        require(key.is_file())
        result = diagnose(key)
    except Exception:
        result = {"status": "rejected", "reason": GENERIC, "provider_check_posts": 0, "token_revoked": None}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "ready" and result.get("token_revoked") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
