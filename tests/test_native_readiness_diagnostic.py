"""Controlled native inspection and a second transport write barrier; no live API."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
import urllib.request
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
CORE = Path(os.environ.get("EXACLY_NATIVE_DIAGNOSTIC_TEST_CORE", ROOT.parent / "native-readiness-diagnostics"))
SPEC = importlib.util.spec_from_file_location("native_readiness_diagnostic", ROOT / "tools/native_readiness_diagnostic.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
TARGET = json.loads((ROOT / "config/native-positive-trial.json").read_bytes())
TOKEN = "controlled-diagnostic-token-never-publish"
GITHUB = SimpleNamespace(READ_QUERY="query($owner:String!){read}", UNSTABLE_QUERY="query($owner:String!){conditions}")


class Response(io.BytesIO):
    status = 200

    def __init__(self, content=b"{}"):
        super().__init__(content)
        self.headers = Message()
        self.headers["Content-Length"] = str(len(content))


class Inner:
    def __init__(self):
        self.calls = []

    def open(self, request, *, timeout):
        self.calls.append((request.full_url, request.get_method(), request.data))
        return Response()


def request(url, *, method="GET", body=None):
    headers = {"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2026-03-10"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=body, headers=headers, method=method)


class NativeReadinessDiagnosticTests(unittest.TestCase):
    def test_unknown_even_lowercase_exception_messages_never_become_public_codes(self):
        self.assertEqual(helper.error_code(helper.Stopped("transport_refused")), "transport_refused")
        for error in (helper.Stopped("secretlowercasecredential"), helper.Stopped(TOKEN),
                      RuntimeError(TOKEN), OSError(TOKEN)):
            self.assertEqual(helper.error_code(error), "native_diagnostic_stopped")

    def test_native_loader_refuses_wrong_revision_dirty_source_extra_module_and_wrong_pins(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "core"
            package = source / "python/src/exacly"
            package.mkdir(parents=True)
            for name in helper.NATIVE_PINS:
                (package / name).write_text("pass\n")
            environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                           "GIT_AUTHOR_NAME": "Diagnostic fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                           "GIT_COMMITTER_NAME": "Diagnostic fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
            def git(*args):
                return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(source), *args],
                                      env=environment, stdin=subprocess.DEVNULL, capture_output=True,
                                      timeout=10, check=True).stdout
            git("init", "--initial-branch=main")
            git("add", ".")
            git("commit", "--no-gpg-sign", "-m", "Controlled native source")
            revision = git("rev-parse", "HEAD").strip().decode()
            pins = {name: hashlib.sha256((package / name).read_bytes()).hexdigest() for name in helper.NATIVE_PINS}
            with patch.object(helper, "CORE_REVISION", "0" * 40), self.assertRaises(helper.Stopped):
                helper.load_native(source)
            with patch.object(helper, "CORE_REVISION", revision), patch.object(helper, "NATIVE_PINS", pins):
                (package / "unexpected.py").write_text("pass\n")
                with self.assertRaises(helper.Stopped):
                    helper.load_native(source)
                (package / "unexpected.py").unlink()
                original = (package / "automatic_merge.py").read_bytes()
                (package / "automatic_merge.py").write_text("changed\n")
                with self.assertRaises(helper.Stopped):
                    helper.load_native(source)
                (package / "automatic_merge.py").write_bytes(original)
                with patch.object(helper, "NATIVE_PINS", {**pins, "automatic_merge.py": "0" * 64}), self.assertRaises(helper.Stopped):
                    helper.load_native(source)

    def test_actual_context_requires_fixed_owner_source_branch_and_first_attempt(self):
        source = "f" * 40
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_REPOSITORY": helper.REPOSITORY["full_name"], "GITHUB_REPOSITORY_ID": "1442278205",
                       "GITHUB_REF": helper.REF, "GITHUB_JOB": helper.JOB, "GITHUB_RUN_ATTEMPT": "1",
                       "GITHUB_ACTOR_ID": "1679024", "GITHUB_SHA": source, "GITHUB_RUN_ID": "12345",
                       "GITHUB_WORKFLOW_REF": helper.REPOSITORY["full_name"]
                       + "/.github/workflows/app-bootstrap.yml@" + helper.REF}
        def selected_git(root, *args):
            return (source + "\n").encode() if args[0] == "rev-parse" else Path(helper.__file__).read_bytes()
        with patch.dict(os.environ, environment), patch.object(helper, "_git", side_effect=selected_git):
            self.assertEqual(helper.context()["source"], source)
            for name, value in (("GITHUB_ACTOR_ID", "1"), ("GITHUB_RUN_ATTEMPT", "2"),
                                ("GITHUB_REF", "refs/heads/main"), ("GITHUB_JOB", "native-positive-trial"),
                                ("GITHUB_REPOSITORY_ID", "1")):
                with patch.dict(os.environ, {name: value}), self.assertRaises(helper.Stopped):
                    helper.context()
            with patch.object(helper, "_git", return_value=b"0" * 40), self.assertRaises(helper.Stopped):
                helper.context()
            with patch.object(helper, "_git", side_effect=[(source + "\n").encode(), b"changed"]), self.assertRaises(helper.Stopped):
                helper.context()

    def test_native_reason_parser_is_closed_and_never_echoes_remote_text(self):
        self.assertEqual(helper.native_diagnostic("GitHub merge readiness blocked: stage=protection; code=http_error; http_status=403."),
                         {"stage": "protection", "code": "http_error", "http_status": 403})
        self.assertEqual(helper.native_diagnostic("GitHub merge readiness blocked: stage=key; code=local_io_error."),
                         {"stage": "key", "code": "local_io_error"})
        for reason in (TOKEN, "Delivery credentials, key or current exact protected merge conditions block.",
                       "GitHub merge readiness blocked: stage=unreviewed; code=http_error; http_status=403.",
                       "GitHub merge readiness blocked: stage=key; code=validation_failed; http_status=403.",
                       "GitHub merge readiness blocked: stage=key; code=http_error; http_status=600.",
                       "GitHub merge readiness blocked: stage=key; code=local_io_error.\n" + TOKEN, None):
            with self.subTest(reason=type(reason).__name__):
                self.assertIsNone(helper.native_diagnostic(reason))

    def test_outer_transport_refuses_writes_changed_queries_and_other_targets_before_sender(self):
        inner = Inner()
        opener = helper.ReadOnlyOpener(TARGET, GITHUB, TOKEN, inner=inner)
        native_variables = {"owner": "whiteredhouse", "name": "exacly-delivery-acceptance", "number": 5}
        read_body = {"query": GITHUB.READ_QUERY, "variables": native_variables}
        bad = [request(helper.API + helper.PREFIX, method=method) for method in ("POST", "PUT", "PATCH", "DELETE")]
        bad += [request(helper.API + "/graphql", method="POST", body=helper.encoded(body)) for body in (
            {"query": "mutation{updateRefs}", "variables": native_variables},
            {"query": GITHUB.READ_QUERY, "variables": {**native_variables, "number": 6}},
            {"query": GITHUB.READ_QUERY + " mutation{updateRefs}", "variables": native_variables})]
        bad += [request(url) for url in ("http://api.github.com" + helper.PREFIX,
                                        "https://evil.example" + helper.PREFIX,
                                        helper.API + helper.PREFIX + "/pulls/6",
                                        helper.API + helper.PREFIX + "/git/ref/heads/other",
                                        helper.API + helper.PREFIX + "#fragment")]
        bad.append(request(helper.API + "/graphql", method="POST",
                           body=b'{"query":"mutation{updateRefs}","query":' + json.dumps(GITHUB.READ_QUERY).encode()
                           + b',"variables":' + helper.encoded(native_variables) + b'}'))
        for candidate in bad:
            with self.subTest(method=candidate.get_method()), self.assertRaises(helper.Stopped):
                opener.open(candidate, 10)
        self.assertEqual(inner.calls, [])
        good = request(helper.API + "/graphql", method="POST", body=json.dumps(read_body).encode())
        with opener.open(good, 10) as response:
            self.assertEqual(response.read(3), b"{}")
        self.assertEqual(len(inner.calls), 1)
        with self.assertRaises(helper.Stopped):
            opener.open(good, 10)
        self.assertEqual(len(inner.calls), 1)

    def test_outer_transport_refuses_extra_headers_deadline_and_size_overrun(self):
        inner = Inner()
        opener = helper.ReadOnlyOpener(TARGET, GITHUB, TOKEN, inner=inner)
        extra = request(helper.API + helper.PREFIX)
        extra.add_header("X-HTTP-Method-Override", "DELETE")
        with self.assertRaises(helper.Stopped):
            opener.open(extra, 10)
        self.assertEqual(inner.calls, [])
        expired = helper.ReadOnlyOpener(TARGET, GITHUB, TOKEN, inner=inner, monotonic=lambda: 0)
        expired.deadline = -1
        with self.assertRaises(helper.Stopped):
            expired.open(request(helper.API + helper.PREFIX), 10)
        self.assertEqual(inner.calls, [])
        with patch.object(helper, "MAX_READS", 0), self.assertRaises(helper.Stopped):
            opener.open(request(helper.API + helper.PREFIX), 10)
        self.assertEqual(inner.calls, [])
        response = helper.BoundedResponse(Response(b"12345"), opener)
        with patch.object(helper, "MAX_RESPONSE", 4), self.assertRaises(helper.Stopped):
            response.read(5)

    def test_private_output_is_create_only_and_exactly_allowlisted(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"RUNNER_TEMP": folder}):
            path = Path(folder) / "private"
            files = helper.PrivateOutput(path, TOKEN)
            try:
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                with self.assertRaises(helper.Stopped):
                    files.write("private.key", {"status": "blocked"})
                with self.assertRaises(helper.Stopped):
                    files.write("native-readiness-diagnostic.json", {"error": TOKEN})
                files.write("native-readiness-diagnostic.json", {"status": "blocked"})
                target = path / "native-readiness-diagnostic.json"
                original = target.read_bytes()
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    files.write("native-readiness-diagnostic.json", {"status": "ready"})
                self.assertEqual(target.read_bytes(), original)
                os.symlink("missing", path / "mint-attestation.json")
                with self.assertRaises(FileExistsError):
                    files.write("mint-attestation.json", {"status": "ready"})
            finally:
                os.close(files.fd)
            with self.assertRaises(FileExistsError):
                helper.PrivateOutput(path, TOKEN)

    def test_redirect_handler_never_returns_a_followup_request(self):
        self.assertIsNone(helper.NoRedirect().redirect_request(None, None, 302, "untrusted", {}, "https://evil.example"))

    def test_workflow_has_distinct_owner_gated_read_only_job_and_exact_safe_uploads(self):
        workflow = (ROOT / ".github/workflows/app-bootstrap.yml").read_text()
        job = workflow.split("  native-readiness-diagnostic:\n", 1)[1].split("  native-positive-trial:\n", 1)[0]
        for required in ("github.actor_id == '1679024'", "github.run_attempt == 1", "github.repository_id == '1442278205'",
                         "inputs.mode == 'native-readiness-diagnostic'", "canary-merger-diagnostic",
                         "ref: ${{ github.sha }}", "persist-credentials: false", "permission-contents: write",
                         "permission-statuses: read", "skip-token-revoke: false", "overwrite: false"):
            self.assertIn(required, job)
        for filename in helper.SAFE_NAMES:
            self.assertIn("/" + filename, job)
        self.assertNotIn("native_positive_trial.py", job)
        self.assertNotIn("/diagnostic-only.key", job)
        self.assertNotIn("*.json", job)
        source = (ROOT / "tools/native_readiness_diagnostic.py").read_text()
        for forbidden in ("DeliveryEngine(", "delivery_store.initialize(", "adapter.invoke(", "adapter.reconcile("):
            self.assertNotIn(forbidden, source)

    def test_actual_native_inspection_is_read_only_and_failure_diagnostics_are_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            process = subprocess.run([str(CORE / ".venv/bin/python"), "-I", "-B", "-c", INTEGRATION,
                                      str(ROOT / "tools/native_readiness_diagnostic.py"), str(CORE), folder],
                                     stdin=subprocess.DEVNULL, capture_output=True,
                                     timeout=120, check=False)
            self.assertEqual(process.returncode, 0, process.stderr.decode())
            result = json.loads(process.stdout)
            self.assertEqual(result["cases"], ["ready", "http_403", "malformed_response", "review_blocked", "cli_ready"])
            self.assertEqual(result["provider_writes"], 0)
            self.assertEqual(result["socket_calls"], 0)


INTEGRATION = r'''
import contextlib, copy, datetime as dt, importlib.util, io, json, os, shutil, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
from email.message import Message
from urllib.error import HTTPError
helper_path, core, folder = map(Path, sys.argv[1:])
sys.path[:0] = [str(core / 'python/src'), str(core / 'python/tests')]
from exacly import automatic_merge, delivery_automation, delivery_key, github_merge, execution_store
import automatic_merge_fixtures as f
loader = importlib.util.spec_from_file_location('native_readiness_diagnostic', helper_path)
helper = importlib.util.module_from_spec(loader); loader.loader.exec_module(helper)
spec = json.loads((helper.ROOT / 'config/native-positive-trial.json').read_bytes())
token = 'controlled-diagnostic-token-never-publish'
f.REPOSITORY = {k: helper.REPOSITORY[k] for k in ('id', 'full_name')}
f.NODE_ID, f.PREFIX, f.BASE_REF, f.HEAD_REF = helper.REPOSITORY['node_id'], helper.PREFIX, spec['base_ref'], spec['head_ref']
f.BASE, f.HEAD, f.MERGE, f.TREE = (spec[n] for n in ('base_revision', 'head_revision', 'merge_revision', 'merge_tree'))
f.TOKEN = token
native = helper.load_native(core)
context = {'repository':helper.REPOSITORY['full_name'],'repository_id':helper.REPOSITORY['id'],
           'source':'f'*40,'run_id':12345,'run_attempt':1,'ref':helper.REF,'job':helper.JOB,
           'workflow_ref':helper.REPOSITORY['full_name']+'/.github/workflows/app-bootstrap.yml@'+helper.REF}
class Backend(f.ScriptedGitHub):
 def respond(self, method, path, body):
  if method == 'GET' and path == helper.PREFIX+'/pulls/5': return copy.deepcopy(self.pull_request)
  if method == 'POST' and path == '/graphql':
   expected={'owner':'whiteredhouse','name':'exacly-delivery-acceptance','number':5}
   repo={'id':helper.REPOSITORY['node_id'],'databaseId':helper.REPOSITORY['id']}
   if body['query']==github_merge.READ_QUERY:
    assert body['variables']==expected
    return {'data':{'repository':{**repo,'pullRequest':copy.deepcopy(self.graph)}}}
   assert body['query']==github_merge.UNSTABLE_QUERY and body['variables']=={**expected,'base':'refs/heads/main'}
   return {'data':{'repository':{**repo,'nameWithOwner':helper.REPOSITORY['full_name'],
    'ref':{'prefix':'refs/heads/','name':'main','target':{'oid':f.BASE},'branchProtectionRule':copy.deepcopy(self.branch_policy)},
    'pullRequest':{'number':5,'headRefOid':f.HEAD,'baseRefOid':f.BASE,'potentialMergeCommit':{'oid':f.MERGE},
                   'reviewThreads':copy.deepcopy(self.review_threads)}}}}
  return super().respond(method,path,body)
def backend():
 b=Backend();b.repository['permissions']={'admin':False,'maintain':False,'push':False}
 b.pull_request['number']=5;b.graph['mergeStateStatus']='UNSTABLE'
 check=spec['policy']['required_checks'][0]
 b.protection['required_status_checks']['checks']=[{'context':check['name'],'app_id':check['app_id']}]
 b.check_runs[0].update(name=check['name'],app={'id':check['app_id']})
 b.trees={revision:[{'path':item['path'],'sha':item[phase],'type':'blob','mode':'100644'}
                    for item in spec['protected_files']] for revision,phase in ((f.BASE,'before'),(f.HEAD,'after'))}
 return b
socket_calls=[]
def forbid(event,args):
 if event.startswith('socket.'):
  socket_calls.append(event);raise AssertionError('controlled fixture attempted network')
sys.addaudithook(forbid)
os.environ.update(CANARY_APP_TOKEN=token,CANARY_INSTALLATION_ID='177653055',RUNNER_TEMP=str(folder))
cases=[];writes=0
for case in ('ready','http_403','malformed_response','review_blocked'):
 b=backend()
 if case=='http_403': b.overrides[('GET',helper.PREFIX+'/branches/main/protection')]=HTTPError(helper.API,403,token,Message(),io.BytesIO(token.encode()))
 if case=='malformed_response': b.overrides[('GET',helper.PREFIX)]=['untrusted',token]
 if case=='review_blocked': b.graph['reviewDecision']='REVIEW_REQUIRED'
 out=folder/case
 report=helper.run_diagnostic(out,core_source=core,native=native,inner=b,selected_context=context,now=dt.datetime.now(dt.UTC))
 assert report['inspect_calls']==1 and report['provider_writes']==0 and report['merge_authority'] is False,report
 assert not report['delivery_journal_created'] and not report['original_journal_accessed']
 if case=='ready': assert report['status']=='ready' and report['ready'] is True,report
 else:
  assert report['status']=='blocked' and report['ready'] is False,report
  assert report['native_diagnostic']['code']!='metadata_unavailable',report
 if case=='http_403': assert report['native_diagnostic']=={'stage':'protection','code':'http_error','http_status':403},report
 if case=='review_blocked': assert report['native_diagnostic']['stage']=='ready_facts',report
 assert not b.writes and not b.mutations
 writes+=len(b.writes)
 assert not list(out.glob('*.sqlite*'))
 public=[p for p in out.iterdir() if p.name in helper.SAFE_NAMES]
 assert len(public)==3 and all(p.stat().st_mode&0o777==0o600 for p in public)
 text=json.dumps(report)+''.join(p.read_text() for p in public)
 assert token not in text and 'Bearer ' not in text
 assert 'EXACLY_DELIVERY_MERGE_TOKEN' not in os.environ
 cases.append(case)
# The real CLI path verifies both its committed source and the exact native
# commit/hashes. Only urllib's transport is controlled; no helper/native seam is
# used to skip context, source verification or private-input construction.
source=folder/'cli-source';(source/'tools').mkdir(parents=True);(source/'config').mkdir()
shutil.copyfile(helper_path,source/'tools/native_readiness_diagnostic.py')
shutil.copyfile(helper.ROOT/'config/native-positive-trial.json',source/'config/native-positive-trial.json')
git_env={'PATH':os.defpath,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
         'GIT_AUTHOR_NAME':'Diagnostic fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid',
         'GIT_COMMITTER_NAME':'Diagnostic fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid'}
def git(*args):
 return subprocess.run(['git','-c','core.hooksPath='+os.devnull,'-C',str(source),*args],env=git_env,
                       stdin=subprocess.DEVNULL,capture_output=True,timeout=10,check=True).stdout
git('init','--initial-branch=main');git('add','.');git('commit','--no-gpg-sign','-m','Controlled CLI source')
revision=git('rev-parse','HEAD').strip().decode()
cli_spec=importlib.util.spec_from_file_location('controlled_cli_diagnostic',source/'tools/native_readiness_diagnostic.py')
cli=importlib.util.module_from_spec(cli_spec);cli_spec.loader.exec_module(cli)
os.environ.update(GITHUB_ACTIONS='true',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REPOSITORY=helper.REPOSITORY['full_name'],
 GITHUB_REPOSITORY_ID=str(helper.REPOSITORY['id']),GITHUB_REF=helper.REF,GITHUB_JOB=helper.JOB,GITHUB_RUN_ATTEMPT='1',
 GITHUB_ACTOR_ID='1679024',GITHUB_SHA=revision,GITHUB_RUN_ID='12345',
 GITHUB_WORKFLOW_REF=helper.REPOSITORY['full_name']+'/.github/workflows/app-bootstrap.yml@'+helper.REF)
b=backend();original_builder=cli.urllib.request.build_opener
cli.urllib.request.build_opener=lambda *handlers:b
sys.argv=[str(source/'tools/native_readiness_diagnostic.py'),'--core-source',str(core),'--out',str(folder/'cli_ready')]
printed=io.StringIO()
try:
 with contextlib.redirect_stdout(printed): code=cli.main()
finally: cli.urllib.request.build_opener=original_builder
report=json.loads(printed.getvalue())
assert code==0 and report['status']=='ready' and report['inspect_calls']==1,report
assert report['context']['source']==revision and report['core_revision']==cli.CORE_REVISION
assert token not in printed.getvalue() and not b.writes and not b.mutations
assert not list((folder/'cli_ready').glob('*.sqlite*'))
cases.append('cli_ready')
assert socket_calls==[]
print(json.dumps({'cases':cases,'provider_writes':writes,'socket_calls':len(socket_calls)}))
'''


if __name__ == "__main__":
    unittest.main()
