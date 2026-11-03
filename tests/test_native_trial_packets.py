"""Offline checks for advisory packets and actual pinned native local storage."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
CORE = Path(os.environ.get('EXACLY_NATIVE_TRIAL_TEST_CORE', ROOT.parent / 'readiness-core-merged'))
NOW = dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc)
TOKEN = 'controlled-native-trial-token-never-publish'
SPEC = json.loads((ROOT / 'config/native-positive-trial.json').read_text())
CONTEXT = {
    'repository': 'whiteredhouse/exacly-delivery-acceptance',
    'repository_id': 1442278205,
    'source': 'f' * 40,
    'run_id': 12345,
    'run_attempt': 1,
    'workflow_ref': ('whiteredhouse/exacly-delivery-acceptance/.github/workflows/'
                     'app-bootstrap.yml@refs/heads/codex/preflight-diagnostics'),
    'ref': 'refs/heads/codex/preflight-diagnostics',
    'job': 'native-positive-trial',
}

# This fixture uses real native schemas, key/journal storage and marker proofs.
# Its HTTP provider is explicitly controlled and supplies no live acceptance.
NATIVE_INTEGRATION = r'''
import contextlib, copy, datetime as dt, importlib.util, io, json, os, shutil, stat, subprocess, sys, time
from unittest.mock import patch
from pathlib import Path
helper_path, core, spec_path, private = map(Path, sys.argv[1:])
sys.path.insert(0, str(core / 'python/src'))
sys.path.insert(0, str(core / 'python/tests'))
import automatic_merge_fixtures as fixture
from exacly import automatic_merge, automatic_merge_live, delivery_automation as delivery
from exacly import delivery_store, execution_store, executor_runtime, github_merge
from exacly.delivery_engine import DeliveryEngine
loader = importlib.util.spec_from_file_location('native_trial_packets', helper_path)
packets = importlib.util.module_from_spec(loader)
loader.loader.exec_module(packets)
spec = json.loads(spec_path.read_text())
context = {
 'repository': spec['repository']['full_name'], 'repository_id': spec['repository']['id'],
 'source': 'f' * 40, 'run_id': 12345, 'run_attempt': 1,
 'workflow_ref': spec['repository']['full_name'] + '/.github/workflows/app-bootstrap.yml@refs/heads/codex/preflight-diagnostics',
 'ref': 'refs/heads/codex/preflight-diagnostics', 'job': 'native-positive-trial'
}
token = 'controlled-native-trial-token-never-publish'
socket_attempts = []
def forbid_network(event, args):
 if event.startswith('socket.'):
  socket_attempts.append(event)
  raise AssertionError('local packet preparation attempted provider activity')
sys.addaudithook(forbid_network)
now = dt.datetime.now(dt.timezone.utc)
supplemental = spec.get('kind') == 'fixed-native-supplemental-trial'
if supplemental:
 from test_delivery_cli import SharedMapping, SharedSequence
 from exacly import delivery_io
 from exacly.cli import exacly_main
profile_args, prepare_args = {}, {}
if supplemental:
 protocol_loader = importlib.util.spec_from_file_location('native_trial_protocol', helper_path.with_name('native_trial_protocol.py'))
 protocol_module = importlib.util.module_from_spec(protocol_loader)
 protocol_loader.loader.exec_module(protocol_module)
 protocol = protocol_module.load(helper_path.parents[1])
 profile_args = {'profile': protocol['profile']}
 command = protocol_module.allowance_command(protocol, context)
 allocation = {'schema_version': '0.1.0', 'kind': 'owner-approved-supplemental-native-allocation',
               'status': 'approved', 'context': context, 'accounting': spec['accounting'],
               'accounting_digest': protocol['profile']['accounting_digest'],
               'reviewer_id': 1679024, 'environment_id': 26032127012,
               'command': command, 'command_digest': 'sha256:' + __import__('hashlib').sha256(command.encode()).hexdigest(),
               'observed_at': now.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
 prepare_args = {**profile_args, 'allocation': allocation}
prepared = packets.prepare(private, spec, context, core, token, spec['installation_id'], now=now, **prepare_args)
proposal, selection, paths = prepared['proposal'], prepared['selection'], prepared['paths']
assert proposal['status'] == 'proposed' and proposal['authority_granted'] is False
assert selection['packet_digest'] == packets.digest(proposal)
assert selection['identity_digest'] == packets.digest(proposal['identity_decision'])
assert selection['approval_digest'] == packets.digest(proposal['operation_approval'])
assert selection['phase'] == 'merge' and selection['issuer'] == 'p1c2u'
assert selection['run_id'] == 12345 and selection['run_attempt'] == 1
assert len(selection['challenge']) == 64 and int(selection['challenge'], 16) >= 0
assert 'identity_approval_digest' not in proposal['actor_candidate']
config, policy, request, payload, approval = (proposal[key] for key in
 ('configuration', 'policy', 'request', 'payload', 'operation_approval'))
assert config['actor']['identity_approval_digest'] == selection['identity_digest']
assert config['actor']['grant']['schema_version'] == '0.2.0'
assert config['actor']['grant']['permissions'] == automatic_merge.INSTALLATION_STATUS_PERMISSIONS
assert config['actor']['grant']['repository_ids'] == [spec['repository']['id']]
assert payload['marker_ref'] == 'refs/tags/exacly-delivery-operations/' + spec['operation_key'].split(':')[1]
assert request['native_payload_digest'] == delivery.digest(payload)
assert payload['operation_profile_digest'] == automatic_merge.operation_profile_digest(config, policy)
assert approval['adapter']['configuration_digest'] == automatic_merge.configuration_digest(config, policy)
assert approval['resource_key'] == delivery.resource_key(request)
assert approval['limits'] == spec['limits']
assert stat.S_IMODE(private.stat().st_mode) == 0o700
for name in ('key', 'journal', 'config', 'policy', 'request', 'payload', 'approval', 'identity', 'mint', 'objective', 'limits', 'native_limits', 'proposal'):
 path = Path(paths[name])
 assert path.is_absolute() and path.resolve() == path and path.is_file()
 assert stat.S_IMODE(path.stat().st_mode) == 0o600
for descriptor in proposal['documents'].values():
 assert packets.digest(json.loads(Path(descriptor['path']).read_text())) == descriptor['digest']
for value in (proposal, selection):
 assert token not in json.dumps(value)
controls = private.parent / 'safe-output-controls'
controls.mkdir(mode=0o700)
safe = controls / Path(paths['proposal']).name
for value in ({'echo': token}, {'not_finite': float('nan')}, {'oversize': 'x' * (1024 * 1024 + 1)}):
 try:
  packets.write_safe(safe, value, token)
 except Exception:
  pass
 else:
  raise AssertionError('unsafe selected data reached a publishable artifact')
 assert not safe.exists()
packets.write_safe(safe, {'status': 'proposed', 'authority_granted': False}, token)
original_safe = safe.read_bytes()
assert stat.S_IMODE(safe.stat().st_mode) == 0o600
try:
 packets.write_safe(safe, {'replacement': True}, token)
except Exception:
 pass
else:
 raise AssertionError('safe output was overwritten')
assert safe.read_bytes() == original_safe
for name in ('merge.key', 'delivery.sqlite3', 'unreviewed-output.json'):
 try:
  packets.write_safe(controls / name, {'status': 'proposed'}, token)
 except Exception:
  pass
 else:
  raise AssertionError('unapproved output name was accepted')
 assert not (controls / name).exists()
automatic_merge.validate_configuration(config)
automatic_merge.validate_payload(request, payload, config, policy)
with delivery_store.opened(Path(paths['journal']), prepared['journal_id']) as journal:
 metadata = journal.metadata
 info = Path(paths['journal']).stat()
 assert (metadata['device'], metadata['inode']) == (info.st_dev, info.st_ino)
 assert journal.read()['operations'] == {}
assert socket_attempts == []
state_path = packets.save_private(prepared)
state_bytes = state_path.read_bytes()
assert token.encode() not in state_bytes and b'"_token"' not in state_bytes
assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
assert packets.save_private(prepared) == state_path and state_path.read_bytes() == state_bytes
restore_code = """
import importlib.util, json, os, sys
from pathlib import Path
source, core, private, spec_path = map(Path, sys.argv[1:])
def forbid(event, args):
 if event.startswith('socket.'):
  raise AssertionError('restore attempted provider activity')
sys.addaudithook(forbid)
loader = importlib.util.spec_from_file_location('native_trial_packets', source)
packets = importlib.util.module_from_spec(loader)
loader.loader.exec_module(packets)
profile_args = {}
if spec_path.name == 'native-supplemental-trial.json':
 protocol_loader = importlib.util.spec_from_file_location('native_trial_protocol', source.with_name('native_trial_protocol.py'))
 protocol_module = importlib.util.module_from_spec(protocol_loader)
 protocol_loader.loader.exec_module(protocol_module)
 profile_args = {'profile': protocol_module.load(source.parents[1])['profile']}
restored = packets.restore(private, core, os.environ['EXACLY_DELIVERY_MERGE_TOKEN'], **profile_args)
print(json.dumps({'journal_id': restored['journal_id'], 'packet_digest': restored['selection']['packet_digest'],
                  'observer_present': 'observer' in restored}))
"""
restore_environment = dict(os.environ)
restore_environment['EXACLY_DELIVERY_MERGE_TOKEN'] = token
restored_process = subprocess.run([sys.executable, '-I', '-B', '-c', restore_code,
 str(helper_path), str(core), str(private), str(spec_path)], env=restore_environment, stdin=subprocess.DEVNULL,
 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
assert restored_process.returncode == 0, restored_process.stderr.decode()
assert json.loads(restored_process.stdout) == {
 'journal_id': prepared['journal_id'], 'packet_digest': selection['packet_digest'], 'observer_present': False}
before_restore_checks = Path(paths['journal']).read_bytes()
try:
 packets.restore(private, core, token + '-other', **profile_args)
except Exception:
 pass
else:
 raise AssertionError('restore accepted a changed mint token')
assert Path(paths['journal']).read_bytes() == before_restore_checks
config_path = Path(paths['config'])
original_config = config_path.read_bytes()
changed_config = copy.deepcopy(config)
changed_config['actor']['grant']['permissions']['statuses'] = 'write'
config_path.write_text(json.dumps(changed_config, sort_keys=True, ensure_ascii=False, separators=(',', ':')))
try:
 try:
  packets.restore(private, core, token, **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('restore accepted a changed original document')
 assert Path(paths['journal']).read_bytes() == before_restore_checks
finally:
 config_path.write_bytes(original_config)
journal_path = Path(paths['journal'])
original_inode = journal_path.stat().st_ino
retained_journal = private / 'original-journal-for-controlled-test.sqlite3'
journal_path.rename(retained_journal)
journal_path.write_bytes(before_restore_checks)
journal_path.chmod(0o600)
assert journal_path.stat().st_ino != original_inode
try:
 try:
  packets.restore(private, core, token, **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('restore accepted a copied journal with a new inode')
 assert journal_path.read_bytes() == before_restore_checks
finally:
 journal_path.unlink()
 retained_journal.rename(journal_path)
assert journal_path.stat().st_ino == original_inode
assert state_path.read_bytes() == state_bytes
key_path = Path(paths['key'])
withheld_key = private / 'withheld-key-for-controlled-test'
key_path.rename(withheld_key)
try:
 try:
  packets.restore(private, core, token, **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('restore accepted a missing original marker key')
 assert journal_path.read_bytes() == before_restore_checks
finally:
 withheld_key.rename(key_path)
retained_key = private / 'original-key-for-controlled-test'
original_key_inode = key_path.stat().st_ino
key_path.rename(retained_key)
shutil.copyfile(retained_key, key_path)
key_path.chmod(0o600)
assert key_path.stat().st_ino != original_key_inode
try:
 try:
  packets.restore(private, core, token, **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('restore accepted a byte-identical key in a new inode')
 assert journal_path.read_bytes() == before_restore_checks
finally:
 key_path.unlink()
 retained_key.rename(key_path)
assert key_path.stat().st_ino == original_key_inode
previous_proxy = os.environ.get('https_proxy')
os.environ['https_proxy'] = 'http://controlled-runtime-change.invalid:8888'
try:
 try:
  packets.restore(private, core, token, **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('restore accepted changed effective native transport settings')
 assert journal_path.read_bytes() == before_restore_checks
finally:
 if previous_proxy is None:
  del os.environ['https_proxy']
 else:
  os.environ['https_proxy'] = previous_proxy

# Bind the pre-existing controlled native HTTP fixture to the fixed trial tuple.
fixture.REPOSITORY = {key: spec['repository'][key] for key in ('id', 'full_name')}
fixture.NODE_ID = spec['repository']['node_id']
fixture.BASE, fixture.HEAD, fixture.MERGE, fixture.TREE = (spec[name] for name in
 ('base_revision', 'head_revision', 'merge_revision', 'merge_tree'))
fixture.PREFIX = '/repos/' + spec['repository']['full_name']
fixture.BASE_REF, fixture.HEAD_REF = spec['base_ref'], spec['head_ref']
opener = fixture.ScriptedGitHub()
opener.expected_token = token
opener.repository['permissions']['push'] = False
opener.pull_request['number'] = spec['pull_request']
opener.graph['mergeStateStatus'] = 'UNSTABLE'
opener.protection['required_status_checks']['checks'] = [
 {'context': entry['name'], 'app_id': entry['app_id']} for entry in policy['required_checks']]
opener.check_runs = [
 {'name': entry['name'], 'app': {'id': entry['app_id']}, 'head_sha': spec['merge_revision'],
  'status': 'completed', 'conclusion': 'success'} for entry in policy['required_checks']]
opener.trees = {spec[revision]: [
 {'path': item['path'], 'sha': item[phase], 'type': 'blob', 'mode': '100644'}
 for item in spec['protected_files']]
 for revision, phase in (('base_revision', 'before'), ('head_revision', 'after'))}
original_respond = opener.respond
read_queries = (github_merge.READ_QUERY, github_merge.UNSTABLE_QUERY)
if supplemental:
 read_queries += (github_merge.MERGE_RECEIPT_QUERY,)
 assert 'merge_commit_sha' not in opener.respond('GET', fixture.PREFIX + '/pulls/42', None)
def controlled_response(method, path, body):
 # The reusable fixture's query assertions retain its original symbolic PR.
 # Translate only that local assertion boundary, never the actual HTTP request.
 selected = copy.deepcopy(body)
 selected_path = fixture.PREFIX + '/pulls/42' if path == fixture.PREFIX + '/pulls/' + str(spec['pull_request']) else path
 if method == 'POST' and path == '/graphql' and body['query'] in read_queries:
  selected['variables'].update(owner='owner', name='product', number=42)
 response = original_respond(method, selected_path, selected)
 if method == 'POST' and path == '/graphql' and body['query'] in read_queries:
  response['data']['repository']['databaseId'] = spec['repository']['id']
 if supplemental and method == 'GET' and selected_path == fixture.PREFIX + '/pulls/42':
  assert 'merge_commit_sha' not in response
 return response
opener.respond = controlled_response
if supplemental:
 provider = private.parent / 'controlled-provider-state'
 provider.mkdir(mode=0o700)
 for name in ('refs', 'pull_request', 'tags'):
  setattr(opener, name, SharedMapping(provider / (name + '.json'), getattr(opener, name)))
 for name in ('calls', 'mutations'):
  setattr(opener, name, SharedSequence(provider / (name + '.json'), getattr(opener, name)))
assert delivery.digest(automatic_merge.protection_snapshot(opener.protection)) == policy['protection_digest']
adapter = github_merge.GitHubMergeAdapter(config, policy, opener=opener)
engine = DeliveryEngine(Path(paths['journal']), journal_id=prepared['journal_id'], adapter_factory=lambda: adapter)
before_preview = Path(paths['journal']).read_bytes()
advisory = engine.preview(request, payload)
assert advisory['status'] == 'approval_required' and advisory['live_checked'] is False
assert Path(paths['journal']).read_bytes() == before_preview and list(opener.calls) == []

# Purely controlled authorization: no external approval or live effect is claimed.
pin = delivery.ApprovalPin(approval['issuer'], approval['approval_id'], delivery.digest(approval))
os.environ['EXACLY_DELIVERY_MERGE_TOKEN'] = token
if supplemental:
 execution_loader = importlib.util.spec_from_file_location('native_trial_execution', helper_path.with_name('native_trial_execution.py'))
 execution = importlib.util.module_from_spec(execution_loader)
 execution_loader.loader.exec_module(execution)
 execution._integrity(prepared, **profile_args)
 arguments = execution._arguments(prepared, selection)
 def public_cli():
  output = io.StringIO()
  with contextlib.redirect_stdout(output):
   try:
    code = exacly_main(arguments)
   except SystemExit as error:
    code = error.code
  assert code == 0
  return json.loads(output.getvalue())
 with patch.object(delivery_io, 'merge_adapter', return_value=adapter):
  applied = public_cli()
 assert applied['status'] == 'applied' and applied['live_checked'] is True and applied['historical'] is False
 intent, receipt = applied['intent'], applied['receipt']
 assert receipt['effect']['commit'] == spec['merge_revision']
 operation = delivery_store.show(Path(paths['journal']), prepared['journal_id'], spec['operation_key'])['operation']
 result = operation['calls'][-1]['result']
 assert [call['method'] for call in operation['calls']] == ['inspect', 'invoke']
 assert result['outcome'] == 'applied'
 saved = Path(paths['journal']).read_bytes()
 old_calls = len(opener.calls)
 actual_key = Path(paths['key'])
 withheld_key = private / 'public-cli-replay-withheld-key'
 key_inode = actual_key.stat().st_ino
 actual_key.rename(withheld_key)
 os.environ.pop('EXACLY_DELIVERY_MERGE_TOKEN')
 try:
  with patch.object(delivery_io, 'merge_adapter', side_effect=AssertionError('historical replay acquired adapter')):
   replay = public_cli()
  assert replay['historical'] is True and replay['receipt'] == receipt
  assert Path(paths['journal']).read_bytes() == saved and len(opener.calls) == old_calls
 finally:
  withheld_key.rename(actual_key)
  os.environ['EXACLY_DELIVERY_MERGE_TOKEN'] = token
 assert actual_key.stat().st_ino == key_inode
else:
 intent = engine.preview(request, payload, approval=approval, pin=pin)['packet']['intent']
 result = adapter.invoke(intent, payload, approval, deadline=execution_store.Deadline(120))
 assert result['outcome'] == 'applied'
 receipt = engine._receipt(intent, result)
 with delivery_store.opened(Path(paths['journal']), prepared['journal_id'], write=True) as retained:
  retained.prepare(intent, payload, approval, pin, now)
  call = retained.reserve_call(request['operation_key'], 'invoke', adapter.call_limits['invoke'], approval, pin, now)
  retained.update_call(request['operation_key'], call['id'], lambda item: item.update(
   owner={'process': executor_runtime.identity(os.getpid()), 'deadline_monotonic': time.monotonic() + 120}, cleanup=True))
  operation = retained.finish_call(request['operation_key'], call['id'], result, receipt)
 applied = engine._report(request, 'applied', result['reason'], operation=operation, live_checked=True)
assert result['provenance']['facts']['preflight']['review']['mergeStateStatus'] == 'UNSTABLE'
expected_reads = 58 if supplemental else 40
assert len(opener.calls) - len(opener.writes) == expected_reads and len(opener.writes) == 2
before_observer = Path(paths['journal']).read_bytes()
for wrong in ({**applied, 'status': 'uncertain'},
              {**applied, 'intent': {**intent, 'id': delivery.digest('another intent')}},
              {**applied, 'receipt': {**receipt, 'id': delivery.digest('another receipt')}}):
 try:
  packets.build_observer(prepared, wrong, now=dt.datetime.now(dt.timezone.utc), **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('observer accepted an unbound applied report')
 assert Path(paths['journal']).read_bytes() == before_observer
observer = packets.build_observer(prepared, applied, now=dt.datetime.now(dt.timezone.utc), **profile_args)
packet = observer['proposal']['packet']
assert observer['selection']['phase'] == 'observe'
assert observer['selection']['packet_digest'] == delivery.digest(packet)
assert observer['selection']['approval_digest'] == delivery.digest(packet['read_approval'])
assert observer['selection']['issuer'] == packet['read_approval']['issuer'] == 'p1c2u'
assert packet['maximum_calls'] == 1 and packet['limits']['write_calls'] == 0
assert packet['journal'] == {'path': paths['journal'], 'id': prepared['journal_id']}
assert packet['intent_id'] == intent['id'] and packet['receipt_id'] == receipt['id']
assert packet['read_approval']['approval_id'] != approval['approval_id']
automatic_merge_live.validate_packet(packet, packet_digest=observer['selection']['packet_digest'])
observer_adapter = github_merge.GitHubMergeAdapter(packet['configuration'], packet['policy'])
metadata, operation = automatic_merge_live._retained(packet, observer_adapter)
automatic_merge_live._current(packet, observer_adapter, metadata, operation)
assert Path(paths['journal']).read_bytes() == before_observer
assert not Path(observer['paths']['output_bundle']).exists()
observer_state = private / 'observer-state.json'
original_observer_state = observer_state.read_bytes()
changed_observer = json.loads(original_observer_state)
changed_observer['selection']['approval_digest'] = delivery.digest('another observer selection')
observer_state.write_text(json.dumps(changed_observer, sort_keys=True, ensure_ascii=False, separators=(',', ':')))
try:
 try:
  packets.restore(private, core, token, **profile_args)
 except Exception:
  pass
 else:
  raise AssertionError('restore accepted a changed observer selection')
 assert Path(paths['journal']).read_bytes() == before_observer
finally:
 observer_state.write_bytes(original_observer_state)
restored = packets.restore(private, core, token, **profile_args)
assert restored['observer'] == observer
assert packets.save_private(prepared) == state_path and state_path.read_bytes() == state_bytes
assert Path(paths['journal']).read_bytes() == before_observer
assert socket_attempts == []
if supplemental:
 assert proposal['runtime_profile'] == profile_args['profile']
 assert proposal['supplemental_allocation'] == allocation
 assert json.loads(Path(paths['allocation']).read_text()) == allocation
 assert proposal['documents']['allocation']['digest'] == packets.digest(allocation)
 assert prepared['spec']['objective'] == allocation['accounting']['original_objective']
 assert prepared['spec']['limits'] == allocation['accounting']['additional_limits']
 assert any(call['body'] and call['body'].get('query') == github_merge.MERGE_RECEIPT_QUERY for call in opener.calls)
 for wrong_profile in (None, {**profile_args['profile'], 'core_revision': '0' * 40}):
  try:
   execution._integrity(prepared, profile=wrong_profile)
  except Exception:
   pass
  else:
   raise AssertionError('execution accepted missing or different explicit runtime profile')
  try:
   packets.restore(private, core, token, profile=wrong_profile)
  except Exception:
   pass
  else:
   raise AssertionError('supplemental state accepted missing or different explicit runtime profile')
  assert Path(paths['journal']).read_bytes() == before_observer
 allocation_path = Path(paths['allocation'])
 original_allocation = allocation_path.read_bytes()
 changed_allocation = copy.deepcopy(allocation)
 changed_allocation['accounting']['charged_prior_limits']['operations'] = 0
 allocation_path.write_text(json.dumps(changed_allocation, sort_keys=True, separators=(',', ':')))
 try:
  try:
   packets.restore(private, core, token, **profile_args)
  except Exception:
   pass
  else:
   raise AssertionError('changed supplemental debit was accepted on restore')
  assert Path(paths['journal']).read_bytes() == before_observer
 finally:
  allocation_path.write_bytes(original_allocation)
print(json.dumps({'prepared': True, 'controlled_native_reads': expected_reads, 'controlled_native_writes': 2,
                  'observer_bound': True, 'same_job_restore': True, 'socket_attempts': 0}))
'''


def load_packets():
    selected = importlib.util.spec_from_file_location('native_trial_packets', ROOT / 'tools/native_trial_packets.py')
    module = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(module)
    return module


class NativeTrialPacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-packet-tests-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.private = self.directory / 'private'
        self.packets = load_packets()

    def prepare(self, *, spec=None, context=None, token=TOKEN, installation_id=177653055, now=NOW):
        return self.packets.prepare(
            self.private, copy.deepcopy(SPEC if spec is None else spec),
            copy.deepcopy(CONTEXT if context is None else context), CORE, token, installation_id, now=now)

    def test_content_digest_is_canonical_but_does_not_claim_approval(self):
        value = {'status': 'proposed', 'authority_granted': False, 'nested': {'second': 2, 'first': 1}}
        reordered = {'nested': {'first': 1, 'second': 2}, 'authority_granted': False, 'status': 'proposed'}
        expected = 'sha256:' + hashlib.sha256(json.dumps(
            value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        self.assertEqual(self.packets.digest(value), expected)
        self.assertEqual(self.packets.digest(value), self.packets.digest(reordered))
        self.assertNotEqual(self.packets.digest(value), self.packets.digest({**value, 'authority_granted': True}))

    def test_wrong_host_context_stops_before_loading_native_or_creating_material(self):
        changes = (
            ('repository', 'other/repository'), ('repository_id', 999), ('source', 'not-a-commit'),
            ('run_id', True), ('run_attempt', 2), ('workflow_ref', CONTEXT['workflow_ref'] + '/other'),
            ('ref', 'refs/heads/main'), ('job', 'other-job'),
        )
        for field, value in changes:
            with self.subTest(field=field), patch.object(self.packets, '_load_native') as native:
                changed = {**CONTEXT, field: value}
                with self.assertRaises(Exception):
                    self.prepare(context=changed)
                native.assert_not_called()
                self.assertFalse(self.private.exists())

    def test_wrong_fixed_target_cannot_become_another_delivery_proposal(self):
        changes = (
            ('core_revision', 'd' * 40), ('app_id', 1), ('installation_id', 1),
            ('pull_request', 6), ('base_revision', 'd' * 40), ('head_revision', 'd' * 40),
            ('merge_revision', 'd' * 40), ('merge_tree', 'd' * 40), ('base_ref', 'refs/heads/other'),
        )
        for field, value in changes:
            with self.subTest(field=field), patch.object(self.packets, '_load_native') as native:
                changed = {**SPEC, field: value}
                with self.assertRaises(Exception):
                    self.prepare(spec=changed)
                native.assert_not_called()
                self.assertFalse(self.private.exists())

    def test_invalid_mint_or_local_time_never_reaches_native_material_creation(self):
        for changed in ({'token': 'short'}, {'token': TOKEN + '\n'}, {'installation_id': True},
                        {'installation_id': 177653019}, {'now': NOW.replace(tzinfo=None)}):
            with self.subTest(fields=tuple(changed)), patch.object(self.packets, '_load_native') as native:
                with self.assertRaises(Exception):
                    self.prepare(**changed)
                native.assert_not_called()
                self.assertFalse(self.private.exists())

    def test_unverified_source_fails_before_native_import_or_key_journal_initialization(self):
        untrusted = self.directory / 'untrusted-core'
        untrusted.mkdir()
        imported = []
        original = __import__
        def track(name, *args, **kwargs):
            if name == 'exacly' or name.startswith('exacly.'):
                imported.append(name)
                raise AssertionError('unverified source reached native import')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=track), self.assertRaises(Exception):
            self.packets.prepare(self.private, copy.deepcopy(SPEC), copy.deepcopy(CONTEXT),
                                 untrusted, TOKEN, 177653055, now=NOW)
        self.assertEqual(imported, [])
        self.assertFalse(any(self.private.glob('*')))

    def test_existing_private_directory_is_never_reused_or_overwritten(self):
        self.private.mkdir(mode=0o700)
        original = self.private / 'owner-retained.txt'
        original.write_text('must survive')
        with self.assertRaises(Exception):
            self.prepare()
        self.assertEqual(original.read_text(), 'must survive')
        self.assertEqual({item.name for item in self.private.iterdir()}, {original.name})

    @unittest.skipUnless(CORE.is_dir(), 'set EXACLY_NATIVE_TRIAL_TEST_CORE to the exact pinned core checkout')
    def test_actual_pinned_native_prepare_and_controlled_observer_binding_without_sockets(self):
        runtime_names = {
            'PATH', 'LANG', 'LC_ALL', 'TZ', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
        }
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', NATIVE_INTEGRATION,
             str(ROOT / 'tools/native_trial_packets.py'), str(CORE),
             str(ROOT / 'config/native-positive-trial.json'), str(self.private)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, check=False, env={key: value for key, value in os.environ.items() if key in runtime_names},
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(TOKEN, result.stdout.decode())
        self.assertEqual(json.loads(result.stdout), {
            'prepared': True, 'controlled_native_reads': 40, 'controlled_native_writes': 2,
            'observer_bound': True, 'same_job_restore': True, 'socket_attempts': 0})


if __name__ == '__main__':
    unittest.main()

