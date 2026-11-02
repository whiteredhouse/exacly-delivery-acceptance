"""Offline producer-boundary checks; native grant policy is tested in Exacly."""
import copy
from contextlib import redirect_stdout
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('app_grant_preflight', ROOT / 'tools/app_grant_preflight.py')
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)
NOW = dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc)
TOKEN = 'fixture-app-token-must-never-be-rendered'
SOURCE = 'f' * 40
REPOSITORY = {'id': 1442278205, 'full_name': 'whiteredhouse/exacly-delivery-acceptance', 'node_id': 'R_kgDOVfdrPQ'}
PERMISSIONS = {'contents': 'write', 'administration': 'read', 'checks': 'read', 'metadata': 'read', 'pull_requests': 'read'}
PREFIX = '/repos/whiteredhouse/exacly-delivery-acceptance'
MAIN = '723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8'
SNAPSHOT = {
    'checks': [{'context': 'exacly-generated-merge', 'app_id': 5572341}],
    'strict': True, 'approvals': 1, 'last_push_approval': True,
    'dismiss_stale_reviews': True, 'code_owners': False, 'enforce_admins': True,
    'required_linear_history': False, 'allow_force_pushes': False,
    'allow_deletions': False, 'required_conversation_resolution': True,
    'lock_branch': False, 'required_signatures': False,
}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def protection():
    return {
        'required_status_checks': {'strict': True, 'checks': copy.deepcopy(SNAPSHOT['checks'])},
        'required_pull_request_reviews': {
            'required_approving_review_count': 1, 'require_last_push_approval': True,
            'dismiss_stale_reviews': True, 'require_code_owner_reviews': False,
            'bypass_pull_request_allowances': {'users': [], 'teams': [], 'apps': []},
        },
        **{key: {'enabled': SNAPSHOT[key]} for key in (
            'enforce_admins', 'required_linear_history', 'allow_force_pushes',
            'allow_deletions', 'required_conversation_resolution', 'lock_branch', 'required_signatures')},
    }


class Backend:
    def __init__(self):
        self.calls = []
        self.fail_path = None
        self.repository = {
            **REPOSITORY, 'private': False, 'default_branch': 'main', 'archived': False, 'disabled': False,
            'owner': {'login': 'whiteredhouse', 'id': 216294095, 'type': 'Organization'},
            'permissions': {'admin': False, 'maintain': False, 'push': False},
        }
        self.scope = {'total_count': 1, 'repositories': [copy.deepcopy(self.repository)]}
        self.protection = protection()
        self.responses = {
            PREFIX: self.repository,
            '/installation/repositories?per_page=100': self.scope,
            PREFIX + '/git/ref/heads/main': {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': MAIN}},
            PREFIX + '/branches/main/protection': self.protection,
            PREFIX + '/branches/main/protection/required_signatures': {'enabled': False},
            PREFIX + '/rules/branches/main': [],
        }

    def sender(self, method, url, headers, payload, timeout):
        self.calls.append((method, url, payload))
        if method != 'GET' or payload is not None:
            raise AssertionError('producer attempted a provider mutation')
        if headers.get('Authorization') != 'Bearer ' + TOKEN:
            raise AssertionError('producer did not use the selected token')
        path = url.removeprefix('https://api.github.com')
        if path == self.fail_path:
            raise RuntimeError(TOKEN)
        return 200, encoded(self.responses[path])


class NativeBoundary:
    """Records native API use without copying its schema or merge implementation."""
    INSTALLATION_GRANT_KIND = 'github-app-installation-grant-v1'
    INSTALLATION_GRANT_VERSION = '0.1.0'

    def __init__(self, backend):
        self.backend = backend
        self.time_calls = []
        self.candidate_calls = []
        self.snapshot_calls = []
        self.facts_calls = []
        self.expire_after_reads = None
        self.selected_snapshot = copy.deepcopy(SNAPSHOT)

    def validate_installation_grant_time(self, actor, *, now):
        self.time_calls.append((copy.deepcopy(actor), now, len(self.backend.calls)))
        if self.expire_after_reads is not None and len(self.backend.calls) >= self.expire_after_reads:
            raise ValueError('controlled expired native lease')

    def validate_installation_grant_candidate(self, repository, actor, facts):
        self.candidate_calls.append((copy.deepcopy(repository), copy.deepcopy(actor), copy.deepcopy(facts)))
        if 'identity_approval_digest' in actor or actor['grant']['permissions'] != PERMISSIONS:
            raise ValueError('controlled native candidate refusal')
        if facts['repository']['admin'] is True or facts['repository']['maintain'] is True:
            raise ValueError('controlled broad actor refusal')
        if facts['installation_repository_ids'] != [REPOSITORY['id']]:
            raise ValueError('controlled broad scope refusal')
        return copy.deepcopy(actor)

    def protection_snapshot(self, value):
        self.snapshot_calls.append(copy.deepcopy(value))
        return copy.deepcopy(self.selected_snapshot)

    def protection_facts(self, value):
        self.facts_calls.append(copy.deepcopy(value))
        return protection()


class AppGrantPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='app-grant-producer-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.workspace = self.directory / 'workspace'
        self.workspace.mkdir()
        self.out = self.directory / 'evidence'
        self.backend = Backend()
        self.native = NativeBoundary(self.backend)
        self.environment = {
            'GITHUB_ACTIONS': 'true',
            'GITHUB_REPOSITORY': REPOSITORY['full_name'], 'GITHUB_REPOSITORY_ID': str(REPOSITORY['id']),
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/codex/preflight-diagnostics',
            'GITHUB_WORKFLOW_REF': REPOSITORY['full_name'] + '/.github/workflows/app-bootstrap.yml@refs/heads/codex/preflight-diagnostics',
            'GITHUB_SHA': SOURCE, 'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_JOB': 'app-grant-preflight', 'CANARY_INSTALLATION_ID': '177653055',
            'CANARY_APP_TOKEN': TOKEN, 'RUNNER_TEMP': str(self.directory), 'GITHUB_WORKSPACE': str(self.workspace),
        }

    def run_preflight(self):
        printed = io.StringIO()
        with patch.dict(os.environ, self.environment), redirect_stdout(printed):
            result = preflight.run_preflight(self.out, native=self.native, sender=self.backend.sender, clock=lambda: NOW)
        text = json.dumps(result) + printed.getvalue()
        for path in self.out.glob('*.json'):
            text += path.read_text()
        self.assertNotIn(TOKEN, text)
        return result

    def test_candidate_binds_actual_mint_inputs_and_cannot_self_approve(self):
        with patch.dict(os.environ, self.environment):
            attestation = preflight.build_mint_attestation(TOKEN, 177653055, NOW)
            candidate = preflight.build_candidate(attestation, NOW)
        self.assertNotIn(TOKEN, json.dumps(attestation))
        self.assertEqual(candidate['token_digest'], 'sha256:' + hashlib.sha256(TOKEN.encode()).hexdigest())
        self.assertEqual(candidate['app_id'], 5572362)
        self.assertEqual(candidate['installation_id'], 177653055)
        self.assertNotIn('identity_approval_digest', candidate)
        self.assertEqual(candidate['grant']['repository_ids'], [REPOSITORY['id']])
        self.assertEqual(candidate['grant']['permissions'], PERMISSIONS)
        self.assertEqual(candidate['grant']['mint_provenance_digest'], 'sha256:' + hashlib.sha256(encoded(attestation)).hexdigest())
        self.assertIn(SOURCE, json.dumps(attestation))
        self.assertIn('64ab729a6294000f5aa4a4bc0b73d1f32bc45510', json.dumps(attestation))
        self.assertIs(attestation['provider_mint_response_retained'], False)
        self.assertIs(attestation['provider_expiry_verified'], False)
        self.assertEqual(attestation['local_use_lease_seconds'], 900)
        start = dt.datetime.fromisoformat(candidate['grant']['not_before'].replace('Z', '+00:00'))
        end = dt.datetime.fromisoformat(candidate['grant']['not_after'].replace('Z', '+00:00'))
        self.assertEqual(end - start, dt.timedelta(seconds=900))

    def test_retained_attestation_cannot_silently_renew_a_later_local_lease(self):
        with patch.dict(os.environ, self.environment):
            attestation = preflight.build_mint_attestation(TOKEN, 177653055, NOW)
        original = copy.deepcopy(attestation)
        for elapsed in (1, 900, 3600):
            with self.subTest(elapsed=elapsed), self.assertRaises(preflight.Stopped):
                preflight.build_candidate(attestation, NOW + dt.timedelta(seconds=elapsed))
        self.assertEqual(attestation, original)

    def test_candidate_builder_refuses_changed_mint_scope_or_assurance_claims(self):
        with patch.dict(os.environ, self.environment):
            original = preflight.build_mint_attestation(TOKEN, 177653055, NOW)
        changes = [
            ('app_id', 999), ('installation_id', 999),
            ('repository', {**REPOSITORY, 'node_id': 'other-node'}),
            ('requested_repository_ids', [REPOSITORY['id'], 999]),
            ('requested_permissions', {**PERMISSIONS, 'administration': 'write'}),
            ('local_use_lease_seconds', 3601), ('local_use_lease_seconds', True),
            ('workflow_ref', 'other/repository/.github/workflows/other.yml@refs/heads/main'),
            ('mint_action', 'actions/create-github-app-token@' + '0' * 40),
            ('exacly_source_commit', '0' * 40), ('token_digest', TOKEN),
            ('provider_mint_response_retained', True), ('provider_expiry_verified', True),
            ('independent_mint_approval', True), ('merge_authority', True),
        ]
        for field, changed in changes:
            with self.subTest(field=field, value_type=type(changed).__name__):
                attestation = copy.deepcopy(original)
                attestation[field] = changed
                with self.assertRaises(preflight.Stopped):
                    preflight.build_candidate(attestation, NOW)

    def test_tampered_native_files_are_refused_before_package_import(self):
        source = self.directory / 'native-source'
        package = source / 'python/src/exacly'
        package.mkdir(parents=True)
        trusted = {'automatic_merge.py': b'# controlled trusted merge module\n',
                   'github_merge.py': b'# controlled trusted adapter module\n'}
        pins = {name: hashlib.sha256(data).hexdigest() for name, data in trusted.items()}
        completed = subprocess.CompletedProcess([], 0, (preflight.CORE_REVISION + '\n').encode(), b'')
        original_import = __import__
        imported_native = []
        def record_import(name, *args, **kwargs):
            if name == 'exacly' or name.startswith('exacly.'):
                imported_native.append(name)
                raise AssertionError('native import occurred before source verification')
            return original_import(name, *args, **kwargs)
        for damaged in trusted:
            with self.subTest(file=damaged):
                for name, content in trusted.items():
                    (package / name).write_bytes(content + (b'# tampered\n' if name == damaged else b''))
                with patch.dict(preflight.NATIVE_PINS, pins, clear=True), \
                     patch.object(preflight.subprocess, 'run', return_value=completed), \
                     patch('builtins.__import__', side_effect=record_import), \
                     self.assertRaises(preflight.Stopped):
                    preflight.load_native(source)
        self.assertEqual(imported_native, [])

    def test_success_uses_native_boundaries_six_gets_and_private_advisory_outputs(self):
        result = self.run_preflight()
        self.assertTrue(result['credential_and_protection_candidate_checks_passed'])
        for key in ('independent_mint_approval', 'pr_readiness_verified', 'merge_authority'):
            self.assertIs(result[key], False)
        self.assertEqual(len(self.backend.calls), 6)
        self.assertEqual([call[0] for call in self.backend.calls], ['GET'] * 6)
        self.assertTrue(all(any(read_count == i for _, _, read_count in self.native.time_calls) for i in range(6)))
        self.assertTrue(self.native.candidate_calls)
        self.assertTrue(self.native.snapshot_calls)
        self.assertTrue(self.native.facts_calls)
        self.assertEqual({path.name for path in self.out.iterdir()}, {'mint-attestation.json', 'actor-candidate.json', 'preflight.json'})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in self.out.iterdir()))

    def test_raw_false_and_unknown_roles_are_not_replaced_by_push_authority(self):
        self.backend.repository['permissions'] = {'admin': False}
        result = self.run_preflight()
        self.assertTrue(result['credential_and_protection_candidate_checks_passed'])
        facts = self.native.candidate_calls[-1][2]['repository']
        self.assertEqual({key: facts[key] for key in ('admin', 'maintain', 'push')}, {'admin': False, 'maintain': None, 'push': None})

    def test_broad_scope_and_broad_actor_are_not_accepted(self):
        self.backend.scope['total_count'] = 2
        self.backend.scope['repositories'].append({'id': 999, 'full_name': 'other/repository'})
        result = self.run_preflight()
        self.assertFalse(result['credential_and_protection_candidate_checks_passed'])
        self.assertTrue(all(call[0] == 'GET' for call in self.backend.calls))

    def test_native_rejection_of_actual_administrator_is_preserved(self):
        self.backend.repository['permissions']['admin'] = True
        result = self.run_preflight()
        self.assertFalse(result['credential_and_protection_candidate_checks_passed'])

    def test_wrong_installation_or_rerun_does_not_contact_provider(self):
        for name, wrong in [('CANARY_INSTALLATION_ID', '177653019'), ('GITHUB_RUN_ATTEMPT', '2')]:
            with self.subTest(field=name):
                previous = self.environment[name]
                self.environment[name] = wrong
                result = self.run_preflight()
                self.assertFalse(result['credential_and_protection_candidate_checks_passed'])
                self.assertEqual(self.backend.calls, [])
                self.environment[name] = previous

    def test_token_binding_and_get_only_allowlist_fail_before_transport(self):
        with patch.dict(os.environ, self.environment):
            attestation = preflight.build_mint_attestation(TOKEN, 177653055, NOW)
            candidate = preflight.build_candidate(attestation, NOW)
        reader = preflight.FixedReads(TOKEN, candidate, self.native, sender=self.backend.sender, clock=lambda: NOW)
        with self.assertRaises(preflight.Stopped):
            reader.request('POST', PREFIX + '/check-runs', {})
        with self.assertRaises(preflight.Stopped):
            reader.request('GET', 'https://api.github.com.evil.invalid' + PREFIX)
        candidate['token_digest'] = 'sha256:' + '0' * 64
        with self.assertRaises(preflight.Stopped):
            reader.request('GET', preflight.READS[0])
        self.assertEqual(self.backend.calls, [])

    def test_lease_failure_before_third_get_prevents_further_activity(self):
        self.native.expire_after_reads = 2
        result = self.run_preflight()
        self.assertFalse(result['credential_and_protection_candidate_checks_passed'])
        self.assertEqual(len(self.backend.calls), 2)

    def test_unavailable_transport_is_redacted_and_never_retried(self):
        self.backend.fail_path = PREFIX + '/branches/main/protection'
        result = self.run_preflight()
        self.assertFalse(result['credential_and_protection_candidate_checks_passed'])
        self.assertEqual(sum(url.endswith(self.backend.fail_path) for _, url, _ in self.backend.calls), 1)

    def test_native_snapshot_must_equal_the_approved_canary_policy(self):
        self.native.selected_snapshot['strict'] = False
        result = self.run_preflight()
        self.assertFalse(result['credential_and_protection_candidate_checks_passed'])

    def test_existing_private_output_is_never_reused_or_overwritten(self):
        self.assertTrue(self.run_preflight()['credential_and_protection_candidate_checks_passed'])
        original = {path.name: path.read_bytes() for path in self.out.iterdir()}
        self.backend.calls.clear()
        self.assertFalse(self.run_preflight()['credential_and_protection_candidate_checks_passed'])
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.out.iterdir()})

    def test_import_does_not_require_the_exacly_package(self):
        script = 'import runpy,sys; runpy.run_path(sys.argv[1]); assert not any(n == "exacly" or n.startswith("exacly.") for n in sys.modules)'
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT / 'tools/app_grant_preflight.py')],
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
