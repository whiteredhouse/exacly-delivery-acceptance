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
PERMISSIONS = {'contents': 'write', 'administration': 'read', 'checks': 'read', 'metadata': 'read', 'pull_requests': 'read', 'statuses': 'read'}
PREFIX = '/repos/whiteredhouse/exacly-delivery-acceptance'
MAIN = '723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8'
HEAD = '7e5f04446bd7eb2bd69132f27e8d20c9a967a156'
MERGE = '3196bd964e77c0963d2f00ff20c71408a345b54c'
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


class NativeGitHubBoundary:
    # A distinct sentinel proves forwarding from the injected native module;
    # the production query is obtained only from the verified installed source.
    UNSTABLE_QUERY = 'query($owner:String!){controlledRead}'


class Backend:
    def __init__(self):
        self.calls = []
        self.fail_path = None
        self.http_status = {}
        self.raw_bodies = {}
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
            **{path: {'sha': sha, 'state': 'pending', 'total_count': 0, 'statuses': []}
               for path, sha in zip(preflight.STATUS_READS, (HEAD, MERGE))},
            '/graphql': {'data': {'repository': {
                'id': REPOSITORY['node_id'], 'databaseId': REPOSITORY['id'], 'nameWithOwner': REPOSITORY['full_name'],
                'ref': {'prefix': 'refs/heads/', 'name': 'main', 'target': {'oid': MAIN},
                        'branchProtectionRule': {
                            'id': 'BPR_controlled_main', 'pattern': 'main', 'requiresDeployments': False,
                            'requiredDeploymentEnvironments': [], 'requiresConversationResolution': True,
                            'restrictsPushes': False}},
                'pullRequest': {'number': 5, 'headRefOid': HEAD, 'baseRefOid': MAIN, 'potentialMergeCommit': {'oid': MERGE},
                                'reviewThreads': {'totalCount': 0, 'pageInfo': {'hasNextPage': False}, 'nodes': []}},
            }}},
            preflight.COMPARE_READ: {
                'base_commit': {'sha': MAIN}, 'merge_base_commit': {'sha': MAIN},
                'status': 'ahead', 'ahead_by': 1, 'behind_by': 0, 'total_commits': 1,
                'commits': [{'sha': HEAD}],
            },
        }

    def sender(self, method, url, headers, payload, timeout):
        self.calls.append((method, url, payload))
        if headers.get('Authorization') != 'Bearer ' + TOKEN:
            raise AssertionError('producer did not use the selected token')
        path = url.removeprefix('https://api.github.com')
        if method == 'POST':
            if (path != '/graphql' or payload != {'query': NativeGitHubBoundary.UNSTABLE_QUERY,
                                                 'variables': preflight.QUERY_VARIABLES}):
                raise AssertionError('producer attempted an unreviewed GraphQL operation')
            if headers.get('Content-Type') != 'application/json':
                raise AssertionError('producer omitted GraphQL content type')
        elif method != 'GET' or payload is not None or path == '/graphql':
            raise AssertionError('producer attempted a provider mutation')
        if path == self.fail_path:
            raise RuntimeError(TOKEN)
        return self.http_status.get(path, 200), self.raw_bodies.get(path, encoded(self.responses[path]))


class NativeBoundary:
    """Records native API use without copying its schema or merge implementation."""
    INSTALLATION_GRANT_KIND = 'github-app-installation-grant-v1'
    INSTALLATION_GRANT_VERSION = '0.1.0'
    INSTALLATION_STATUS_GRANT_VERSION = '0.2.0'

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
        if ('identity_approval_digest' in actor or actor['grant']['permissions'] != PERMISSIONS
                or actor['grant']['schema_version'] != '0.2.0'):
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
        self.case_number = 0
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
            result = preflight.run_preflight(self.out, native=(self.native, NativeGitHubBoundary),
                                            sender=self.backend.sender, clock=lambda: NOW)
        text = json.dumps(result) + printed.getvalue()
        for path in self.out.glob('*.json'):
            text += path.read_text()
        self.assertNotIn(TOKEN, text)
        return result

    def reset_probe_case(self):
        self.case_number += 1
        self.out = self.directory / ('evidence-' + str(self.case_number))
        self.backend = Backend()
        self.native = NativeBoundary(self.backend)

    def reader(self):
        with patch.dict(os.environ, self.environment):
            attestation = preflight.build_mint_attestation(TOKEN, 177653055, NOW)
            candidate = preflight.build_candidate(attestation, NOW)
        return preflight.FixedReads(TOKEN, candidate, self.native, NativeGitHubBoundary.UNSTABLE_QUERY,
                                    sender=self.backend.sender, clock=lambda: NOW)

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
        self.assertEqual(candidate['grant']['schema_version'], '0.2.0')
        self.assertEqual(attestation['schema_version'], '0.1.0')
        self.assertEqual(attestation['exacly_source_commit'], '9a5cd90b8d3c3b2acc2a00e7e68e175558025432')
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
            ('fact_read_api_version', '2022-11-28'),
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

    def test_success_uses_native_boundaries_ten_reads_and_private_advisory_outputs(self):
        result = self.run_preflight()
        self.assertTrue(result['credential_and_protection_candidate_checks_passed'])
        self.assertTrue(result['endpoint_access_checks_passed'])
        for key in ('independent_mint_approval', 'pr_readiness_verified', 'merge_authority'):
            self.assertIs(result[key], False)
        self.assertEqual(len(self.backend.calls), 10)
        self.assertEqual(result['provider_reads'], 10)
        self.assertEqual([call[0] for call in self.backend.calls], ['GET'] * 8 + ['POST', 'GET'])
        self.assertEqual([url for _, url, _ in self.backend.calls[:6]], [preflight.API + path for path in preflight.READS])
        self.assertTrue(all(any(read_count == i for _, _, read_count in self.native.time_calls) for i in range(10)))
        self.assertTrue(self.native.candidate_calls)
        self.assertTrue(self.native.snapshot_calls)
        self.assertTrue(self.native.facts_calls)
        self.assertEqual({path.name for path in self.out.iterdir()}, {
            'mint-attestation.json', 'actor-candidate.json', 'preflight.json', 'readiness-endpoint-facts.json'})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in self.out.iterdir()))

    def test_fact_reads_and_attestation_use_the_pinned_native_api_version(self):
        headers_seen = []
        original = self.backend.sender
        def capture(method, url, headers, payload, timeout):
            headers_seen.append(headers.get('X-GitHub-Api-Version'))
            return original(method, url, headers, payload, timeout)
        self.backend.sender = capture
        result = self.run_preflight()
        self.assertTrue(result['credential_and_protection_candidate_checks_passed'])
        # Native github_merge.py at the pinned source uses this exact protocol.
        self.assertEqual(headers_seen, ['2026-03-10'] * 10)
        attestation = json.loads((self.out / 'mint-attestation.json').read_text())
        self.assertEqual(attestation['fact_read_api_version'], '2026-03-10')

    def test_endpoint_access_does_not_claim_native_readiness(self):
        self.backend.responses[preflight.STATUS_READS[0]].update(
            total_count=1, statuses=[{'context': 'exacly-generated-merge', 'state': 'failure'}])
        repository = self.backend.responses['/graphql']['data']['repository']
        repository['ref']['branchProtectionRule'].update(
            requiresDeployments=True, requiredDeploymentEnvironments=['production'], restrictsPushes=True)
        repository['pullRequest']['reviewThreads'].update(
            totalCount=1, nodes=[{'id': 'PRRT_unresolved', 'isResolved': False}])
        self.backend.responses[preflight.COMPARE_READ].update(
            status='diverged', behind_by=2, merge_base_commit={'sha': 'c' * 40})
        result = self.run_preflight()
        self.assertTrue(result['endpoint_access_checks_passed'])
        self.assertIs(result['pr_readiness_verified'], False)
        facts = json.loads((self.out / 'readiness-endpoint-facts.json').read_text())
        self.assertEqual(facts['legacy_statuses']['head']['statuses'][0]['state'], 'failure')
        self.assertTrue(facts['branch_policy']['requires_deployments'])
        self.assertFalse(facts['review_threads']['threads'][0]['is_resolved'])
        self.assertEqual(facts['comparison']['behind_by'], 2)
        for key in ('pr_readiness_verified', 'independent_mint_approval', 'merge_authority'):
            self.assertIs(facts[key], False)

    def test_opaque_failure_of_each_new_endpoint_counts_once_and_stops(self):
        paths = (*preflight.STATUS_READS, '/graphql', preflight.COMPARE_READ)
        for index, path in enumerate(paths, 7):
            with self.subTest(endpoint=path):
                self.reset_probe_case()
                self.backend.http_status[path] = 403
                self.backend.responses[path] = {'message': TOKEN}
                result = self.run_preflight()
                self.assertTrue(result['credential_and_protection_candidate_checks_passed'])
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], index)
                self.assertEqual(len(self.backend.calls), index)
                self.assertFalse((self.out / 'readiness-endpoint-facts.json').exists())

    def test_graphql_errors_and_null_protection_cannot_prove_access(self):
        for damage in ('errors', 'null-policy'):
            with self.subTest(damage=damage):
                self.reset_probe_case()
                response = self.backend.responses['/graphql']
                if damage == 'errors':
                    response['errors'] = [{'message': TOKEN}]
                else:
                    response['data']['repository']['ref']['branchProtectionRule'] = None
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], 9)
                self.assertEqual(result['stage'], 'graphql_policy_access')

    def test_query_response_is_bound_to_repository_ref_and_exact_pr_tuple(self):
        for damage in ('repository', 'ref', 'base-ref', 'number', 'head', 'base', 'merge'):
            with self.subTest(damage=damage):
                self.reset_probe_case()
                repository = self.backend.responses['/graphql']['data']['repository']
                if damage == 'repository':
                    repository['databaseId'] = 999
                elif damage == 'ref':
                    repository['ref']['name'] = 'other'
                elif damage == 'base-ref':
                    repository['ref']['target']['oid'] = 'd' * 40
                else:
                    pr = repository['pullRequest']
                    if damage == 'number':
                        pr['number'] = 6
                    elif damage == 'merge':
                        pr['potentialMergeCommit']['oid'] = 'd' * 40
                    else:
                        pr['headRefOid' if damage == 'head' else 'baseRefOid'] = 'd' * 40
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], 9)

    def test_status_access_requires_complete_bounded_typed_inventory(self):
        for damage in ('wrong-sha', 'truncated', 'ceiling', 'boolean-count', 'malformed-status'):
            with self.subTest(damage=damage):
                self.reset_probe_case()
                value = self.backend.responses[preflight.STATUS_READS[0]]
                if damage == 'wrong-sha':
                    value['sha'] = MERGE
                elif damage == 'truncated':
                    value['total_count'] = 1
                elif damage == 'ceiling':
                    value.update(total_count=100, statuses=[{'context': 'optional', 'state': 'success'}] * 100)
                elif damage == 'boolean-count':
                    value['total_count'] = False
                else:
                    value.update(total_count=1, statuses=[{'context': 'optional', 'state': {'message': TOKEN}}])
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], 7)

    def test_thread_access_requires_complete_inventory_but_not_resolved_threads(self):
        for damage in ('next-page', 'count', 'ceiling', 'unknown-resolution'):
            with self.subTest(damage=damage):
                self.reset_probe_case()
                threads = self.backend.responses['/graphql']['data']['repository']['pullRequest']['reviewThreads']
                if damage == 'next-page':
                    threads['pageInfo']['hasNextPage'] = True
                elif damage == 'count':
                    threads['totalCount'] = 1
                elif damage == 'ceiling':
                    threads.update(totalCount=100, nodes=[{'id': str(i), 'isResolved': False} for i in range(100)])
                else:
                    threads.update(totalCount=1, nodes=[{'id': 'PRRT_unknown', 'isResolved': None}])
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], 9)

    def test_compare_access_binds_base_head_and_complete_commit_inventory(self):
        for damage in ('base', 'head', 'count', 'duplicate', 'ceiling'):
            with self.subTest(damage=damage):
                self.reset_probe_case()
                value = self.backend.responses[preflight.COMPARE_READ]
                if damage == 'base':
                    value['base_commit']['sha'] = 'd' * 40
                elif damage == 'head':
                    value['commits'][-1]['sha'] = 'd' * 40
                elif damage == 'count':
                    value['total_commits'] = 2
                elif damage == 'duplicate':
                    value.update(ahead_by=2, total_commits=2, commits=[{'sha': HEAD}] * 2)
                else:
                    value.update(ahead_by=100, total_commits=100, commits=[{'sha': HEAD}] * 100)
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], 10)

    def test_fixed_query_cannot_be_replaced_or_mutated_and_total_attempts_are_bounded(self):
        reader = self.reader()
        for path in (*preflight.READS, *preflight.STATUS_READS):
            reader.request('GET', path)
        payload = {'query': NativeGitHubBoundary.UNSTABLE_QUERY, 'variables': dict(preflight.QUERY_VARIABLES)}
        for method, path, body in (
                ('POST', '/graphql', {**payload, 'query': 'mutation{updateRefs{clientMutationId}}'}),
                ('POST', '/graphql', {**payload, 'query': payload['query'] + ' '}),
                ('POST', '/graphql', {**payload, 'variables': {**payload['variables'], 'number': 6}}),
                ('POST', PREFIX + '/pulls/5/merge', {}),
                ('GET', PREFIX + '/commits/' + HEAD + '/status?per_page=99', None)):
            with self.subTest(method=method, path=path), self.assertRaises(preflight.Stopped):
                reader.request(method, path, body)
        self.assertEqual(len(self.backend.calls), 8)
        reader.request('POST', '/graphql', payload)
        reader.request('GET', preflight.COMPARE_READ)
        self.assertEqual(len(self.backend.calls), 10)
        with self.assertRaises(preflight.Stopped):
            reader.request('GET', preflight.READS[0])
        self.assertEqual(len(self.backend.calls), 10)

    def test_failed_attempt_cannot_be_retried_or_replaced_by_a_later_probe(self):
        reader = self.reader()
        self.backend.http_status[preflight.READS[0]] = 403
        with self.assertRaises(preflight.Stopped):
            reader.request('GET', preflight.READS[0])
        with self.assertRaises(preflight.Stopped):
            reader.request('GET', preflight.READS[0])
        with self.assertRaises(preflight.Stopped):
            reader.request('GET', preflight.READS[1])
        self.assertEqual(len(reader.seen), 1)
        self.assertEqual(len(self.backend.calls), 1)

    def test_lease_is_rechecked_between_each_additional_endpoint(self):
        for count in (6, 7, 8, 9):
            with self.subTest(after_reads=count):
                self.reset_probe_case()
                self.native.expire_after_reads = count
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(len(self.backend.calls), count)

    def test_work_deadline_expiring_during_lease_check_stops_before_next_http_attempt(self):
        tick = [0]
        validate = self.native.validate_installation_grant_time
        def expire(actor, *, now):
            validate(actor, now=now)
            if len(self.backend.calls) == 7:
                tick[0] = 76
        self.native.validate_installation_grant_time = expire
        with patch.object(preflight.time, 'monotonic', side_effect=lambda: tick[0]):
            result = self.run_preflight()
        self.assertFalse(result['endpoint_access_checks_passed'])
        self.assertEqual(result['provider_reads'], 7)
        self.assertEqual(len(self.backend.calls), 7)

    def test_new_read_json_is_unique_finite_and_bounded(self):
        for body in (b'{"sha":"wrong","sha":"also-wrong"}', b'{"total_count":NaN}', b'x' * (preflight.MAX_RESPONSE + 1)):
            with self.subTest(body_prefix=body[:16]):
                self.reset_probe_case()
                self.backend.raw_bodies[preflight.STATUS_READS[0]] = body
                result = self.run_preflight()
                self.assertFalse(result['endpoint_access_checks_passed'])
                self.assertEqual(result['provider_reads'], 7)

    def test_only_selected_public_fields_reach_endpoint_artifact(self):
        self.backend.responses[preflight.COMPARE_READ]['files'] = [{'patch': TOKEN}]
        self.backend.responses[preflight.COMPARE_READ]['commits'][0]['commit'] = {'message': TOKEN}
        self.backend.responses['/graphql']['data']['repository']['debug'] = TOKEN
        self.backend.responses[preflight.STATUS_READS[0]]['debug'] = TOKEN
        result = self.run_preflight()
        self.assertTrue(result['endpoint_access_checks_passed'])
        facts = json.loads((self.out / 'readiness-endpoint-facts.json').read_text())
        self.assertEqual(facts['comparison']['commit_revisions'], [HEAD])
        self.assertNotIn('files', facts['comparison'])
        self.assertNotIn('debug', json.dumps(facts))

    def test_selected_field_echoing_token_cannot_be_published(self):
        self.backend.responses[preflight.STATUS_READS[0]].update(
            total_count=1, statuses=[{'context': TOKEN, 'state': 'pending'}])
        result = self.run_preflight()
        self.assertFalse(result['endpoint_access_checks_passed'])
        self.assertFalse((self.out / 'readiness-endpoint-facts.json').exists())

    def test_transport_rejects_nonfixed_operations_and_never_retries_redirect_or_http_failure(self):
        for method, url, body in (
                ('POST', preflight.API + '/graphql', {'query': 'mutation{updateRefs{clientMutationId}}'}),
                ('GET', preflight.API + PREFIX + '/pulls/5', None)):
            with self.subTest(method=method), patch.object(preflight.urllib.request, 'build_opener') as build:
                with self.assertRaises(preflight.Stopped):
                    preflight.transport(method, url, {}, body, 10, query=NativeGitHubBoundary.UNSTABLE_QUERY)
                build.assert_not_called()
        for status in (302, 403):
            with self.subTest(status=status), patch.object(preflight.urllib.request, 'build_opener') as build:
                build.return_value.open.side_effect = preflight.urllib.error.HTTPError(
                    preflight.API, status, TOKEN, {}, io.BytesIO(TOKEN.encode()))
                with self.assertRaises(preflight.Stopped) as stopped:
                    preflight.transport('GET', preflight.API + preflight.READS[0], {}, None, 10,
                                        query=NativeGitHubBoundary.UNSTABLE_QUERY)
                self.assertNotIn(TOKEN, str(stopped.exception))
                self.assertIsInstance(build.call_args.args[0], preflight.NoRedirect)
                build.return_value.open.assert_called_once()

    def test_command_success_requires_both_candidate_and_endpoint_checks(self):
        for candidate, endpoint, expected in ((True, True, 0), (True, False, 1), (False, True, 1), (False, False, 1)):
            with self.subTest(candidate=candidate, endpoint=endpoint), \
                 patch.object(sys, 'argv', ['preflight', '--core-source', '/fixed/source', '--out', '/fixed/out']), \
                 patch.object(preflight, 'run_preflight', return_value={
                     'credential_and_protection_candidate_checks_passed': candidate,
                     'endpoint_access_checks_passed': endpoint}), redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main(), expected)

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
        reader = preflight.FixedReads(TOKEN, candidate, self.native, NativeGitHubBoundary.UNSTABLE_QUERY,
                                      sender=self.backend.sender, clock=lambda: NOW)
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
