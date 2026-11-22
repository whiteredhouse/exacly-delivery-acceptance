"""Offline diagnostic tests using the unchanged pinned helper and real local Git."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('hosted_diagnostic', ROOT / 'tools/hosted_merger_diagnostic.py')
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)
SECRET = 'fixture-secret-must-not-appear'


class HostedDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hosted-diagnostic-tests-')
        cls.source = Path(cls.temporary.name) / 'source'
        env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', str(ROOT), str(cls.source)],
                       env=env, check=True, capture_output=True, timeout=5)
        subprocess.run(['git', '-C', str(cls.source), '-c', 'core.hooksPath=' + os.devnull,
                        'checkout', '--quiet', '--detach', diagnostic.SOURCE],
                       env=env, check=True, capture_output=True, timeout=5)
        spec = importlib.util.spec_from_file_location('pinned_backend_fixtures', cls.source / 'tests/test_app_bootstrap.py')
        cls.fixtures = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixtures)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def backend(self):
        return self.fixtures.Backend(SimpleNamespace(base=diagnostic.SOURCE, merge='f' * 40))

    def run_diagnostic(self, backend, *, installation='177653055', source=None):
        real_run_path = runpy.run_path
        def load(path, **kwargs):
            namespace = real_run_path(path, **kwargs)
            if Path(path).name == 'app_bootstrap.py':
                namespace['transport'] = backend.sender
            return namespace
        with tempfile.TemporaryDirectory() as output, \
             patch.dict(os.environ, {'CANARY_APP_TOKEN': self.fixtures.ROLE_TOKEN, 'CANARY_INSTALLATION_ID': installation}), \
             patch.object(diagnostic.runpy, 'run_path', side_effect=load):
            result = diagnostic.diagnose(source or self.source, Path(output) / 'evidence')
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertLess(len(json.dumps(result)), 4096)
        return result

    def test_full_original_preflight_runs_without_writes_or_policy_replacement(self):
        backend = self.backend()
        result = self.run_diagnostic(backend)
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['provider_check_posts'], 0)
        self.assertEqual(result['reads_attempted'], 6)
        self.assertEqual([x[0] for x in backend.calls], ['GET'] * 6)
        self.assertEqual(result['observations']['scope_total_count'], 1)
        self.assertTrue(result['observations']['current_main_matches_source'])
        self.assertEqual(result['observations']['actor_permissions'], {'admin': False, 'maintain': False, 'push': True})
        self.assertTrue(result['observations']['protection']['checks_expected_match'])
        self.assertFalse(result['observations']['required_signatures_enabled'])
        self.assertEqual(result['observations']['effective_rules_count'], 0)

    def test_actual_original_actor_failure_is_exposed_and_missing_flags_stay_unknown(self):
        for permissions in ({'admin': True, 'maintain': False, 'push': True}, {}):
            with self.subTest(permissions=permissions):
                backend = self.backend()
                backend.repository['permissions'] = permissions
                result = self.run_diagnostic(backend)
                self.assertEqual(result['status'], 'rejected')
                self.assertEqual(result['stage'], 'actor_permissions')
                self.assertEqual(result['reason'], 'merge actor is not a non-admin/non-maintainer push actor')
                self.assertEqual(len(backend.calls), 3)
                expected = {key: permissions.get(key) for key in ('admin', 'maintain', 'push')}
                self.assertEqual(result['observations']['actor_permissions'], expected)

    def test_actual_original_capability_and_signature_failures_remain_rejected(self):
        backend = self.backend()
        backend.protection['enforce_admins']['enabled'] = False
        result = self.run_diagnostic(backend)
        self.assertEqual(result['status'], 'rejected')
        self.assertEqual(result['reason'], 'classic protection capability changed')
        self.assertFalse(result['observations']['protection']['capabilities']['enforce_admins'])
        backend = self.backend()
        backend.signatures = {'enabled': True}
        result = self.run_diagnostic(backend)
        self.assertEqual(result['status'], 'rejected')
        self.assertTrue(result['observations']['required_signatures_enabled'])

    def test_unknown_transport_exception_is_redacted_without_retry(self):
        backend = self.backend()
        original = backend.sender
        def fail(method, url, headers, payload, timeout):
            if url.endswith('/branches/main/protection'):
                backend.calls.append((method, url, payload))
                raise RuntimeError(SECRET)
            return original(method, url, headers, payload, timeout)
        backend.sender = fail
        result = self.run_diagnostic(backend)
        self.assertEqual(result['status'], 'rejected')
        self.assertEqual(result['reason'], 'bounded bootstrap could not complete')
        self.assertEqual(result['stage'], 'classic_protection_read')
        self.assertEqual(len(backend.calls), 4)

    def test_unapproved_write_and_duplicate_read_are_refused_before_transport(self):
        calls = []
        def transport(*args):
            calls.append(args)
            return 200, b'{}'
        sender = diagnostic.ReadOnlySender(transport, json.loads)
        with self.assertRaises(diagnostic.Stopped):
            sender('POST', diagnostic.API + diagnostic.PREFIX + '/check-runs', {}, {}, 1)
        with self.assertRaises(diagnostic.Stopped):
            sender('GET', diagnostic.API + '.evil.invalid' + diagnostic.PREFIX, {}, None, 1)
        sender('GET', diagnostic.API + diagnostic.PREFIX, {}, None, 1)
        with self.assertRaises(diagnostic.Stopped):
            sender('GET', diagnostic.API + diagnostic.PREFIX, {}, None, 1)
        self.assertEqual(len(calls), 1)

    def test_wrong_source_and_wrong_installation_stop_before_helper_reads(self):
        backend = self.backend()
        result = self.run_diagnostic(backend, installation='177653019')
        self.assertEqual(result['status'], 'rejected')
        self.assertEqual(result['stage'], 'installation_identity')
        self.assertFalse(backend.calls)
        with tempfile.TemporaryDirectory() as empty:
            result = self.run_diagnostic(backend, source=Path(empty))
        self.assertEqual(result['stage'], 'trusted_source')
        self.assertFalse(backend.calls)

    def test_modified_helper_hash_stops_before_loading_or_transport(self):
        helper = self.source / 'tools/app_bootstrap.py'
        original = helper.read_bytes()
        try:
            helper.write_bytes(original + b'\n# unexpected change\n')
            backend = self.backend()
            result = self.run_diagnostic(backend)
            self.assertEqual(result['status'], 'rejected')
            self.assertEqual(result['stage'], 'trusted_source')
            self.assertFalse(backend.calls)
        finally:
            helper.write_bytes(original)

    def test_server_strings_and_actor_names_never_enter_diagnostics(self):
        sender = diagnostic.ReadOnlySender(None, None)
        sender.record(diagnostic.PREFIX, {'permissions': {name: SECRET for name in ('admin', 'maintain', 'push')}})
        sender.record('/installation/repositories?per_page=100', {'total_count': SECRET})
        sender.record(diagnostic.PREFIX + '/branches/main/protection', {
            'required_status_checks': {'strict': SECRET, 'checks': [{'context': SECRET}]},
            'required_pull_request_reviews': {
                **{key: SECRET for key in ('require_last_push_approval', 'required_approving_review_count', 'dismiss_stale_reviews', 'require_code_owner_reviews')},
                'bypass_pull_request_allowances': {'users': [{'login': SECRET}], 'teams': SECRET, 'apps': []}},
            **{key: {'enabled': SECRET} for key in diagnostic.CAPABILITIES}})
        sender.record(diagnostic.PREFIX + '/branches/main/protection/required_signatures', {'enabled': SECRET})
        sender.record(diagnostic.PREFIX + '/rules/branches/main', [{'name': SECRET}])
        self.assertNotIn(SECRET, json.dumps(sender.observations))
        self.assertEqual(sender.observations['actor_permissions'], {'admin': None, 'maintain': None, 'push': None})
        policy = sender.observations['protection']
        self.assertIsNone(policy['strict'])
        self.assertIsNone(policy['review_count'])
        self.assertEqual(policy['bypass_counts'], {'users': 1, 'teams': None, 'apps': 0})
        self.assertTrue(all(value is None for value in policy['capabilities'].values()))
        self.assertIsNone(sender.observations['required_signatures_enabled'])


if __name__ == '__main__':
    unittest.main()
