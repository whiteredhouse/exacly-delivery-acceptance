"""Offline regression checks for the owner-local credential boundary."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('diagnose_merger', Path(__file__).resolve().parents[1] / 'tools' / 'diagnose_merger.py')
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
SECRET = 'secret-must-never-be-rendered'


class DiagnosticTests(unittest.TestCase):
    def run_diagnostic(self, *, status='ready', reason=None, thrown=None, invalid_install=False,
                       invalid_permissions=False, revoke_fail=False):
        calls = []
        helper_calls = []
        def request(api, method, path, credential, payload=None, **kwargs):
            calls.append((method, path, payload))
            if path.startswith('/app/installations/') and method == 'GET':
                return 200, json.dumps({'id': d.INSTALLATION_ID, 'app_id': 1 if invalid_install else d.APP_ID,
                                       'account': {'id': 99, 'login': 'whiteredhouse', 'type': 'Organization'}}).encode()
            if method == 'POST':
                return 201, json.dumps({'token': SECRET, 'permissions': {} if invalid_permissions else d.PERMISSIONS}).encode()
            if method == 'DELETE':
                if revoke_fail:
                    raise RuntimeError(SECRET)
                return 204, b''
            if path == d.PREFIX:
                return 200, json.dumps({'owner': {'id': 99}, 'permissions': {'admin': False, 'maintain': False, 'push': True}}).encode()
            raise AssertionError('unexpected test request')
        def execute(arguments, sender):
            helper_calls.append(arguments)
            self.assertEqual(os.environ['CANARY_APP_TOKEN'], SECRET)
            sender('GET', d.API + d.PREFIX, {'Authorization': 'Bearer ' + SECRET}, None, 10)
            if thrown:
                raise thrown
            return {'status': status, 'reason': reason, 'provider_check_posts': 0}
        with mock.patch.object(d, 'trusted_source', return_value=Path('/not-read')), \
             mock.patch.object(d.runpy, 'run_path', return_value={'execute': execute}), \
             mock.patch.object(d, 'app_jwt', return_value=SECRET), \
             mock.patch.object(d.Api, 'request', request):
            result = d.diagnose(Path('/not-read.pem'))
        self.assertNotIn(SECRET, json.dumps(result))
        return result, calls, helper_calls

    def test_success_uses_exact_existing_helper_mode_and_revokes(self):
        with mock.patch.dict(os.environ, {'CANARY_APP_TOKEN': 'prior-owner-value'}):
            result, calls, helpers = self.run_diagnostic()
            self.assertEqual(os.environ['CANARY_APP_TOKEN'], 'prior-owner-value')
        self.assertEqual(result['status'], 'ready')
        self.assertTrue(result['token_revoked'])
        self.assertEqual(result['actor_permissions'], {'admin': False, 'maintain': False, 'push': True})
        self.assertEqual(helpers[0].command, 'preflight')
        self.assertEqual(helpers[0].role, 'merger')
        self.assertEqual(helpers[0].installation_id, d.INSTALLATION_ID)
        self.assertEqual([x for x in calls if x[0] == 'POST'], [('POST', '/app/installations/177653055/access_tokens', {'repository_ids': [1442278205], 'permissions': d.PERMISSIONS})])
        self.assertEqual(calls[-1][0:2], ('DELETE', '/installation/token'))

    def test_fixed_actual_actor_rejection_exposed_and_revoked(self):
        reason = 'merge actor is not a non-admin/non-maintainer push actor'
        result, _, _ = self.run_diagnostic(status='rejected', reason=reason)
        self.assertEqual(result['reason'], reason)
        self.assertEqual(result['stage'], 'actor_permissions')
        self.assertTrue(result['token_revoked'])

    def test_arbitrary_helper_reason_and_exception_are_not_printed(self):
        for variant in ({'status': 'rejected', 'reason': SECRET}, {'thrown': RuntimeError(SECRET)}):
            with self.subTest(variant=tuple(variant)):
                result, _, _ = self.run_diagnostic(**variant)
                self.assertEqual(result['reason'], d.GENERIC)
                self.assertTrue(result['token_revoked'])

    def test_invalid_installation_never_mints_or_invokes_helper(self):
        result, calls, helpers = self.run_diagnostic(invalid_install=True)
        self.assertEqual(result['status'], 'rejected')
        self.assertFalse(any(x[0] == 'POST' for x in calls))
        self.assertFalse(helpers)
        self.assertIsNone(result['token_revoked'])

    def test_bad_minted_permissions_still_revoke_without_using_helper(self):
        result, calls, helpers = self.run_diagnostic(invalid_permissions=True)
        self.assertEqual(result['status'], 'rejected')
        self.assertTrue(result['token_revoked'])
        self.assertFalse(helpers)
        self.assertEqual(sum(x[0] == 'POST' for x in calls), 1)

    def test_revoke_failure_is_visible_and_not_retried(self):
        result, calls, _ = self.run_diagnostic(revoke_fail=True)
        self.assertEqual(result['status'], 'rejected')
        self.assertFalse(result['token_revoked'])
        self.assertEqual(sum(x[0] == 'DELETE' for x in calls), 1)

    def test_wrong_pinned_commit_stops_before_checkout(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return b'wrong-commit\n' if 'rev-parse' in args else b''
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(d, 'command', command):
            with self.assertRaises(d.Stopped):
                d.trusted_source(Path(temp))
        self.assertFalse(any('checkout' in x for x in calls))

    def test_transport_refuses_unapproved_provider_writes_before_network(self):
        api = d.Api()
        with mock.patch.object(d.urllib.request, 'build_opener') as opener:
            with self.assertRaises(d.Stopped):
                api.request('POST', d.PREFIX + '/check-runs', SECRET, {'name': 'fabricated'})
            with self.assertRaises(d.Stopped):
                api.sender('GET', 'https://api.github.com.evil.invalid' + d.PREFIX,
                           {'Authorization': 'Bearer ' + SECRET}, None, 10)
            opener.assert_not_called()

    def test_child_process_environment_excludes_credentials(self):
        with mock.patch.dict(os.environ, {'CANARY_APP_TOKEN': SECRET, 'GITHUB_TOKEN': SECRET, 'PRIVATE_KEY': SECRET}):
            env = d.clean_environment()
        self.assertNotIn(SECRET, json.dumps(env))
        self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')


if __name__ == '__main__':
    unittest.main()
