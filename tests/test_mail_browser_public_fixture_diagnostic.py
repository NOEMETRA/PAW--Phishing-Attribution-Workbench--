"""Inert exact preparation/error paths; no Root, sockets, VM or service calls."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace as NS
import sys
import unittest
from unittest.mock import Mock, patch

from paw.core import mail_browser_fixture_diagnostic as diagnostic

J, R = 'a' * 32, 'b' * 40


class FixtureDiagnostic(unittest.TestCase):
    def exercise(self, *, failed=False, cleanup_failed=False, changed=False,
                 oversized=False, exited=False):
        p = diagnostic.public
        raw = b'Traceback: synthetic fixture\nValueError: exact-owned-fixture-error\n'
        actor = NS(unit='fixed-owned-fixture', errors=bytearray(b'x' * 8193 if oversized else raw),
                   process=NS(poll=Mock(side_effect=[1 if exited else None, 1 if failed else -15])),
                   observation=None)
        if failed:
            actor.process.poll = Mock(return_value=1)
        prep = NS(fixture_configured=True, server_live=False, worker_live=False, ready=False,
                  poll=Mock(side_effect=ValueError('owned_kernel_role_protocol_lost') if failed else None,
                            return_value=True))
        def create(*args, **kwargs):
            args[4].append(actor)
            return prep
        properties = {'ActiveState': 'active', 'MainPID': str(os.getpid()),
                      'MemoryMax': str(192 * 1024**2), 'MemorySwapMax': '0',
                      'TasksMax': '24', 'CPUQuotaPerSecUSec': '350ms'}
        snapshot = Mock(side_effect=[{'same': True}, {'same': not changed}])
        modules = {'vm_runtime_revalidation': NS(snapshot=snapshot, network_state=lambda: {})}
        with patch.dict(sys.modules, modules), \
             patch.object(diagnostic, '__file__', '/opt/paw-vm/releases/' + R + '/paw/core/mail_browser_fixture_diagnostic.py'), \
             patch.object(diagnostic.os, 'geteuid', return_value=0), \
             patch.object(p.kernel, 'unit_properties', return_value=properties), \
             patch.object(p, 'require_idle'), patch.object(p, 'prepare_network') as prepare, \
             patch.object(p, 'NetworkPreparation', side_effect=create) as preparation, \
             patch.object(p.kernel, 'cleanup_actors', side_effect=ValueError('unknown stop') if cleanup_failed else None) as cleanup, \
             patch.object(p.kernel, 'vacant_ids'), patch.object(p.time, 'sleep'), \
             patch.object(p.socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(p.subprocess, 'Popen', side_effect=AssertionError('process launch forbidden')):
            result = diagnostic.run(J, R)
        prepare.assert_called_once()
        self.assertEqual(prepare.call_args.args[3:], ('owned-browser', {}))
        preparation.assert_called_once_with(J, prepare.call_args.args[1], R, 'owned-browser', [actor], protocol=True)
        cleanup.assert_called_once_with([actor])
        self.assertFalse(result['vm_started']); self.assertEqual(result['real_connections'], 0)
        self.assertFalse(result['native_authority_created'])
        self.assertTrue(result['writers_stopped']); self.assertTrue(result['host_restored'])
        self.assertEqual(result['roles'][0]['stderr'], raw.decode())
        self.assertEqual(result['roles'][0]['stderr_sha256'], hashlib.sha256(raw).hexdigest())
        return result

    def test_failed_fixture_keeps_exact_stopped_error_without_acceptance(self):
        r = self.exercise(failed=True)
        self.assertEqual(r['result'], 'FAIL')
        self.assertEqual(r['error'], 'ValueError:owned_kernel_role_protocol_lost')
        self.assertEqual(r['roles'][0]['launcher_returncode'], 1)
        self.assertIn('exact-owned-fixture-error', r['roles'][0]['stderr'])

    def test_readiness_only_success_is_not_browser_or_TLS_handshake_acceptance(self):
        self.assertEqual(self.exercise()['result'], 'PASS')

    def test_role_exiting_after_readiness_remains_a_failure(self):
        r = self.exercise(exited=True)
        self.assertEqual(r['result'], 'FAIL')
        self.assertIn('unexpected_exit', r['error'])

    def test_unknown_stop_cannot_return_diagnostic(self):
        with self.assertRaisesRegex(ValueError, 'unknown stop'):
            self.exercise(cleanup_failed=True)

    def test_changed_host_cannot_return_diagnostic(self):
        with self.assertRaisesRegex(ValueError, 'restore'):
            self.exercise(changed=True)

    def test_oversized_stderr_cannot_return_diagnostic(self):
        with self.assertRaisesRegex(ValueError, 'stderr_budget'):
            self.exercise(oversized=True)

    def test_ordinary_UID_refused_before_service_or_namespace(self):
        with patch.object(diagnostic.os, 'geteuid', return_value=1000), \
             patch.object(diagnostic.public, 'prepare_network') as prepare:
            with self.assertRaisesRegex(ValueError, 'snapshot'):
                diagnostic.run(J, R)
            prepare.assert_not_called()

    def test_wrong_parent_budget_refuses_before_preparation(self):
        with patch.object(diagnostic.os, 'geteuid', return_value=0), \
             patch.object(diagnostic, '__file__', '/opt/paw-vm/releases/' + R + '/paw/core/mail_browser_fixture_diagnostic.py'), \
             patch.object(diagnostic.public.kernel, 'unit_properties', return_value={}), \
             patch.object(diagnostic.public, 'prepare_network') as prepare:
            with self.assertRaisesRegex(ValueError, 'parent_budget'):
                diagnostic.run(J, R)
            prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
