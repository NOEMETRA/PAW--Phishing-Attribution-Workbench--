"""Real private client metadata/ack writes; Root/kernel/systemd substituted."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14')]
import representation_producer as p


class Runner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.state = self.root/'state'; self.state.mkdir(mode=0o700); (self.state/'jobs').mkdir(mode=0o700)
        self.job = 'a'*32; (self.state/'jobs'/self.job).mkdir(mode=0o700)
        self.readers = self.root/'readers'; self.readers.mkdir(mode=0o700)
        (self.readers/(self.job+'-client-source')).mkdir(mode=0o700)

    def tearDown(self): self.tmp.cleanup()

    @contextmanager
    def boundary(self):
        @contextmanager
        def anchor(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        with mock.patch.object(p, 'root_only'), mock.patch.object(p, 'STATE', self.state), \
             mock.patch.object(p, 'READERS', self.readers), mock.patch.object(p, 'CLIENTS', self.root/'clients'), \
             mock.patch.object(p.auth.fs, 'root_directory', anchor), mock.patch.object(p.os, 'fchown'):
            yield

    def execute(self, fault=None):
        context = {'profile': p.adapter.PYTHON}; frontend = mock.Mock()
        frontend.poll.side_effect = [None, 0] if fault == 'identity' else None
        frontend.poll.return_value = None; frontend.wait.return_value = 7 if fault == 'returncode' else 0
        process = {'pid': 123456, 'pid_identity': '123', 'uid': 1000, 'groups': [], 'no_new_privileges': True}
        with self.boundary(), mock.patch.object(p, 'verify_snapshot'), \
             mock.patch.object(p.auth, 'capture', return_value=context), \
             mock.patch.object(p.subprocess, 'Popen', return_value=frontend) as spawn, \
             mock.patch.object(p.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as stop, \
             mock.patch.object(p, 'client_properties', return_value={'MainPID': '123456'}), \
             mock.patch.object(p, 'client_process', side_effect=ValueError('owned invalid kernel identity') if fault == 'identity' else None,
                               return_value=process), mock.patch.object(p, 'client_limits', return_value={'owned': 'limits substituted'}), \
             mock.patch.object(p, 'client_terminal', side_effect=ValueError('owned live writer') if fault == 'terminal' else None,
                               return_value={'writers_stopped': True, 'main_pid': 0}) as terminal:
            try: value = p.run_client(self.job, 'b'*16, 'python', 'source', 'prepare', context)
            except Exception as error: value = error
        return value, spawn, stop, terminal

    def test_success_ack_is_bound_to_observed_pid_and_full_cgroup_stop(self):
        value, spawn, stop, terminal = self.execute()
        self.assertIsInstance(value, dict, repr(value)); self.assertEqual(value['result'], 'PASS')
        gate = self.readers/(self.job+'-client-source/go-python-source-prepare.json')
        self.assertEqual(json.loads(gate.read_bytes()), {'schema': 'paw-s14-owned-client-go-v1',
            'nonce': 'b'*16, 'tag': 'python-source-prepare', 'pid': 123456})
        self.assertEqual(gate.stat().st_mode & 0o777, 0o440)
        self.assertEqual(spawn.call_args.kwargs['stdin'], p.subprocess.DEVNULL)
        self.assertEqual(stop.call_args.args[0][:2], ['/usr/bin/systemctl', 'stop']); terminal.assert_called_once()

    def test_bad_identity_never_acknowledges_and_still_stops_unit(self):
        value, _, stop, terminal = self.execute('identity')
        self.assertIsInstance(value, ValueError)
        self.assertFalse((self.readers/(self.job+'-client-source/go-python-source-prepare.json')).exists())
        stop.assert_called_once(); terminal.assert_called_once()

    def test_failed_client_or_unconfirmed_stop_never_returns_PASS(self):
        for fault in ['returncode', 'terminal']:
            with self.subTest(fault=fault):
                value, _, stop, terminal = self.execute(fault)
                self.assertIsInstance(value, ValueError); stop.assert_called_once(); terminal.assert_called_once()
            # The next attempt uses its own fresh private log/gate, as a real
            # immutable job does. Never overwrite previous acceptance evidence.
            self.tearDown(); self.setUp()

    def test_unprivileged_runner_refuses_before_commands_or_snapshot_access(self):
        with mock.patch.object(p.os, 'geteuid', return_value=1000), \
             mock.patch.object(p, 'verify_snapshot') as snapshot, mock.patch.object(p.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError): p.run_client(self.job, 'b'*16, 'python', 'source', 'prepare', {})
            snapshot.assert_not_called(); spawn.assert_not_called()


if __name__ == '__main__': unittest.main()
