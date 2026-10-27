"""Finite command and proc identity checks; no systemd/Root/VM activation."""
import copy
from pathlib import Path
import subprocess
import unittest

import sys
REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/"lab/s14")]
import representation_producer as client

STATUS = 'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t\nNoNewPrivs:\t1\n'+''.join(
    key+':\t0000000000000000\n' for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'])


class Client(unittest.TestCase):
    def test_only_fixed_setpriv_can_precede_the_user_writable_interpreter(self):
        for mode in ['source', 'installed']:
            value = client.client_command('a'*32, 'b'*16, 'python', mode, 'prepare'); argv = value['argv']
            position = argv.index(str(client.CLIENT_PYTHON))
            self.assertEqual(argv[position-8:position], ['/usr/bin/setpriv', '--reuid=1000', '--regid=1000',
                '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all', '--no-new-privs'])
            self.assertIn('--property=IPAddressDeny=any', argv); self.assertIn('--property=Slice=machine-paws14.slice', argv)
            self.assertIn('--property=KillMode=control-group', argv); self.assertIn('--property=BindsTo='+value['parent_unit'], argv)
            self.assertIn('--property=PrivateNetwork=yes', argv); self.assertIn('--property=ProtectSystem=strict', argv)
            self.assertIn('--property=ReadWritePaths='+str(client.CLIENTS/('a'*32)), argv)
            self.assertEqual(argv[position+1:position+3], ['-I', '-B'])
            self.assertEqual('--source-tree' in argv, mode == 'source')
            self.assertNotIn('PYTHONPATH', value['environment']); self.assertNotIn('LD_PRELOAD', value['environment'])

    def test_unknown_profile_phase_mode_slot_and_shell_strings_refuse(self):
        for values in [('bad', 'b'*16, 'python', 'source', 'prepare'), ('a'*32, 'bad', 'python', 'source', 'prepare'),
                ('a'*32, 'b'*16, '/bin/sh', 'source', 'prepare'), ('a'*32, 'b'*16, 'python', 'source', 'shell'),
                ('a'*32, 'b'*16, 'python', 'caller-mode', 'prepare')]:
            with self.subTest(values=values), self.assertRaises(ValueError): client.client_command(*values)
        with self.assertRaises(ValueError): client.client_command('a'*32, 'b'*16, 'python', 'source', 'request', slot='../escape')
        with self.assertRaises(ValueError): client.client_command('a'*32, 'b'*16, 'python', 'source', 'prepare', slot='positive')

    def test_complete_kernel_identity_is_required_not_just_effective_uid(self):
        self.assertEqual(client.client_identity(STATUS)['uid'], 1000)
        for before, after in [('Uid:\t1000 1000 1000 1000', 'Uid:\t1000 1000 0 1000'), ('Groups:\t', 'Groups:\t107'),
                ('NoNewPrivs:\t1', 'NoNewPrivs:\t0'), ('CapBnd:\t0000000000000000', 'CapBnd:\t0000000000000001'),
                ('CapEff:\t0000000000000000', 'CapEff:\tINVALID')]:
            with self.subTest(before=before), self.assertRaises(ValueError): client.client_identity(STATUS.replace(before, after))
        with self.assertRaises(ValueError): client.client_identity(STATUS+'Uid:\t1000 1000 1000 1000\n')

    def test_real_local_nnp_child_does_not_substitute_for_full_privilege_drop(self):
        # This harmless ordinary-UID child proves the kernel NNP transition;
        # its unchanged groups/bounding caps must still fail the full guard.
        child = subprocess.run(['/usr/bin/setpriv', '--no-new-privs', '/usr/bin/python3', '-I', '-B', '-c',
            'from pathlib import Path;print(Path("/proc/self/status").read_text())'], capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr); self.assertIn('NoNewPrivs:\t1', child.stdout)
        with self.assertRaises(ValueError): client.client_identity(child.stdout)


if __name__ == '__main__': unittest.main()
