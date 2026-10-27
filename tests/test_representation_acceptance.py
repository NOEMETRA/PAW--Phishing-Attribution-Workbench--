"""Temporary protected acceptance/readiness binding; no Root, service or VM."""
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14')]
import representation_producer as p
from test_vm_release_contract import fixture as release_fixture


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.store = self.root/'store'; self.store.mkdir(mode=0o700); self.control = self.root/'control'; self.control.mkdir(mode=0o700)
        self.context = {'profile': p.adapter.PYTHON, 'backend': {'owned': 'hardware substituted'},
            'contract_sha256': p.auth.contract.contract_hash(), 'runtime_sources_sha256': '1'*64, 'maintenance_sha256': '2'*64}
        self.job = 'a'*32; self.matrix = self.control/('representation-owned-'+self.job); self.matrix.mkdir(mode=0o700)
        self.validation = b'{"owned":"completed validation fixture"}\n'; self.acceptance = b'{"owned":"completed two smokes fixture"}\n'
        (self.matrix/'validation.json').write_bytes(self.validation); (self.matrix/'acceptance.json').write_bytes(self.acceptance)

    def tearDown(self): self.tmp.cleanup()

    @contextmanager
    def boundary(self):
        @contextmanager
        def store():
            fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        with mock.patch.object(p.auth, 'store', store), mock.patch.object(p.auth.fs, 'OWNER_UID', os.getuid()), \
             mock.patch.object(p, 'CONTROL', self.control), \
             mock.patch.object(p.auth, '_backend', return_value=SimpleNamespace(validate_context=lambda value: None)):
            yield

    def receipt(self, expired=False):
        now = int(time.time()); created = now-7200 if expired else now
        ready = p.auth.canonical({'schema': 'paw-s14-representation-i08-v1', 'scope': p.auth.SCOPE,
            'decision': 'ready-for-explicit-single-representation-no-nic',
            'context_sha256': p.auth.digest(p.auth.canonical(self.context)), 'matrix_sha256': p.auth.digest(self.validation),
            'reviewed_head': '3'*40, 'review_url': 'https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/120#issuecomment-6431132705',
            'ci_runs': [1, 2], 'ci_successful_jobs': 7, 'created_at': created, 'expires_at': created+3600})
        path = self.store/('readiness-'+p.auth.digest(ready)+'.json'); path.write_bytes(ready); path.chmod(0o400)
        value = {'schema': 'paw-s14-representation-owned-acceptance-v1', 'result': 'PASS', 'job': self.job,
            'profile': self.context['profile'], 'context_sha256': p.auth.digest(p.auth.canonical(self.context)),
            'readiness_sha256': p.auth.digest(ready), 'matrix_sha256': p.auth.digest(self.validation),
            'acceptance_sha256': p.auth.digest(self.acceptance)}
        accepted = self.store/('acceptance-python-'+value['context_sha256']+'-'+value['readiness_sha256']+'.json')
        accepted.write_bytes(p.auth.canonical(value)); accepted.chmod(0o400)
        return path

    def test_current_bound_receipt_and_evidence_are_required(self):
        with self.boundary():
            self.assertFalse(p.accepted('python', self.context))
            self.receipt(); self.assertTrue(p.accepted('python', self.context))
            (self.matrix/'acceptance.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'owned_representation_acceptance_files'): p.accepted('python', self.context)

    def test_revoked_or_expired_receipt_does_not_authorize_cached_acceptance(self):
        with self.boundary():
            self.receipt(expired=True); self.assertFalse(p.accepted('python', self.context))
            current = self.receipt(); self.assertTrue(p.accepted('python', self.context))
            current.unlink(); self.assertFalse(p.accepted('python', self.context))

    def test_owned_fixture_error_status_is_not_a_successful_smoke(self):
        good = {'result': 'PASS', 'runs': [{'outcome': {'status': 'completed', 'returncode': 0,
            'records': [{'bytes_hex': b'OWNED-REPRESENTATION-0000000000000000\n'.hex()}]}}]}
        p.owned_success(good, 'python', '0'*16)
        for status, code in [('failed', 7), ('timeout', -9), ('completed', True)]:
            good['runs'][0]['outcome'].update(status=status, returncode=code)
            with self.subTest(status=status, code=code), self.assertRaises(ValueError): p.owned_success(good, 'python', '0'*16)

    def test_full_merged_review_head_and_main_proof_required_for_readiness(self):
        state = self.root/'state'; state.mkdir(mode=0o700); releases = self.root/'releases'; releases.mkdir(mode=0o700)
        policy, proof = release_fixture(); now = int(time.time()); policy.update(created_at=now-10, expires_at=now+3600)
        for name, value in [('policy.json', policy), ('active.json', {'release_sha': proof['merge_sha'], 'manifest_sha256': '1'*64})]:
            target = state/name; target.write_bytes(p.auth.canonical(value)); target.chmod(0o400)
        @contextmanager
        def anchor(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        with self.boundary(), mock.patch.object(p, 'STATE', state), mock.patch.object(p, 'RELEASES', releases), \
             mock.patch.object(p.auth, 'HERE', releases/proof['merge_sha']/'lab/s14'), \
             mock.patch.object(p.auth.fs, 'root_directory', anchor), \
             mock.patch.object(p.auth.storage, 'verify', return_value=({'head_sha': proof['head_sha']}, proof)):
            raw = p.new_readiness(self.context, self.validation)
            self.assertEqual(p.auth.decode(raw)['reviewed_head'], proof['head_sha'])
            self.assertEqual(p.auth.decode(raw)['ci_runs'], [1, 2])
            proof['ci'][-1]['conclusion'] = 'failure'
            with self.assertRaises(ValueError): p.new_readiness(self.context, self.validation)
            proof['ci'][-1]['conclusion'] = 'success'; proof['schema'] = 'paw-vm-native-candidate-v1'
            with self.assertRaises(ValueError): p.new_readiness(self.context, self.validation)


if __name__ == '__main__': unittest.main()
