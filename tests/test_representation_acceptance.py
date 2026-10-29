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
        key = next(key for key, spec in p.auth.contract.PROFILES.items() if spec[0] == self.context['profile'])
        accepted = self.store/('acceptance-'+key+'-'+value['context_sha256']+'-'+value['readiness_sha256']+'.json')
        accepted.write_bytes(p.auth.canonical(value)); accepted.chmod(0o400)
        return path

    def test_current_bound_receipt_and_evidence_are_required(self):
        with self.boundary():
            self.assertFalse(p.accepted('python', self.context))
            current = self.receipt(); self.assertTrue(p.accepted('python', self.context))
            self.assertEqual(p.accepted('python', self.context, readiness=True), current.read_bytes())
            (self.matrix/'acceptance.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'owned_representation_acceptance_files'): p.accepted('python', self.context)

    def test_revoked_or_expired_receipt_does_not_authorize_cached_acceptance(self):
        with self.boundary():
            self.receipt(expired=True); self.assertFalse(p.accepted('python', self.context))
            current = self.receipt(); self.assertTrue(p.accepted('python', self.context))
            current.unlink(); self.assertFalse(p.accepted('python', self.context))

    def javascript_proof(self, ready):
        entry = p.javascript_fixture('b'*16); job = 'c'*32; ready_sha = p.auth.digest(ready.read_bytes())
        proof = {'schema': 'paw-s14-owned-javascript-handoff-v1', 'result': 'PASS', 'job': job,
            'profile': p.adapter.HTML, 'context': self.context, 'nonce': 'b'*16, 'readiness_sha256': ready_sha,
            'source_bytes': len(entry['original']), 'source_sha256': p.auth.digest(entry['original']),
            'browser_bytes': len(entry['selected']), 'browser_sha256': p.auth.digest(entry['selected']),
            'smokes': [{'mode': mode, 'original_unchanged': True, 'replay_refused': True} for mode in ['source', 'installed']],
            'real_source_grants_issued': 0}
        matrix = self.control/('representation-js-owned-'+job); matrix.mkdir(mode=0o700)
        path = matrix/'acceptance.json'; path.write_bytes(p.auth.canonical(proof)); path.chmod(0o400)
        context_sha = p.auth.digest(p.auth.canonical(self.context))
        pointer = self.store/('javascript-acceptance-'+context_sha+'-'+ready_sha+'.json')
        value = {'schema': 'paw-s14-owned-javascript-pointer-v1', 'result': 'PASS', 'job': job,
            'context_sha256': context_sha, 'readiness_sha256': ready_sha, 'acceptance_sha256': p.auth.digest(path.read_bytes())}
        pointer.write_bytes(p.auth.canonical(value)); pointer.chmod(0o400)
        return path, pointer

    def test_javascript_cache_requires_current_html_readiness_and_two_bound_smokes(self):
        self.context['profile'] = p.adapter.HTML
        with self.boundary():
            self.assertFalse(p.javascript_accepted(self.context))
            ready = self.receipt(); self.assertFalse(p.javascript_accepted(self.context))
            proof, pointer = self.javascript_proof(ready); current_path = ready; current_raw = ready.read_bytes()
            self.assertTrue(p.javascript_accepted(self.context))
            ready.unlink(); self.assertFalse(p.javascript_accepted(self.context))
            ready = self.receipt(expired=True); self.assertFalse(p.javascript_accepted(self.context))
            ready.unlink(); current_path.write_bytes(current_raw); current_path.chmod(0o400)
            self.assertTrue(p.javascript_accepted(self.context))
            proof.chmod(0o600); proof.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'owned_javascript_acceptance_digest'): p.javascript_accepted(self.context)

    def test_javascript_cache_rejects_false_handoff_even_with_matching_protected_digest(self):
        self.context['profile'] = p.adapter.HTML
        with self.boundary():
            ready = self.receipt(); proof_path, pointer_path = self.javascript_proof(ready)
            original = p.auth.decode(proof_path.read_bytes()); pointer = p.auth.decode(pointer_path.read_bytes())
            for field, changed in [('source_sha256', '0'*64), ('browser_bytes', 1), ('profile', p.adapter.PYTHON),
                    ('smokes', [original['smokes'][0]]), ('readiness_sha256', '0'*64), ('real_source_grants_issued', 1)]:
                proof = dict(original, **{field: changed}); raw = p.auth.canonical(proof)
                proof_path.chmod(0o600); proof_path.write_bytes(raw); proof_path.chmod(0o400)
                pointer['acceptance_sha256'] = p.auth.digest(raw)
                pointer_path.chmod(0o600); pointer_path.write_bytes(p.auth.canonical(pointer)); pointer_path.chmod(0o400)
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'owned_javascript_acceptance_proof'):
                    p.javascript_accepted(self.context)

    def test_owned_fixture_error_status_is_not_a_successful_smoke(self):
        good = {'result': 'PASS', 'runs': [{'outcome': {'status': 'completed', 'returncode': 0,
            'records': [{'bytes_hex': b'OWNED-REPRESENTATION-0000000000000000\n'.hex()}]}}]}
        p.owned_success(good, 'python', '0'*16)
        for status, code in [('failed', 7), ('timeout', -9), ('completed', True)]:
            good['runs'][0]['outcome'].update(status=status, returncode=code)
            with self.subTest(status=status, code=code), self.assertRaises(ValueError): p.owned_success(good, 'python', '0'*16)

    def test_promoted_proof_retains_its_authenticated_previous_active_anchor(self):
        state = self.root/'state'; state.mkdir(mode=0o700); releases = self.root/'releases'; releases.mkdir(mode=0o700)
        policy, proof = release_fixture(); now = int(time.time()); policy.update(created_at=now-10, expires_at=now+3600)
        # The installed policy keeps its original native enrollment anchor.
        # The fixed promoter authenticates against the previous active release,
        # then binds that complete proof to the new protected manifest/state.
        original_anchor = policy['anchor_sha']; proof['anchor_sha'] = '4'*40
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
            self.assertEqual(policy['anchor_sha'], original_anchor)
            proof['anchor_is_ancestor'] = False
            with self.assertRaises(ValueError): p.new_readiness(self.context, self.validation)
            proof['anchor_is_ancestor'] = True; proof['review']['actor_id'] += 1
            with self.assertRaises(ValueError): p.new_readiness(self.context, self.validation)
            proof['review']['actor_id'] -= 1
            # Rebinding the promoted proof cannot hide a malformed original
            # enrollment policy, even though its anchor is historical now.
            policy['anchor_sha'] = 'invalid'
            target = state/'policy.json'; target.chmod(0o600)
            target.write_bytes(p.auth.canonical(policy)); target.chmod(0o400)
            with self.assertRaisesRegex(ValueError, 'operator_policy_identity'):
                p.new_readiness(self.context, self.validation)

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
