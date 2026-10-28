"""Unprivileged authority tests; no real Root/image/VM/I08 authority."""
import copy
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14'), str(REPO/'tests')]
import native_runtime as auth
from test_representation_bridge import forensic_case
from linux_profile_fixtures import executable

CAPTURE = auth.capture
OWNED = b'printf owned\n\n\n'


class NativeAuthority(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        case, graph = forensic_case(self.root, b'Content-Type: text/x-shellscript\r\nContent-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(OWNED)+b'Z')
        node = next(key for key, row in graph.nodes.items() if row['kind'] == 'partial_decoded_candidate')
        prepared = auth.contract.prepare(case, node, 'shell', self.root/'request')
        self.raw = Path(prepared['request']).read_bytes(); self.request = auth.contract.validate_request(self.raw)
        self.ctx = {'profile': auth.contract.PROFILES['shell'].engine, 'backend': {'inert': 1},
            'contract_sha256': auth.contract.contract_hash(), 'runtime_sources_sha256': '1'*64, 'maintenance_sha256': '2'*64, 'guest_controller_sha256': auth.guest_controller_hash()}
        self.store = self.root/'authority'; self.store.mkdir(mode=0o700)
        @contextmanager
        def store():
            fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        backend = SimpleNamespace(validate_context=lambda value: None)
        self.patches = [mock.patch.object(auth.python_backend, 'validate_context'),
            mock.patch.object(auth, 'capture', side_effect=lambda profile: copy.deepcopy(self.ctx)),
            mock.patch.object(auth, 'store', store), mock.patch.object(auth.fs, 'OWNER_UID', os.getuid()),
            mock.patch.object(auth.os, 'geteuid', return_value=0)]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.tmp.cleanup()

    def policy(self, raw=None):
        value = auth.make_policy(self.ctx, [raw or self.raw], owned_manifest_sha256='3'*64)
        auth.install_policy(value, self.ctx); return value

    def readiness(self):
        now = int(time.time())
        return auth.canonical({'schema': 'paw-s14-native-i08-v1', 'scope': auth.SCOPE,
            'decision': 'ready-for-explicit-single-native-no-nic', 'context_sha256': auth.digest(auth.canonical(self.ctx)),
            'matrix_sha256': '4'*64, 'reviewed_head': '5'*40,
            'review_url': 'https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/1#issuecomment-1',
            'ci_runs': [1, 2], 'ci_successful_jobs': 7, 'created_at': now, 'expires_at': now+3600})

    def test_inspection_binds_full_case_derivation_and_selected_bytes(self):
        value = auth.inspect(self.raw)
        self.assertEqual(value['request_sha256'], auth.digest(self.raw))
        self.assertEqual(value['selection_binding_sha256'], self.request['candidate']['selection_binding_sha256'])
        self.assertEqual(value['selected_node'], self.request['binding']['derivation']['selected'])
        self.assertEqual(value['source_sha256'], auth.digest(OWNED))
        self.assertNotEqual(value['source_sha256'], value['original_source_sha256'])

    def test_real_temporary_grant_consume_and_durable_replay_refusal(self):
        policy = self.policy(); grant = auth.issue(self.raw, policy, self.ctx)
        ledger, raw_grant, summary, request, source = auth.consume(self.raw, policy, self.ctx)
        self.assertEqual(raw_grant, auth.canonical(grant)); self.assertEqual(source, OWNED)
        self.assertEqual(request, self.request); auth.confirm_consumed(ledger)
        self.assertEqual((self.store/'consumed'/ (summary['request_id']+'.json')).stat().st_mode & 0o777, 0o400)
        with self.assertRaises(FileExistsError): auth.consume(self.raw, policy, self.ctx)

    def test_new_request_same_source_is_not_approved_by_source_hash_alone(self):
        policy = self.policy(); request = copy.deepcopy(self.request)
        request['candidate']['request_id'] = 'f'*32; raw = auth.canonical(request)
        self.assertEqual(auth.inspect(raw)['source_sha256'], auth.inspect(self.raw)['source_sha256'])
        with self.assertRaisesRegex(ValueError, 'not_explicitly_approved'): auth.issue(raw, policy, self.ctx)
        self.assertFalse((self.store/'grants'/'ffffffffffffffffffffffffffffffff.json').exists())

    def test_uninstalled_caller_json_cannot_issue(self):
        raw = auth.make_policy(self.ctx, [self.raw], owned_manifest_sha256='3'*64)
        with self.assertRaises(FileNotFoundError): auth.issue(self.raw, raw, self.ctx)

    def test_changed_actual_context_refuses_install_and_consumption(self):
        policy = self.policy(); auth.issue(self.raw, policy, self.ctx)
        changed = copy.deepcopy(self.ctx); changed['runtime_sources_sha256'] = '9'*64
        with mock.patch.object(auth, 'capture', return_value=changed), self.assertRaisesRegex(ValueError, 'actual_context_changed'):
            auth.consume(self.raw, policy, self.ctx)
        self.assertFalse((self.store/'consumed').exists())

    def test_policy_compares_canonical_types_including_nested_backend(self):
        raw = auth.make_policy(self.ctx, [self.raw], owned_manifest_sha256='3'*64)
        value = json.loads(raw); value['context']['backend']['inert'] = True
        self.assertEqual(value['context'], self.ctx)
        with self.assertRaisesRegex(ValueError, 'policy_context'): auth.validate_policy(auth.canonical(value), self.ctx)

    def test_every_grant_binding_field_is_checked(self):
        policy = self.policy(); grant = auth.issue(self.raw, policy, self.ctx)
        for key in auth.inspect(self.raw):
            value = copy.deepcopy(grant); value[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                auth.validate_binding(self.raw, value, policy, self.ctx)

    def test_old_scope_and_extended_or_boolean_lease_refuse(self):
        policy = self.policy(); grant = auth.issue(self.raw, policy, self.ctx)
        for key, changed in [('scope', 'hash-pinned-offline-html-browser-v1'), ('expires_at', True),
                              ('expires_at', grant['created_at']+901), ('created_at', 0)]:
            value = copy.deepcopy(grant); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): auth.validate_binding(self.raw, value, policy, self.ctx)

    def test_explicit_analysis_requires_installed_context_bound_readiness(self):
        with self.assertRaises(ValueError): auth.make_policy(self.ctx, [self.raw], mode='explicit-source-analysis')
        ready = self.readiness(); auth.install_readiness(ready, self.ctx)
        policy = auth.make_policy(self.ctx, [self.raw], mode='explicit-source-analysis', ready=ready)
        auth.install_policy(policy, self.ctx); auth.issue(self.raw, policy, self.ctx)
        ledger, *_ = auth.consume(self.raw, policy, self.ctx); auth.confirm_consumed(ledger)

    def test_stale_wrong_context_or_old_readiness_namespace_refuses(self):
        for key, changed in [('expires_at', 0), ('context_sha256', '0'*64),
                              ('schema', 'paw-s14-browser-i08-readiness-v1'), ('ci_successful_jobs', True)]:
            value = json.loads(self.readiness()); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): auth.validate_readiness(auth.canonical(value), self.ctx)

    def test_unprivileged_issuance_consumption_policy_and_readiness_refuse_before_storage(self):
        with mock.patch.object(auth.os, 'geteuid', return_value=1000):
            for call in [lambda: auth.initialize(), lambda: auth.install_policy(b'{}', self.ctx),
                         lambda: auth.install_readiness(b'{}', self.ctx),
                         lambda: auth.issue(self.raw, b'{}', self.ctx), lambda: auth.consume(self.raw, b'{}', self.ctx)]:
                with self.assertRaisesRegex(ValueError, 'root_native_authority_required'): call()

    def test_future_or_unknown_profiles_refuse_instead_of_falling_back(self):
        for profile in ['linux-shell-offline-v1', 'linux-elf-offline-v1', 'browser', None, []]:
            with self.subTest(profile=profile), self.assertRaises(ValueError): CAPTURE(profile)

    def test_policy_request_collection_is_bounded_before_inspection(self):
        for values in [[], [self.raw]*33, iter([self.raw]), self.raw]:
            with self.assertRaisesRegex(ValueError, 'request_list_budget'): auth.make_policy(self.ctx, values)

    def test_current_guest_controller_hash_and_profile_are_bound(self):
        for key, changed in [('guest_controller_sha256', '0'*64), ('profile', 'linux-python-offline-v1'),
                             ('contract_sha256', '0'*64)]:
            value = copy.deepcopy(self.ctx); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): auth.validate_context(value)

    def test_elf_uses_its_own_profile_and_one_use_native_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            case,graph=forensic_case(Path(directory),executable())
            info=auth.contract.prepare(case,graph.root,'elf',Path(directory)/'request')
            raw=Path(info['request']).read_bytes()
            with self.assertRaisesRegex(ValueError,'policy_profile'):
                auth.make_policy(self.ctx,[raw],owned_manifest_sha256='3'*64)
            self.ctx=dict(self.ctx,profile=auth.contract.PROFILES['elf'].engine)
            policy=auth.make_policy(self.ctx,[raw],owned_manifest_sha256='3'*64)
            auth.install_policy(policy,self.ctx);auth.issue(raw,policy,self.ctx)
            ledger,grant,summary,request,data=auth.consume(raw,policy,self.ctx)
            self.assertEqual(data,executable());self.assertEqual(summary['profile'],self.ctx['profile']);auth.confirm_consumed(ledger)
            with self.assertRaises(FileExistsError):auth.consume(raw,policy,self.ctx)

    def test_revoked_readiness_refuses_before_consumption_ledger(self):
        ready=self.readiness();auth.install_readiness(ready,self.ctx)
        policy=auth.make_policy(self.ctx,[self.raw],mode='explicit-source-analysis',ready=ready)
        auth.install_policy(policy,self.ctx);auth.issue(self.raw,policy,self.ctx)
        (self.store/('readiness-'+auth.digest(ready)+'.json')).unlink()
        with self.assertRaises(FileNotFoundError):auth.consume(self.raw,policy,self.ctx)
        self.assertFalse((self.store/'consumed').exists())

    def capture_fixture(self, mutation=None):
        # Every file is ordinary UID1000 test data. Only ownership/absolute Root
        # ancestors are substituted; manifest/source hashes and storage.verify
        # perform real immutable-file reads and exact-inventory validation.
        release, head = 'a'*40, 'b'*40
        area = self.root/'capture'; area.mkdir(mode=0o700)
        releases = area/'releases'; releases.mkdir(mode=0o700)
        tree = releases/release; tree.mkdir(mode=0o700); (tree/'paw').mkdir(mode=0o700)
        source = b'# owned snapshot fixture, never executed\n'
        proof = auth.storage.canonical({'repository': auth.storage.REPOSITORY, 'head_sha': head, 'merge_sha': release})
        files = {'paw/owned.py': {'bytes': len(source), 'sha256': auth.digest(source)}}
        manifest = auth.storage.canonical({'schema': 'paw-vm-root-snapshot-v1', 'repository': auth.storage.REPOSITORY,
            'release_sha': release, 'head_sha': head, 'proof_sha256': auth.digest(proof), 'files': files})
        for name, raw in [('paw/owned.py', source), ('release.json', manifest), ('proof.json', proof)]:
            (tree/name).write_bytes(raw); (tree/name).chmod(0o444)
        state = area/'state'; state.mkdir(mode=0o700)
        active = {'release_sha': release, 'manifest_sha256': auth.digest(manifest)}
        if mutation == 'active': active['release_sha'] = 'c'*40
        (state/'active.json').write_bytes(auth.canonical(active)); (state/'active.json').chmod(0o600)
        maintenance = area/'maintenance'; maintenance.mkdir(mode=0o700)
        raw_maintenance = auth.canonical({'fixture': 'owned protected maintenance stand-in'})
        if mutation != 'missing-maintenance':
            name = 'maintenance-'+auth.digest(raw_maintenance)+'.json'
            (maintenance/name).write_bytes(b'changed' if mutation == 'maintenance-digest' else raw_maintenance)
            (maintenance/name).chmod(0o400)
        if mutation == 'source':
            (tree/'paw/owned.py').chmod(0o600); (tree/'paw/owned.py').write_bytes(b'changed'); (tree/'paw/owned.py').chmod(0o444)
        @contextmanager
        def directory(path):
            mapped = {Path('/var/lib/paw-vm'): state, Path('/opt/paw-vm/releases'): releases}[path]
            fd = os.open(mapped, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        @contextmanager
        def maintenance_store():
            fd = os.open(maintenance, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        def validate_maintenance(raw, context):
            if mutation == 'stale-maintenance': raise ValueError('owned stale maintenance stand-in')
            self.assertEqual(raw, raw_maintenance)
        profile = auth.contract.PROFILES['shell'].engine
        with mock.patch.object(auth, 'guest_controller_hash', return_value=self.ctx['guest_controller_sha256']), \
             mock.patch.object(auth.python_backend, 'capture', return_value={'owned': 'backend stand-in'}), \
             mock.patch.object(auth.python_backend, 'validate_context'), \
             mock.patch.object(auth.python_backend, 'validate_maintenance', side_effect=validate_maintenance), \
             mock.patch.object(auth.python_backend, 'store', maintenance_store), \
             mock.patch.object(auth.fs, 'root_directory', directory), \
             mock.patch.object(auth.storage, 'ROOT_UID', os.getuid()), \
             mock.patch.object(auth, 'HERE', Path('/opt/paw-vm/releases')/release/'lab/s14'):
            result = CAPTURE(profile)
        return result, files, auth.digest(raw_maintenance)

    def test_capture_reads_real_snapshot_inventory_and_protected_maintenance_digest(self):
        result, files, maintenance = self.capture_fixture()
        self.assertEqual(result['runtime_sources_sha256'], auth.digest(auth.storage.canonical(files)))
        self.assertEqual(result['maintenance_sha256'], maintenance)
        self.assertEqual(result['contract_sha256'], auth.contract.contract_hash())

    def test_capture_refuses_damaged_source_or_foreign_active_release(self):
        for mutation in ['source', 'active']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                old = self.root; self.root = Path(directory)
                try:
                    with self.assertRaises(ValueError): self.capture_fixture(mutation)
                finally: self.root = old

    def test_capture_requires_matching_current_maintenance_and_its_exact_digest(self):
        for mutation in ['missing-maintenance', 'maintenance-digest', 'stale-maintenance']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                old = self.root; self.root = Path(directory)
                try:
                    with self.assertRaises(ValueError): self.capture_fixture(mutation)
                finally: self.root = old


if __name__ == '__main__': unittest.main()
