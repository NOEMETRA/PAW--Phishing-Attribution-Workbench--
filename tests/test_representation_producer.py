"""Unprivileged producer custody checks; temporary authority, no Root or VM."""
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
import representation_producer as producer
import verify_representation as verifier
from test_representation_bridge import forensic_case, inventory
import test_representation_evidence as evidence


class Producer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.output = self.root/'audit'; self.output.mkdir(mode=0o700)

    def tearDown(self): self.tmp.cleanup()

    @contextmanager
    def boundary(self):
        @contextmanager
        def anchor(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        # All source/manifest hashing, exact inventory, readonly inode checks,
        # descriptor-relative copy, exclusive writes and atomic replacement are
        # real. Only absolute Root locations/ownership/ancestors are substituted.
        with mock.patch.object(producer.auth.fs, 'OWNER_UID', os.getuid()), \
             mock.patch.object(producer, 'READER_GID', os.getgid()), \
             mock.patch.object(producer.auth.storage, 'ROOT_UID', os.getuid()), \
             mock.patch.object(producer.auth.fs, 'root_directory', anchor): yield

    def release(self):
        releases = self.root/'releases'; releases.mkdir(mode=0o700)
        sha = 'a'*40; source = releases/sha; source.mkdir(mode=0o700)
        files = {}
        for name, raw in [('paw/owned.py', b'# owned snapshot data\n'), ('lab/s14/owned.py', b'# lab snapshot data\n')]:
            target = source/name; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw); target.chmod(0o444)
            files[name] = {'sha256': producer.auth.digest(raw), 'bytes': len(raw)}
        for directory in source.rglob('*'):
            if directory.is_dir(): directory.chmod(0o700)
        proof = producer.auth.storage.canonical({'repository': producer.auth.storage.REPOSITORY, 'head_sha': 'b'*40, 'merge_sha': sha})
        raw = producer.auth.storage.canonical({'schema': 'paw-vm-root-snapshot-v1', 'repository': producer.auth.storage.REPOSITORY,
            'head_sha': 'b'*40, 'release_sha': sha, 'proof_sha256': producer.auth.digest(proof), 'files': files})
        for name, data in [('release.json', raw), ('proof.json', proof)]:
            (source/name).write_bytes(data); (source/name).chmod(0o444)
        state = self.root/'state'; state.mkdir(mode=0o700)
        (state/'active.json').write_bytes(producer.auth.canonical({'release_sha': sha, 'manifest_sha256': producer.auth.digest(raw)}))
        (state/'active.json').chmod(0o400)
        return releases, source, state, {'runtime_sources_sha256': producer.auth.digest(producer.auth.storage.canonical(files))}

    def copy(self, value):
        releases, source, state, context = value
        with self.boundary(), mock.patch.object(producer, 'STATE', state), mock.patch.object(producer, 'RELEASES', releases), \
             mock.patch.object(producer.auth, 'HERE', source/'lab/s14'):
            producer.copy_runtime(self.output, context)
        return verifier.verify_snapshot(self.output, context)

    def test_actual_manifest_inventory_and_nested_source_copy_match(self):
        value = self.release(); result = self.copy(value)
        self.assertEqual(result, {'owned.py': producer.auth.digest(b'# lab snapshot data\n')})
        self.assertEqual((self.output/'runtime-snapshot/paw/owned.py').stat().st_mode & 0o777, 0o400)

    def test_changed_source_context_proof_or_inventory_refuses_before_copy(self):
        for fault in ['source', 'context', 'proof', 'inventory']:
            with self.subTest(fault=fault):
                # Isolate each mutation so no previous refusal determines it.
                self.tearDown(); self.setUp(); value = self.release(); _, source, _, context = value
                if fault == 'context': context['runtime_sources_sha256'] = '0'*64
                elif fault in {'source', 'proof'}:
                    target = source/('paw/owned.py' if fault == 'source' else 'proof.json')
                    target.chmod(0o600); target.write_bytes(b'changed'); target.chmod(0o444)
                else: (source/'unknown').mkdir(mode=0o700)
                with self.assertRaises(ValueError): self.copy(value)
                self.assertFalse((self.output/'runtime-snapshot').exists())

    def test_atomic_result_keeps_finite_vm_floats_and_readonly_permissions(self):
        with self.boundary():
            producer.save_results(self.output, {'result': 'PASS', 'stop_seconds': .25})
            producer.save_results(self.output, {'result': 'FAIL', 'stop_seconds': .25, 'verification_error': 'owned'})
        self.assertEqual(json.loads((self.output/'results.json').read_bytes())['result'], 'FAIL')
        self.assertEqual((self.output/'results.json').stat().st_mode & 0o777, 0o400)
        self.assertFalse((self.output/'results.pending').exists())

    def test_pending_symlink_or_oversize_report_cannot_replace_existing_evidence(self):
        original = self.root/'outside'; original.write_bytes(b'original')
        with self.boundary():
            (self.output/'results.pending').symlink_to(original)
            with self.assertRaises(FileExistsError): producer.save_results(self.output, {'result': 'PASS'})
            self.assertEqual(original.read_bytes(), b'original')
            (self.output/'results.pending').unlink()
            with self.assertRaises(ValueError): producer.save_results(self.output, {'oversize': 'x'*(2*1024**2)})
        self.assertFalse((self.output/'results.json').exists())

    def test_unprivileged_public_calls_refuse_before_authority_or_files(self):
        with mock.patch.object(producer.os, 'geteuid', return_value=1000), \
             mock.patch.object(producer.auth, 'capture') as capture, mock.patch.object(producer, 'audit_path') as path:
            for fn, args in [(producer.execute, (b'', b'')), (producer.publish, (b'',))]:
                with self.subTest(function=fn.__name__), self.assertRaises(ValueError): fn(*args)
            capture.assert_not_called(); path.assert_not_called()

    def execute_fixture(self, fault=None):
        case, graph = forensic_case(self.root)
        selected = next(v for v, row in graph.nodes.items() if row['kind'] == 'partial_decoded_candidate')
        info = producer.auth.contract.prepare(case, selected, 'python', self.root/'request')
        raw = Path(info['request']).read_bytes(); request = producer.auth.contract.validate_request(raw)
        summary = producer.auth.inspect(raw); output = self.root/('representation-job-'+summary['request_id'])
        maintenance = b'owned inert maintenance'; context = {'profile': producer.adapter.PYTHON,
            'maintenance_sha256': producer.auth.digest(maintenance), 'backend': {'owned': 'physical context substituted'}}
        store = self.root/'authority'; store.mkdir(mode=0o700)
        (store/('maintenance-'+context['maintenance_sha256']+'.json')).write_bytes(maintenance)
        (store/('maintenance-'+context['maintenance_sha256']+'.json')).chmod(0o400)
        gate = SimpleNamespace(active_vm=None, report={}, snapshot_host=mock.Mock(return_value={'owned': 'same host'}),
            connection=SimpleNamespace(listAllDomains=mock.Mock(return_value=[]), close=mock.Mock()))
        def make(args): args.output.mkdir(mode=0o700); return gate
        def execute(*args, **kwargs):
            if fault in {'protocol', 'unknown-stop'}:
                gate.active_vm = {'owned': 'inert VM'}; raise ValueError('owned_protocol_loss')
            return {'outcome': {'status': 'completed'}, 'stop_seconds': .25, 'writers_stopped': True}
        def stop(vm):
            if fault == 'unknown-stop': raise ValueError('owned_unknown_stop')
            gate.active_vm = None
        gate.stop = mock.Mock(side_effect=stop)
        @contextmanager
        def authority_store():
            fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        def verify(*args, **kwargs):
            if fault == 'verification': raise ValueError('owned_independent_verification_failure')
            return {'result': 'PASS', 'scope': 'inert hardware substitutions only'}
        with self.boundary(), mock.patch.object(producer, 'root_only'), mock.patch.object(producer, 'CONTROL', self.root), \
             mock.patch.object(producer.auth, 'capture', return_value=context), \
             mock.patch.object(producer.auth, 'load_bound', return_value=(b'owned grant', summary, request, b'owned')), \
             mock.patch.object(producer.auth, 'installed', return_value=({'mode': 'owned-validation'}, None)), \
             mock.patch.object(producer.auth.python_backend, 'store', authority_store), \
             mock.patch.object(producer.adapter, 'HashGate', side_effect=make), \
             mock.patch.object(producer.adapter, 'run_python', side_effect=execute), \
             mock.patch.object(producer, 'copy_runtime'), \
             mock.patch.object(producer, 'image_proof', return_value=('image-provenance.json', b'owned image proof')), \
             mock.patch.object(producer, 'digest', return_value=producer.auth.fs.IMAGE_SHA256), \
             mock.patch.object(producer, 'verify_single', side_effect=verify) as checked:
            report, audit = producer.execute(raw, b'owned policy')
        return report, audit, gate, checked.call_count

    def test_successful_flow_writes_only_verified_private_audit_no_external_export(self):
        report, audit, gate, checked = self.execute_fixture()
        self.assertEqual(report['result'], 'PASS'); self.assertEqual(checked, 1)
        self.assertTrue((audit/'independent-verification.json').is_file()); gate.connection.close.assert_called_once()
        self.assertTrue(report['writers_stopped']); self.assertEqual(report['real_connections'], 0)

    def test_independent_failure_atomically_replaces_initial_PASS(self):
        report, audit, gate, checked = self.execute_fixture('verification')
        self.assertEqual(report['result'], 'FAIL'); self.assertEqual(checked, 1)
        self.assertEqual(json.loads((audit/'results.json').read_bytes())['result'], 'FAIL')
        self.assertFalse((audit/'independent-verification.json').exists()); gate.connection.close.assert_called_once()

    def test_protocol_loss_known_stop_stays_failed_and_skips_success_verifier(self):
        report, audit, gate, checked = self.execute_fixture('protocol')
        self.assertEqual(report['result'], 'FAIL'); self.assertEqual(checked, 0)
        self.assertTrue(report['writers_stopped']); gate.stop.assert_called_once()
        self.assertFalse((audit/'independent-verification.json').exists()); gate.connection.close.assert_called_once()

    def test_unknown_external_stop_is_not_marked_restored_or_verified(self):
        report, audit, gate, checked = self.execute_fixture('unknown-stop')
        self.assertEqual(report['result'], 'FAIL'); self.assertEqual(checked, 0)
        self.assertIn('owned_unknown_stop', report['cleanup_error']); self.assertNotIn('writers_stopped', report)
        self.assertFalse((audit/'independent-verification.json').exists()); gate.connection.close.assert_called_once()

    def test_owned_or_missing_readiness_cannot_publish_even_if_offline_verifier_is_substituted(self):
        fixture = evidence.Evidence(); fixture.setUp()
        try:
            output, report, context = fixture.fixture()
            rid = report['runs'][0]['request_id']; raw = (output/'authority-copy'/rid/'request.json').read_bytes()
            for mode, ready in [('owned-validation', None), ('explicit-source-analysis', None)]:
                with self.subTest(mode=mode), mock.patch.object(producer, 'root_only'), \
                     mock.patch.object(producer, 'audit_path', return_value=output), \
                     mock.patch.object(producer, 'verify_single', return_value={'request_sha256': producer.auth.digest(raw)}), \
                     mock.patch.object(producer.auth, 'capture', return_value=context), \
                     mock.patch.object(producer.auth, 'installed', return_value=({'mode': mode}, ready)), \
                     mock.patch.object(producer.auth, 'load_bound') as load, \
                     mock.patch.object(producer, 'publish_reader_tree') as publish:
                    with self.assertRaisesRegex(ValueError, 'representation_publish_analysis_only'): producer.publish(raw)
                    load.assert_not_called(); publish.assert_not_called()
        finally: fixture.tearDown()

    def test_export_parent_is_created_once_and_pinned_without_changing_existing_results(self):
        exports = self.root/'exports'
        with self.boundary(), mock.patch.object(producer.auth.contract, 'EXPORT_ROOT', exports):
            with producer._export_parent() as fd:
                info = os.fstat(fd)
                self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (os.getuid(), os.getgid(), 0o750))
                child = exports/'already-published'; child.mkdir(mode=0o750)
                original = child/'receipt.json'; original.write_bytes(b'preserved'); original.chmod(0o440)
            before = (exports.stat(), original.stat())
            with producer._export_parent() as fd:
                self.assertEqual(os.fstat(fd).st_ino, before[0].st_ino)
            self.assertEqual((exports.stat(), original.stat()), before)
            self.assertEqual(original.read_bytes(), b'preserved')

    def test_export_parent_refuses_links_files_foreign_owner_and_unexpected_modes_without_repair(self):
        target = self.root/'outside'; target.mkdir(mode=0o700)
        (target/'canary').write_bytes(b'unchanged')
        for fault in ['symlink', 'file', 'foreign-owner', 'writable', 'private-existing']:
            with self.subTest(fault=fault):
                exports = self.root/('exports-'+fault)
                if fault == 'symlink': exports.symlink_to(target, target_is_directory=True)
                elif fault == 'file': exports.write_bytes(b'unchanged')
                else:
                    exports.mkdir(mode=0o750)
                    if fault == 'writable': exports.chmod(0o777)
                    if fault == 'private-existing': exports.chmod(0o700)
                before = exports.lstat(); target_before = inventory(target)
                with self.boundary(), mock.patch.object(producer.auth.contract, 'EXPORT_ROOT', exports), \
                     mock.patch.object(producer.auth.fs, 'OWNER_UID', os.getuid()+1 if fault == 'foreign-owner' else os.getuid()):
                    with self.assertRaises((ValueError, OSError)):
                        with producer._export_parent(): self.fail('untrusted export parent accepted')
                self.assertEqual(exports.lstat(), before)
                self.assertEqual(inventory(target), target_before)

    def test_real_authority_custody_receipt_and_sealed_client_round_trip_with_inert_hardware(self):
        fixture = evidence.Evidence(); fixture.setUp()
        try:
            output, report, context = fixture.fixture(producer.adapter.HTML)
            run = report['runs'][0]; rid = run['request_id']; copied = output/'authority-copy'/rid
            raw = (copied/'request.json').read_bytes(); proof = b'owned inert image proof'
            context['backend'].update(image_sha256='e'*64, image_certificate_sha256=producer.auth.digest(proof))
            (output/'browser-image-certificate.json').write_bytes(proof)
            store = self.root/'actual-temporary-authority'; store.mkdir(mode=0o700)
            # A first deployment has no export root. Publication must initialize
            # only that fixed leaf; precreating it hid the actual first-run bug.
            exports = self.root/'temporary-exports'
            now = int(time.time())
            ready = producer.auth.canonical({'schema': 'paw-s14-representation-i08-v1', 'scope': producer.auth.SCOPE,
                'decision': 'ready-for-explicit-single-representation-no-nic',
                'context_sha256': producer.auth.digest(producer.auth.canonical(context)), 'matrix_sha256': '1'*64,
                'reviewed_head': '2'*40, 'review_url': 'https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/119#issuecomment-6430657934',
                'ci_runs': [1, 2], 'ci_successful_jobs': 7, 'created_at': now, 'expires_at': now+3600})
            published = []
            def reader(destination):
                # Publication boundary is substituted; actual protected-reader
                # ownership/ancestor/inode behavior has its dedicated old suite.
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
                for p in destination.iterdir(): p.chmod(0o440)
                destination.chmod(0o750); published.append(destination)
            with self.boundary(), mock.patch.object(producer.auth.os, 'geteuid', return_value=0), \
                 mock.patch.object(producer, 'root_only'), mock.patch.object(producer.auth, 'ROOT', store), \
                 mock.patch.object(producer.auth, '_backend', return_value=SimpleNamespace(validate_context=lambda value: None)), \
                 mock.patch.object(producer.auth, 'capture', return_value=context), \
                 mock.patch.object(producer.auth.python_backend, 'validate_maintenance'), \
                 mock.patch.object(verifier, '_html_vm'), \
                 mock.patch.object(producer, 'audit_path', return_value=output), \
                 mock.patch.object(producer, 'image_proof', return_value=('browser-image-certificate.json', proof)), \
                 mock.patch.object(producer.auth.contract, 'EXPORT_ROOT', exports), \
                 mock.patch.object(producer, 'publish_reader_tree', side_effect=reader):
                # Real policy installation, issue, durable consume and later
                # Root-store revalidation; only location/ownership/physical
                # context are substituted. No real readiness is installed.
                producer.auth.install_readiness(ready, context)
                policy = producer.auth.make_policy(context, [raw], mode='explicit-source-analysis', ready=ready)
                producer.auth.install_policy(policy, context); grant = producer.auth.canonical(producer.auth.issue(raw, policy, context))
                ledger, checked, summary, _, _ = producer.auth.consume(raw, policy, context)
                self.assertEqual(grant, checked)
                run.update(consumption=ledger, admitted_at=int(time.time()), policy_sha256=producer.auth.digest(policy),
                    grant_sha256=producer.auth.digest(grant), context_sha256=producer.auth.digest(producer.auth.canonical(context)))
                for path, data in [(copied/'grant.json', grant), (copied/'consumed.json', producer.auth.canonical(ledger)),
                                   (output/'policy.json', policy), (output/'readiness.json', ready),
                                   (output/'results.json', producer.auth.canonical(report))]: path.write_bytes(data)
                result = producer.publish(raw)
                self.assertEqual(result['result'], 'PASS'); self.assertEqual(published, [exports/rid])
                receipt = producer.auth.contract.validate_receipt((exports/rid/'receipt.json').read_bytes(),
                    producer.auth.contract.validate_request(raw), producer.auth.digest(raw))
                self.assertEqual(receipt['runtime']['readiness_sha256'], producer.auth.digest(ready))
                self.assertEqual(receipt['runtime']['consumption_sha256'], producer.auth.digest(producer.auth.canonical(ledger)))
                with self.assertRaises(FileExistsError): producer.auth.consume(raw, policy, context)
                with self.assertRaises(FileExistsError): producer.publish(raw)
            case = next(fixture.root.glob('cases/case-forensic-*')); before = inventory(case)
            @contextmanager
            def trusted_export(identifier):
                self.assertEqual(identifier, rid)
                fd = os.open(exports/identifier, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: yield fd
                finally: os.close(fd)
            # Only Root reader UID checks are substituted for this ordinary UID
            # fixture; request matching, receipt/output reads and sealed sidecar
            # creation are real and the original case inventory must not change.
            bridge = producer.auth.contract
            with mock.patch.object(bridge, 'trusted_export', trusted_export):
                original = bridge.shared._read_regular
                def regular(*args, **kwargs):
                    kwargs.pop('root_owned', None); return original(*args, **kwargs)
                with mock.patch.object(bridge.shared, '_read_regular', side_effect=regular):
                    sidecar = bridge.import_result(case, copied/'request.json', self.root/'sealed-sidecar')
            self.assertEqual(sidecar['status'], 'collected'); self.assertTrue(sidecar['case_unchanged'])
            self.assertEqual(inventory(case), before)
        finally: fixture.tearDown()


if __name__ == '__main__': unittest.main()
