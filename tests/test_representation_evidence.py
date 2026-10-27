"""Real serialized custody/snapshot checks with explicit inert hardware evidence."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14')]
import representation_authorization as auth
import representation_adapter as adapter
import verify_representation as verify
from test_representation_bridge import forensic_case
from gw_quarantine import publish


class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        case, graph = forensic_case(self.root)
        node = next(key for key, row in graph.nodes.items() if row['kind'] == 'partial_decoded_candidate')
        info = auth.contract.prepare(case, node, 'html', self.root/'request')
        self.request = auth.contract.validate_request(Path(info['request']).read_bytes())

    def tearDown(self): self.tmp.cleanup()

    def fixture(self, profile=adapter.PYTHON):
        root = self.root/uuid.uuid4().hex; root.mkdir(mode=0o700)
        snapshot = root/'runtime-snapshot'; snapshot.mkdir(); (root/'sources').mkdir()
        files = {}; source_hashes = {}
        for source in (REPO/'lab/s14').iterdir():
            if source.suffix not in {'.py', '.nft', '.xml', '.service', '.conf', '.slice'}: continue
            name = 'lab/s14/'+source.name; target = snapshot/name; target.parent.mkdir(parents=True, exist_ok=True)
            raw = source.read_bytes(); target.write_bytes(raw); (root/'sources'/source.name).write_bytes(raw)
            files[name] = {'bytes': len(raw), 'sha256': auth.digest(raw)}; source_hashes[source.name] = auth.digest(raw)
        original_source = b'# owned snapshot fixture, not executed\n'; (snapshot/'paw').mkdir()
        (snapshot/'paw/owned.py').write_bytes(original_source)
        files['paw/owned.py'] = {'bytes': len(original_source), 'sha256': auth.digest(original_source)}
        proof = auth.storage.canonical({'repository': auth.storage.REPOSITORY, 'head_sha': '1'*40, 'merge_sha': '2'*40})
        header = auth.storage.canonical({'schema': 'paw-vm-root-snapshot-v1', 'repository': auth.storage.REPOSITORY,
            'release_sha': '2'*40, 'head_sha': '1'*40, 'proof_sha256': auth.digest(proof), 'files': files})
        (snapshot/'release.json').write_bytes(header); (snapshot/'proof.json').write_bytes(proof)
        maintenance = auth.canonical({'owned': 'inert maintenance stand-in'})
        (root/'maintenance.json').write_bytes(maintenance)
        backend = {'host': {'source_hashes': source_hashes, 'image_sha256': auth.fs.IMAGE_SHA256}}
        if profile == adapter.PYTHON:
            (root/'image-provenance.json').write_bytes(auth.canonical({'result': 'PASS', 'signed_manifest': True,
                'image': verify.BASE.name, 'sha256': auth.fs.IMAGE_SHA256, 'bytes': 259981312,
                'signature_status': '[GNUPG:] VALIDSIG '+verify.SIGNER+' owned inert metadata fixture'}))
        if profile == adapter.HTML:
            backend = {'platform': backend, 'chrome_version': 'Google Chrome inert', 'chrome_binary_sha256': 'a'*64}
        context = {'profile': profile, 'backend': backend, 'contract_sha256': auth.contract.contract_hash(),
            'runtime_sources_sha256': auth.digest(auth.storage.canonical(files)), 'maintenance_sha256': auth.digest(maintenance)}
        request = copy.deepcopy(self.request); request['candidate']['profile'] = profile
        if profile == adapter.PYTHON: request['candidate']['source']['media_type'] = 'text/x-python'
        raw = auth.canonical(request)
        now = int(time.time()); summary = auth.inspect(raw); rid = summary['request_id']
        # Authority shape/binding is real. No Root store, actual approval,
        # physical image/context, guest or I08 is claimed by this fixture.
        with mock.patch.object(auth, '_backend', return_value=SimpleNamespace(validate_context=lambda value: None)):
            policy = auth.make_policy(context, [raw], owned_manifest_sha256='3'*64)
        # Policy generation can cross a wall-clock second. Model grant/consume
        # after policy creation, as the real authority does.
        now = int(time.time())
        grant = {'schema': 'paw-s14-representation-grant-v1', 'scope': auth.SCOPE, **summary,
            'policy_sha256': auth.digest(policy), 'context_sha256': auth.digest(auth.canonical(context)),
            'execution_purpose': 'owned-validation', 'created_at': now, 'expires_at': min(now+900, request['candidate']['expires_at'])}
        grant_raw = auth.canonical(grant)
        ledger = {'schema': 'paw-s14-representation-consumed-v1', 'request_id': rid, 'request_sha256': auth.digest(raw),
            'grant_sha256': auth.digest(grant_raw), 'policy_sha256': auth.digest(policy),
            'context_sha256': auth.digest(auth.canonical(context)), 'consumed_at': now}
        copied = root/'authority-copy'/rid; copied.mkdir(parents=True)
        for name, data in [('request.json', raw), ('grant.json', grant_raw), ('consumed.json', auth.canonical(ledger))]:
            (copied/name).write_bytes(data)
        (root/'policy.json').write_bytes(policy); current = adapter.job(request); label = current['job_id']
        (root/'admissions').mkdir(); (root/'admissions'/(label+'.json')).write_bytes(auth.canonical(current))
        uid = str(uuid.uuid4()); actual = {'uuid': uid, 'pid': 12345, 'pid_identity': '123456'}
        vm = {'uuid': uid, 'label': label, 'stopped': True, 'stop_seconds': .05, 'actual': actual}
        owner = {'reason': 'requested_stop', 'connection_closed': True}
        if profile == adapter.HTML: owner['vm_uuid'] = uid
        (root/(label+'-owner-result.json')).write_text(json.dumps(owner))
        (root/(label+'-ready.json')).write_text(json.dumps(actual))
        data = b'OWNED OPAQUE DATA\n'; names = ['stdout.bin', 'stderr.bin'] if profile == adapter.PYTHON else ['observations.json']
        records = [{'name': name, 'bytes_hex': data.hex(), 'sha256': auth.digest(data),
                    'scope': 'opaque untrusted guest browser output' if profile == adapter.HTML else 'opaque untrusted job output'} for name in names]
        outcome = {'done': True, 'status': 'completed', 'returncode': 0, 'records': records, 'writers_stopped': True,
            'events': {'pids.current': '0', 'memory.events': '', 'pids.events': ''}, 'output_truncated': False}
        if profile == adapter.HTML:
            outcome['sandbox'] = {key: True for key in ['renderer_seen', 'renderer_nnp', 'renderer_seccomp', 'renderer_pid_namespace', 'all_uids_nonroot']}
        manifest = publish(root/(label+'-quarantine'), records, stopped=True)
        job_sha = auth.digest(auth.canonical(current))
        admission = {'source_sha256': summary['source_sha256'], 'job_sha256': job_sha, 'prior_marker_absent': True}
        run = {'request_id': rid, 'job': current, 'job_sha256': job_sha, 'vm_uuid': uid, 'owner_result': owner,
            'request_sha256': summary['request_sha256'], 'candidate_sha256': summary['candidate_sha256'],
            'selection_binding_sha256': summary['selection_binding_sha256'], 'grant_sha256': auth.digest(grant_raw),
            'policy_sha256': auth.digest(policy), 'context_sha256': auth.digest(auth.canonical(context)),
            'consumption': ledger, 'admitted_at': now, 'guest_admission': admission,
            'outcome': outcome, 'quarantine': manifest, 'writers_stopped': True, 'stop_seconds': .05}
        if profile == adapter.HTML:
            admission.update(started=True, job_limits={'memory.max': str(512*1024**2), 'memory.swap.max': '0', 'pids.max': '256'})
            run['guest_inspection'] = {'chrome_version': backend['chrome_version'], 'chrome_binary_sha256': backend['chrome_binary_sha256'],
                'kernel_release': '6.8.0-147-generic', 'network_interfaces': ['lo'], 'prior_marker_absent': True}
        report = {'result': 'PASS', 'host_restored': True, 'base_unchanged': True, 'host_canary_unchanged': True,
            'writers_stopped': True, 'source_freeze_unchanged': True, 'browser_image_unchanged': profile == adapter.HTML,
            'host_before': {'owned': 1}, 'host_after': {'owned': 1}, 'real_connections': 0,
            'source_hashes': source_hashes, 'runs': [run], 'vms': [vm]}
        (root/'results.json').write_text(json.dumps(report)); return root, report, context

    def verify(self, root):
        # Hardware/image validators are exercised by their existing dedicated
        # suites. Here every custody, full-snapshot, authority and byte check is
        # real, including reading serialized reports and quarantine files.
        with mock.patch.object(auth, '_backend', return_value=SimpleNamespace(validate_context=lambda value: None)), \
             mock.patch.object(auth.python_backend, 'validate_maintenance'), \
             mock.patch.object(verify, 'python_vm_evidence'), mock.patch.object(verify, '_html_vm'):
            return verify.verify_single(root)

    def rewrite(self, root, relative, mutate):
        p = root/relative; value = json.loads(p.read_bytes()); mutate(value)
        p.write_bytes(auth.canonical(value))

    def test_python_and_html_serialized_custody_and_snapshot_match_without_rendering(self):
        for profile in [adapter.PYTHON, adapter.HTML]:
            root, _, _ = self.fixture(profile)
            result = self.verify(root); self.assertEqual(result['result'], 'PASS'); self.assertEqual(result['profile'], profile)

    def test_wrong_parent_grant_digest_and_ledger_refuse(self):
        for mutation in ['parent', 'grant', 'ledger']:
            root, report, _ = self.fixture(); rid = report['runs'][0]['request_id']; copied = 'authority-copy/'+rid
            if mutation == 'parent': self.rewrite(root, 'results.json', lambda value: value['runs'][0]['job'].update(parent_sha256='0'*64))
            elif mutation == 'grant': self.rewrite(root, copied+'/grant.json', lambda value: value.update(policy_sha256='0'*64))
            else: self.rewrite(root, copied+'/consumed.json', lambda value: value.update(request_sha256='0'*64))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root)

    def test_unknown_stop_or_owner_loss_refuse(self):
        for mutation in ['stop', 'owner', 'ready']:
            root, report, _ = self.fixture(); label = report['runs'][0]['job']['job_id']
            if mutation == 'stop': self.rewrite(root, 'results.json', lambda value: value['vms'][0].update(stopped=None))
            elif mutation == 'owner': self.rewrite(root, label+'-owner-result.json', lambda value: value.update(connection_closed=False))
            else: self.rewrite(root, label+'-ready.json', lambda value: value.update(pid_identity='changed'))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root)

    def test_modified_runtime_source_or_added_empty_directory_refuse(self):
        for mutation in ['source', 'directory', 'proof']:
            root, _, _ = self.fixture()
            if mutation == 'source': (root/'runtime-snapshot/paw/owned.py').write_bytes(b'changed')
            elif mutation == 'directory': (root/'runtime-snapshot/unknown').mkdir()
            else: (root/'runtime-snapshot/proof.json').write_bytes(b'changed')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root)

    def test_quarantine_changed_extra_file_symlink_and_unknown_status_refuse(self):
        for mutation in ['changed', 'extra', 'symlink', 'status']:
            root, report, _ = self.fixture(); label = report['runs'][0]['job']['job_id']; folder = root/(label+'-quarantine')
            if mutation == 'changed': (folder/'artifact-00.bin').write_bytes(b'changed')
            elif mutation == 'extra': (folder/'extra.bin').write_bytes(b'extra')
            elif mutation == 'symlink': (folder/'artifact-00.bin').unlink(); (folder/'artifact-00.bin').symlink_to(root/'policy.json')
            else: self.rewrite(root, 'results.json', lambda value: value['runs'][0]['outcome'].update(status='safe'))
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, OSError)): self.verify(root)

    def test_directory_symlink_and_traversal_reads_refuse(self):
        root, _, _ = self.fixture(); (root/'link').symlink_to(root/'runtime-snapshot', target_is_directory=True)
        with self.assertRaises(OSError): verify.read(root, 'link/proof.json', 1024)
        for name in ['../policy.json', '/etc/passwd', 'a//b', './policy.json']:
            with self.subTest(name=name), self.assertRaises(ValueError): verify.read(root, name, 1024)

    def test_source_copies_are_bounded_regular_and_exact_inventory(self):
        for mutation in ['oversize', 'empty-directory', 'hardlink']:
            root, _, _ = self.fixture(); source = root/'sources/representation_adapter.py'
            if mutation == 'oversize': source.write_bytes(b'x'*(auth.storage.MAX_FILE+1))
            elif mutation == 'empty-directory': (root/'sources/unknown').mkdir()
            else:
                backup = root/'owned-copy'; source.rename(backup); os.link(backup, source)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root)

    def test_owned_validation_is_not_production_readiness(self):
        root, _, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, 'representation_analysis_readiness'):
            verify.verify_single(root, production=True)

    def test_unreported_admission_request_quarantine_or_job_files_refuse(self):
        for mutation in ['admission', 'request', 'quarantine', 'job-file', 'combined']:
            root, _, _ = self.fixture(); extra = 'rep-python-'+'f'*32
            if mutation in {'admission', 'combined'}:
                (root/'admissions'/(extra+'.json')).write_bytes(b'{}')
            if mutation in {'request', 'combined'}:
                folder = root/'authority-copy'/('f'*32); folder.mkdir()
                (folder/'request.json').write_bytes(b'{}')
            if mutation in {'quarantine', 'combined'}:
                folder = root/(extra+'-quarantine'); folder.mkdir()
                (folder/'artifact-00.bin').write_bytes(b'UNREPORTED OWNED OUTPUT')
            if mutation == 'job-file': (root/(extra+'-ready.json')).write_bytes(b'{}')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root)

    def test_real_descriptor_name_transformations_remain_in_the_single_job_inventory(self):
        import browser_vm
        import hash_offline_adapter
        import gw_validation
        for profile in [adapter.PYTHON, adapter.HTML]:
            root, report, _ = self.fixture(profile); label = report['vms'][0]['label']
            # Execute the real descriptor inheritance/name transformations;
            # substitute only physical VM/media commands and the base writer.
            def descriptor(gate, role, case, *args):
                xml = root/(case+'-'+role+'.xml')
                xml.write_bytes((REPO/'lab/s14/paused-probe.xml').read_bytes())
                return {'xml': xml, 'overlay': root/'owned-overlay-not-created'}
            cls = browser_vm.BrowserVM if profile == adapter.HTML else hash_offline_adapter.HashGate
            gate = object.__new__(cls); gate.phase = 'build'; gate.media = root/'owned-media-not-created'; gate.run = mock.Mock()
            with mock.patch.object(gw_validation.Matrix, 'descriptor', descriptor), \
                 mock.patch.object(hash_offline_adapter, 'protect_input_folder'), mock.patch.object(browser_vm, 'validate_xml'):
                node = gate.descriptor('extractor', label, 'owned', 'owned')
            with self.subTest(profile=profile):
                self.assertEqual(self.verify(root)['result'], 'PASS', node['xml'].name)

    def test_base_image_provenance_is_bound_and_not_a_boolean_or_unsigned_claim(self):
        for mutation in [{'sha256': '0'*64}, {'signed_manifest': False}, {'bytes': True}, {'signature_status': 'unsigned'}]:
            root, _, _ = self.fixture()
            self.rewrite(root, 'image-provenance.json', lambda value: value.update(mutation))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root)


if __name__ == '__main__': unittest.main()
