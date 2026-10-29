"""Real maximum-size PAW byte custody; Root transport substituted, no JS runs."""
from contextlib import contextmanager, redirect_stdout
import copy
import io
import json
import os
import selectors
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14'), str(REPO/'tests')]
import representation_owned_inputs as client
import representation_producer as producer
from paw.core import representation_bridge as bridge
from paw.core.javascript_representation_observer import browser_bytes
from paw.core.verify import verify_case
from test_representation_bridge import receipt_for
import browser_guest as guest
from paw.core.representation_graph import Graph
from paw.core.javascript_representation_observer import observe_javascript


class Javascript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.workspace = self.root/'client'
        self.nonce = '1122334455667788'; self.entry = client.javascript_fixture(self.nonce)
        self.prepared = client.prepare(self.workspace, self.nonce, REPO, 'javascript')
        client.next_request(self.workspace, self.nonce, 'javascript', 'smoke', REPO)
        self.raw = (self.workspace/'slots/smoke/request.json').read_bytes()

    def tearDown(self): self.tmp.cleanup()

    def test_full_size_owned_bytes_and_actual_parent_match_root_regeneration(self):
        self.assertEqual(len(self.entry['original']), 256*1024)
        self.assertEqual(len(self.entry['selected']), 349676)
        self.assertEqual(browser_bytes(self.entry['original']), self.entry['selected'])
        self.assertIn(b'document.currentScript.remove();', self.entry['original'])
        self.assertEqual(len(self.prepared['cases']), 1)
        request = client.validate_owned(self.raw, self.entry, bridge)
        self.assertEqual(request['candidate']['profile'], producer.adapter.HTML)
        with mock.patch.object(producer, 'client_command', return_value={'workspace': self.workspace}):
            raw, parent, before = producer.owned_request('a'*32, self.nonce, 'javascript', 'source', 'smoke')
            self.assertEqual(raw, self.raw); self.assertEqual(before, client.inventory(parent))
            self.assertEqual((parent/'source.bin').read_bytes(), self.entry['original'])
            with self.assertRaises(ValueError): producer.owned_request('a'*32, '0'*16, 'javascript', 'source', 'smoke')
        self.assertFalse(self.prepared['vm_started']); self.assertFalse(self.prepared['execution_authorized'])

    def test_other_slots_and_duplicate_requests_refuse(self):
        for slot in sorted(client.SLOTS):
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                client.next_request(self.workspace, self.nonce, 'javascript', slot, REPO)
        for nonce in ['x'*16, 'a'*15, 'b'*17, '../escape']:
            with self.subTest(nonce=nonce), self.assertRaises(ValueError): client.javascript_fixture(nonce)

    def test_maximum_request_uses_its_declared_budget_before_independent_verification(self):
        self.assertGreater(len(self.raw), 256*1024)
        with self.assertRaisesRegex(ValueError, 'synthetic_json_budget'): producer.auth.decode(self.raw)
        with mock.patch.object(producer, 'root_only'), mock.patch.object(producer, 'verify_single', side_effect=ValueError('independent verifier reached')):
            with self.assertRaisesRegex(ValueError, 'independent verifier reached'): producer.publish(self.raw)

    def test_large_invalid_request_refuses_before_independent_verification(self):
        value = json.loads(self.raw); value['candidate']['profile'] = 'not-an-execution-profile'
        with mock.patch.object(producer, 'root_only'), mock.patch.object(producer, 'verify_single') as verify:
            with self.assertRaises(ValueError): producer.publish(bridge.canonical(value))
        verify.assert_not_called()

    def test_self_consistent_but_different_transform_cannot_get_owned_authority(self):
        original = bridge.validate_request(self.raw)
        for field, changed in [('environment', 'nodejs'), ('errors', 'replace'), ('source_sha256', '0'*64)]:
            value = copy.deepcopy(original); selected = value['binding']['derivation']['nodes'][-1]
            selected['transform']['parameters'][field] = changed
            selected['id'] = bridge.digest(bridge.node_canonical({k: v for k, v in selected.items() if k not in {'id', 'blob_path'}}))
            value['binding']['derivation']['selected'] = selected['id']
            value['candidate']['selection_binding_sha256'] = bridge.digest(bridge.canonical(value['binding']))
            raw = bridge.canonical(value)
            bridge.validate_request(raw)  # Generic custody deliberately permits other explicit derivations.
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'owned_javascript_exact_derivation'):
                client.validate_owned(raw, self.entry, bridge)

    def test_actual_import_seals_sidecar_and_preserves_exact_original(self):
        request = bridge.validate_request(self.raw); export = self.root/'inert-export'; export.mkdir(mode=0o700)
        (export/'request.json').write_bytes(self.raw)
        (export/'receipt.json').write_bytes(bridge.canonical(receipt_for(request, self.raw)))
        (export/'artifact-00.bin').write_bytes(b'out')
        @contextmanager
        def trusted(identifier):
            self.assertEqual(identifier, request['candidate']['request_id'])
            fd = os.open(export, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        regular_read = bridge.shared._read_regular
        def regular(*args, **kwargs):
            kwargs.pop('root_owned', None); return regular_read(*args, **kwargs)
        # Root provenance only is substituted; actual request/receipt/bytes and
        # seal validators run. This is not VM or browser acceptance.
        with mock.patch.object(bridge, 'trusted_export', trusted), mock.patch.object(bridge.shared, '_read_regular', side_effect=regular):
            value = client.next_request(self.workspace, self.nonce, 'javascript', 'smoke', REPO, collect=True)
        self.assertTrue(value['original_case_unchanged'])
        with redirect_stdout(io.StringIO()): self.assertTrue(verify_case(self.workspace/'sidecar-smoke/result'))
        for row in self.prepared['cases']: self.assertEqual(client.inventory(Path(row['case'])), row['case_inventory'])


class OutputBudget(unittest.TestCase):
    def drain(self, payload):
        # Actual drain/poll/finish and ordinary pipe. Only privileged cgroup,
        # process and sandbox observations are inert; no Chrome or JS executes.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); group = root/'group'; group.mkdir()
            for name, raw in [('cgroup.kill',''), ('pids.current','0'), ('memory.events','oom 0\noom_kill 0\n'), ('pids.events','max 0\n')]:
                (group/name).write_text(raw)
            read_fd, write_fd = os.pipe(); stream = os.fdopen(read_fd, 'rb', buffering=0); os.set_blocking(read_fd, False)
            selector = selectors.DefaultSelector(); selector.register(stream, selectors.EVENT_READ, 'stdout')
            def writer():
                try:
                    view = memoryview(payload)
                    while view: view = view[os.write(write_fd, view):]
                finally: os.close(write_fd)
            thread = threading.Thread(target=writer)
            active = SimpleNamespace(returncode=0, poll=lambda: None if thread.is_alive() else 0, wait=lambda timeout: 0)
            try:
                with mock.patch.object(guest, 'GROUP', group), mock.patch.object(guest, 'WORK', root), \
                     mock.patch.object(guest, 'ACTIVE', active), mock.patch.object(guest, 'STARTED', time.monotonic()), \
                     mock.patch.object(guest, 'DONE', None), mock.patch.object(guest, 'OUTPUT', {'stdout': bytearray(), 'stderr': bytearray()}), \
                     mock.patch.object(guest, 'SELECTOR', selector), mock.patch.object(guest, 'SANDBOX', {k: True for k in guest.SANDBOX}), \
                     mock.patch.object(guest, 'observe_sandbox'):
                    thread.start(); deadline = time.monotonic()+5
                    while True:
                        value = guest.poll()
                        if value['done']: break
                        self.assertLess(time.monotonic(), deadline); time.sleep(.001)
                    thread.join(timeout=2); self.assertFalse(thread.is_alive())
                    return value
            finally: selector.close(); stream.close()

    def test_old_maximum_fixture_echo_exceeds_unchanged_dom_cap(self):
        prefix = b'document.title="OWNED-REPRESENTATION-1122334455667788";\n/*'
        original = prefix+b'x'*(256*1024-len(prefix)-3)+b'*/\n'
        value = self.drain(browser_bytes(original))
        self.assertEqual(value['status'], 'output_budget'); self.assertTrue(value['output_truncated'])
        self.assertEqual(guest.MAX_DOM, 256*1024)

    def test_bounded_post_removal_dom_fits_without_lowering_input_or_raising_output(self):
        entry = client.javascript_fixture('1122334455667788')
        self.assertEqual(len(entry['original']), 256*1024); self.assertEqual(len(entry['selected']), 349676)
        self.assertIn(b'document.currentScript.remove();', entry['original'])
        value = self.drain(b'<html><head><title>OWNED-REPRESENTATION-1122334455667788</title></head><body></body></html>')
        self.assertEqual(value['status'], 'completed'); self.assertFalse(value['output_truncated'])
        # This is bounded stream acceptance, not evidence that a browser ran.


class HistoricalJavascript(unittest.TestCase):
    def outcome(self, observations=None):
        blob = producer.auth.canonical({'dom_bytes': guest.MAX_DOM, 'dom_sha256': 'a'*64,
            'title': 'PRIVATE MARKUP MUST NOT LEAVE ROOT'} if observations is None else observations)
        return {'result': 'PASS', 'runs': [{'outcome': {'done': True, 'status': 'output_budget', 'returncode': -9,
            'writers_stopped': True, 'output_truncated': True, 'events': {'memory.events': 'oom_kill 0\n', 'pids.events': 'max 0\n', 'pids.current': '0'},
            'sandbox': {k: True for k in guest.SANDBOX}, 'records': [{'name': 'observations.json', 'bytes_hex': blob.hex(),
                'sha256': producer.auth.digest(blob), 'scope': 'opaque untrusted guest browser output'}]}}]}

    def test_outcome_summary_exposes_only_typed_status_counters_hashes_and_flags(self):
        value = producer.browser_outcome_metadata(self.outcome()); self.assertEqual(value['status'], 'output_budget')
        self.assertTrue(value['observations_available']); self.assertEqual(value['dom_bytes'], guest.MAX_DOM)
        self.assertNotIn('PRIVATE', json.dumps(value)); self.assertNotIn('title', value)
        for changed in [{'dom_bytes': True, 'dom_sha256': 'a'*64}, {'dom_bytes': guest.MAX_DOM+1, 'dom_sha256': 'a'*64},
                        {'dom_bytes': 1, 'dom_sha256': 'not a hash'}]:
            with self.subTest(changed=changed): self.assertFalse(producer.browser_outcome_metadata(self.outcome(changed))['observations_available'])
        bad = self.outcome(); bad['runs'][0]['outcome']['writers_stopped'] = False
        with self.assertRaises(ValueError): producer.browser_outcome_metadata(bad)

    def historical(self, mutation=None):
        rid = '212c0b19513e4fe8a31fdf114c2d6ec1'; job = 'ca8b61fc0c7b4d4f8288fe9ff63f131b'
        release = 'd0a9dbd78f0170b85e3a5516337908ec5809e3cc'; nonce = 'ee4fa4ca23784bd3'
        prefix = ('document.title="OWNED-REPRESENTATION-'+nonce+'";\n/*').encode()
        original = prefix+b'x'*(256*1024-len(prefix)-3)+b'*/\n'
        graph = Graph(original); view = observe_javascript(graph, graph.root); source = graph.payload(view['browser_representation'])
        binding = {'case_reference': {'case_id': 'case-forensic-'+'a'*32, 'manifest_sha256': '1'*64,
            'merkle_index_sha256': '2'*64, 'merkle_root_blake3': '3'*64}, 'original_source': {'bytes': len(original), 'sha256': bridge.digest(original)},
            'graph_sha256': '4'*64, 'interpretations_sha256': '5'*64, 'case_coverage': 'partial',
            'derivation': {'root': graph.root, 'selected': view['browser_representation'], 'nodes': graph.record()['nodes']},
            'bridge_contract_sha256': bridge.contract_hash()}
        request = {'schema': 'paw-s14-representation-request-v1', 'binding': binding, 'candidate': {
            'schema': 'paw-s14-representation-candidate-v1', 'profile': producer.adapter.HTML, 'request_id': rid,
            'selection_binding_sha256': bridge.digest(bridge.canonical(binding)), 'source': {'media_type': 'text/html', 'encoding': 'opaque',
                'bytes': len(source), 'sha256': bridge.digest(source), 'data_hex': source.hex()},
            'provenance': {'kind': 'operator-selected-forensic-representation', 'origin_verified': False,
                'interpretation_authenticated': False, 'execution_authority': 'none'},
            'created_at': 1, 'expires_at': 601, 'purpose': 'offline-explicit-forensic-selection-v1'}}
        raw = bridge.canonical(request); bridge.validate_request(raw, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); audit = root/'audit'; audit.mkdir(); state = root/'state'; (state/'jobs'/job).mkdir(parents=True)
            outer = {'result': 'FAIL', 'job': job, 'recipe': 'python-owned-v2', 'release_sha': release,
                     'error': 'owned_representation_expected_completion', 'real_samples_executed': 0}
            if mutation == 'outer': outer['result'] = 'PASS'
            (state/'jobs'/job/'result.json').write_bytes(bridge.canonical(outer))
            snapshot = audit/'runtime-snapshot'; (snapshot/'lab/s14').mkdir(parents=True)
            code = b'# inert historical snapshot, never executed\n'; (snapshot/'lab/s14/owned.py').write_bytes(code)
            files = {'lab/s14/owned.py': {'bytes': len(code), 'sha256': bridge.digest(code)}}
            proof = producer.auth.storage.canonical({'repository': producer.auth.storage.REPOSITORY, 'head_sha': 'b'*40, 'merge_sha': release})
            header = producer.auth.storage.canonical({'schema': 'paw-vm-root-snapshot-v1', 'repository': producer.auth.storage.REPOSITORY,
                'head_sha': 'b'*40, 'release_sha': release, 'proof_sha256': bridge.digest(proof), 'files': files})
            (snapshot/'release.json').write_bytes(header); (snapshot/'proof.json').write_bytes(proof)
            context = {'profile': producer.adapter.HTML, 'runtime_sources_sha256': bridge.digest(producer.auth.storage.canonical(files))}
            (audit/'policy.json').write_bytes(bridge.canonical({'context': context, 'mode': 'explicit-source-analysis'}))
            copied = audit/'authority-copy'/rid; copied.mkdir(parents=True); (copied/'request.json').write_bytes(raw)
            (audit/'results.json').write_bytes(bridge.canonical(self.outcome()))
            if mutation == 'request': (copied/'request.json').write_bytes(raw+b' ')
            if mutation == 'source': (snapshot/'lab/s14/owned.py').write_bytes(b'changed')
            for path in root.rglob('*'): path.chmod(0o700 if path.is_dir() else 0o400)
            @contextmanager
            def anchor(path):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: yield fd
                finally: os.close(fd)
            # Fixed paths/provenance and complete VM verification are explicit
            # inert boundaries; real snapshot and request/byte validators run.
            with mock.patch.object(producer, 'root_only'), mock.patch.object(producer, 'STATE', state), \
                 mock.patch.object(producer, 'audit_path', return_value=audit), \
                 mock.patch.object(producer.auth.fs, 'OWNER_UID', os.getuid()), \
                 mock.patch.object(producer.auth.fs, 'root_directory', anchor), \
                 mock.patch.object(producer, 'HISTORICAL_JS_MANIFEST_SHA256', bridge.digest(header)), \
                 mock.patch.object(producer, 'HISTORICAL_JS_REQUEST_SHA256', bridge.digest(raw)), \
                 mock.patch.object(producer, 'verify_single', side_effect=ValueError('inert VM verification failure') if mutation == 'verification' else None,
                     return_value={'result': 'PASS', 'request_sha256': bridge.digest(raw)}) as verify:
                value = producer.previous_owned_javascript_failure()
                verify.assert_called_once_with(audit, production=True)
                return value

    def test_pinned_historical_reader_requires_full_verification_and_preserves_failure_scope(self):
        value = self.historical(); self.assertEqual(value['outcome']['status'], 'output_budget')
        self.assertEqual(value['source_bytes'], 262144); self.assertEqual(value['browser_bytes'], 349676)
        self.assertFalse(value['smoke_accepted']); self.assertFalse(value['vm_started']); self.assertFalse(value['i08_installed'])
        self.assertNotIn('PRIVATE', json.dumps(value))
        for mutation in ['outer', 'source', 'request', 'verification']:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.historical(mutation)

    def test_unprivileged_historical_reader_refuses_before_reading_paths(self):
        with mock.patch.object(producer.os, 'geteuid', return_value=1000), mock.patch.object(producer.auth.fs, 'root_directory') as opened:
            with self.assertRaises(ValueError): producer.previous_owned_javascript_failure()
        opened.assert_not_called()


if __name__ == '__main__': unittest.main()
