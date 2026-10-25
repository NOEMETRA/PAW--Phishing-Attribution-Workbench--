"""Inert browser protocol tests: no VM, browser, sample or network execution."""
import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import time
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1] if HERE.parent.name == 'lab' else HERE.parents[1] / 'PAW'
sys.path.insert(0, str(REPO)); sys.path.insert(0, str(REPO / 'lab/s14'))
if HERE.parent.name == 'lab':
    from paw.core import browser_bridge as contract
else:
    spec = importlib.util.spec_from_file_location('paw.core.browser_bridge', HERE / 'browser_bridge.py')
    contract = importlib.util.module_from_spec(spec); sys.modules[spec.name] = contract; spec.loader.exec_module(contract)
sys.path.insert(0, str(HERE))
import browser_authorization as auth
import browser_guest as guest
import browser_offline_adapter as adapter


def frame(source=b'<title>owned</title>', now=100):
    return {'schema': 'paw-s14-browser-candidate-v1', 'profile': contract.PROFILE,
            'request_id': 'a'*32, 'case_reference_sha256': 'b'*64,
            'source': {'media_type': 'text/html', 'encoding': 'opaque', 'bytes': len(source),
                       'sha256': hashlib.sha256(source).hexdigest(), 'data_hex': source.hex()},
            'provenance': {'kind': 'operator-supplied', 'reference': 'PAW sealed-case HTML attachment; custody only'},
            'created_at': now, 'expires_at': now+900, 'purpose': 'offline-html-single-job-review'}


class Contract(unittest.TestCase):
    def test_exact_opaque_html_bytes_and_budget(self):
        for data in [b'\x00\xff<!doctype html>', b'x'*contract.MAX_SOURCE]:
            value = frame(data)
            self.assertEqual(contract.validate_frame(contract.canonical(value), now=100), value)
        for data in [b'', b'x'*(contract.MAX_SOURCE+1)]:
            with self.assertRaises(ValueError): contract.validate_frame(contract.canonical(frame(data)), now=100)

    def test_digest_and_profile_confusion_refused(self):
        for keys, value in [(('source', 'sha256'), 'c'*64), (('source', 'media_type'), 'text/x-python'),
                            (('source', 'bytes'), True), (('profile',), 'linux-python-offline-v1'),
                            (('purpose',), 'anything'), (('request_id',), '../evil')]:
            changed = frame(); target = changed
            for key in keys[:-1]: target = target[key]
            target[keys[-1]] = value
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                contract.validate_frame(contract.canonical(changed), now=100)

    def test_lease_duplicates_and_noncanonical_refused(self):
        value = frame(); raw = contract.canonical(value)
        for now in [99, 1000]:
            with self.assertRaises(ValueError): contract.validate_frame(raw, now=now)
        for bad in [json.dumps(value).encode(), b'{"schema":"x",'+raw[1:]]:
            with self.assertRaises(ValueError): contract.validate_frame(bad, now=100)

    def test_dom_title_is_parsed_not_found_inside_script(self):
        parser = guest.DOM(); parser.feed('<title>before</title><script>document.title="after"</script>')
        self.assertEqual(parser.title, 'before'); self.assertEqual(parser.counts['script'], 1)
        parser = guest.DOM(); parser.feed('<title>'+'x'*100+'</title><form><input><iframe></iframe>')
        self.assertEqual(parser.title, 'x'*32); self.assertEqual(parser.counts['form'], 1)

    def test_finished_guest_poll_is_stable(self):
        completed = {'done': True, 'status': 'completed'}
        with patch.object(guest, 'DONE', completed), patch.object(guest, 'ACTIVE', object()):
            self.assertIs(guest.poll(), completed); self.assertIs(guest.finish('cancelled'), completed)

    def test_oom_kernel_console_text_cannot_be_accepted_as_a_response(self):
        # Actual owned memory trial: printk appended inside the serial JSON line.
        line = '{"id":105,"ok":true,"data":{"done":false}}[   55.002277] Memory cgroup out of memory'
        with self.assertRaises(json.JSONDecodeError): json.loads(line)
        # Reserve only the guest console; retain its other printk parameters.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'printk'; path.write_text('7\t4\t1\t7\n')
            with patch.object(guest, 'Path', return_value=path): guest.reserve_control_console()
            self.assertEqual(path.read_text().split(), ['0', '4', '1', '7'])
            path.write_text('unexpected')
            with patch.object(guest, 'Path', return_value=path), self.assertRaises(ValueError): guest.reserve_control_console()


class Authority(unittest.TestCase):
    def context(self):
        return {'platform': {}, 'image_sha256': '1'*64, 'image_certificate_sha256': '2'*64,
                'chrome_version': 'Google Chrome owned', 'chrome_binary_sha256': '3'*64,
                'bridge_contract_sha256': contract.contract_hash(), 'qemu_limits': dict(auth.LIMITS),
                'guest_memory_bytes': 1024**3, 'job_memory_bytes': 512*1024**2, 'job_tasks': 256}

    def policy(self, context):
        return {'schema': 'paw-s14-browser-policy-v1', 'scope': auth.SCOPE, 'context': context,
                'mode': 'validation', 'approved_source_hashes': [frame()['source']['sha256']],
                'readiness_sha256': None, 'validation_manifest_sha256': '4'*64,
                'created_at': 100, 'expires_at': 1000}

    def test_grant_binds_all_parent_frame_source_policy_and_lease(self):
        context = self.context(); policy = self.policy(context); raw = contract.canonical(frame())
        policy_raw = contract.canonical(policy)
        grant = {'schema': 'paw-s14-browser-grant-v1', 'scope': auth.SCOPE, **auth.inspect(raw, 101),
                 'policy_sha256': auth.digest(policy_raw), 'execution_purpose': 'validation',
                 'created_at': 101, 'expires_at': 900}
        with patch.object(auth.platform, 'validate_context'):
            self.assertEqual(auth.validate_binding(raw, grant, policy_raw, context, now=102)[2], b'<title>owned</title>')
            for key in ['request_id', 'case_reference_sha256', 'frame_sha256', 'source_sha256', 'policy_sha256', 'execution_purpose']:
                bad = copy.deepcopy(grant); bad[key] = 'bad'
                with self.subTest(key=key), self.assertRaises(ValueError):
                    auth.validate_binding(raw, bad, policy_raw, context, now=102)
            with self.assertRaises(ValueError): auth.validate_binding(raw, grant, policy_raw, context, now=900)

    def test_validation_never_substitutes_for_readiness(self):
        context = self.context(); policy = self.policy(context); policy['mode'] = 'sample-analysis'
        with patch.object(auth.platform, 'validate_context'), self.assertRaises(ValueError):
            auth.validate_policy(contract.canonical(policy), context, now=102)

    def test_changed_image_or_contract_or_limits_refused(self):
        context = self.context()
        for key, value in [('image_sha256', 'invalid'), ('bridge_contract_sha256', '0'*64),
                           ('guest_memory_bytes', 512*1024**2), ('job_tasks', 257),
                           ('qemu_limits', {})]:
            changed = copy.deepcopy(context); changed[key] = value
            with patch.object(auth.platform, 'validate_context'), self.subTest(key=key), self.assertRaises(ValueError):
                auth.validate_context(changed)

    def test_global_consumption_replay_and_frame_change_refused(self):
        context = self.context(); now = int(time.time()); value = frame(now=now)
        raw = contract.canonical(value); policy = self.policy(context)
        policy.update(created_at=now, expires_at=now+900)
        policy_raw = contract.canonical(policy)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            @contextlib.contextmanager
            def opened():
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try: yield fd
                finally: os.close(fd)
            with patch.object(auth, 'store', opened), patch.object(auth.fs, 'OWNER_UID', os.getuid()), \
                    patch.object(auth.os, 'geteuid', return_value=0), patch.object(auth.platform, 'validate_context'):
                with auth.store() as fd: auth.fs.exclusive(fd, 'policy-'+auth.digest(policy_raw)+'.json', policy_raw)
                auth.issue(raw, policy_raw, context)
                changed = copy.deepcopy(value); changed['case_reference_sha256'] = 'e'*64
                with self.assertRaises(ValueError): auth.consume(contract.canonical(changed), policy_raw, context)
                self.assertFalse((root/'consumed').exists())
                ledger, grant_raw, summary, candidate, source = auth.consume(raw, policy_raw, context)
                self.assertEqual(source, b'<title>owned</title>'); auth.confirm_consumed(ledger)
                with self.assertRaises(FileExistsError): auth.consume(raw, policy_raw, context)
                self.assertEqual(len(list((root/'consumed').iterdir())), 1)


class Output(unittest.TestCase):
    def outcome(self):
        raw = b'{"owned":true}\n'
        return {'done': True, 'status': 'completed', 'returncode': 0, 'writers_stopped': True,
                'events': {'memory.events': 'oom_kill 0\n', 'pids.events': 'max 0\n', 'pids.current': '0'},
                'output_truncated': False, 'sandbox': {k: True for k in
                    ['renderer_seen', 'renderer_nnp', 'renderer_seccomp', 'renderer_pid_namespace', 'all_uids_nonroot']},
                'records': [{'name': 'observations.json', 'bytes_hex': raw.hex(), 'sha256': auth.digest(raw),
                             'scope': 'opaque untrusted guest browser output'}]}

    def test_opaque_records_validate_without_interpretation(self):
        for raw in [b'\xff\x00<script>owned inert bytes</script>', b'x'*1024]:
            value = self.outcome(); value['records'][0].update(bytes_hex=raw.hex(), sha256=auth.digest(raw))
            self.assertEqual(adapter.validate_outcome(value), value)

    def test_malformed_live_oversize_and_unsandboxed_completed_output_refused(self):
        for kind in ['live', 'size', 'digest', 'path', 'sandbox', 'status', 'pids', 'count']:
            value = self.outcome()
            if kind == 'live': value['writers_stopped'] = False
            elif kind == 'size': value['records'][0].update(bytes_hex=(b'x'*1025).hex(), sha256=auth.digest(b'x'*1025))
            elif kind == 'digest': value['records'][0]['sha256'] = '0'*64
            elif kind == 'path': value['records'][0]['name'] = '../evil'
            elif kind == 'sandbox': value['sandbox']['renderer_seccomp'] = False
            elif kind == 'status': value['status'] = 'safe'
            elif kind == 'pids': value['events']['pids.current'] = '1'
            elif kind == 'count': value['records'] = []
            with self.subTest(kind=kind), self.assertRaises(ValueError): adapter.validate_outcome(value)


if __name__ == '__main__': unittest.main()
