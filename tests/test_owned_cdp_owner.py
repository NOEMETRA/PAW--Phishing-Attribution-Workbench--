"""Inert producer control-flow test; fake Root/VM, never privileged execution."""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from paw.core import browser_owned_cdp_probe as probe

RELEASE='b'*40;JOB='c'*32;UUID='00000000-0000-4000-8000-000000000001'
GOOD={'reason':'requested_stop','connection_closed':True,'vm_uuid':UUID}


class OwnerDisposition(unittest.TestCase):
    def simulate(self,owner,expect_pass):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);releases=root/'releases';repo=releases/RELEASE
            core=repo/'paw/core';core.mkdir(parents=True)
            for name in ['browser_cdp.py','browser_owned_cdp_guest.py','browser_owned_cdp_probe.py']:
                (core/name).write_bytes(('owned inert program '+name).encode())
            control=root/'control';control.mkdir();exports=root/'exports';exports.mkdir()
            attr=root/'attr';attr.write_text('unconfined')
            base=root/'base.img';base.write_bytes(b'owned foundation')
            browser=root/'browser.img';browser.write_bytes(b'owned browser image')
            def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
            context={'image_sha256':digest(browser),'chrome_version':'Google Chrome owned',
                'chrome_binary_sha256':'a'*64}
            def mapped(value):
                path=Path(value)
                for old,new in [(Path('/opt/paw-vm/releases'),releases),(Path('/var/lib/paw-s14/control'),control),
                                (Path('/var/lib/paw-vm-exports'),exports)]:
                    if path==old or path.is_relative_to(old):return new/path.relative_to(old)
                if path==Path('/proc/self/attr/current'):return attr
                return path
            def module(name,**attrs):
                value=types.ModuleType(name);value.__dict__.update(attrs);return value
            def read(fd,name,limit):
                raw=(fd/name).read_bytes()
                if len(raw)>limit:raise ValueError('inert read budget')
                return raw
            auth=module('browser_authorization',capture=lambda:dict(context),validate_context=lambda _:None,
                canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode(),
                fs=types.SimpleNamespace(execution_lock=lambda:nullcontext(),root_directory=lambda p:nullcontext(p),
                    read=read,IMAGE_SHA256=digest(base)))
            sandbox={k:True for k in ['renderer_seen','renderer_nnp','renderer_seccomp','renderer_pid_namespace','all_uids_nonroot']}
            published=[]
            class Gate:
                def __init__(self,args,**kwargs):
                    self.output=args.output;self.output.mkdir();self.active_vm=None;self.report={}
                    self.connection=types.SimpleNamespace(listAllDomains=lambda _:[],close=lambda:None)
                def snapshot_host(self):return {'fixture':'unchanged'}
                def start(self,*args):
                    if owner is not None:(self.output/'owner.json').write_text(json.dumps(owner))
                    def call(op,**kwargs):
                        if op=='inspect':return {**context,'network_interfaces':['lo']}
                        if op=='start':return {'started':True}
                        return {'done':True,'status':'completed','writers_stopped':True,
                            'network_interfaces':['lo'],'requests':2,'cdp_frames':10,'sandbox':sandbox}
                    self.active_vm={'actual':{'uuid':UUID},'node':{'uuid':UUID},
                        'owner_result_path':str(self.output/'owner.json'),'channel':types.SimpleNamespace(call=call)}
                    return self.active_vm
                def stop(self,vm):self.active_vm=None
            modules={'browser_authorization':auth,
                'browser_vm':module('browser_vm',BrowserVM=Gate,BROWSER_BASE=browser,BROWSER_META=root/'meta',
                    validate_xml=lambda _:None,LIMITS={'fixture':'same'}),
                'browser_offline_adapter':module('browser_offline_adapter',input_media=lambda *_:root/'owned.iso',available_memory=lambda:3*1024**3),
                'benign_guest_validation':module('benign_guest_validation',BASE=base,digest=digest),
                'reader_export':module('reader_export',publish_reader_tree=published.append)}
            with patch.dict(sys.modules,modules),patch.object(sys,'path',list(sys.path)), \
                 patch.object(probe,'__file__',str(core/'browser_owned_cdp_probe.py')), \
                 patch.object(probe,'Path',mapped),patch.object(probe.os,'geteuid',return_value=0), \
                 patch.object(probe.shutil,'disk_usage',return_value=types.SimpleNamespace(free=20*1024**3)):
                if expect_pass:
                    result=probe.run_owned(JOB,RELEASE)
                    self.assertEqual(result['result'],'PASS');self.assertEqual(len(published),1)
                    attestation=json.loads(Path(result['attestation']).read_text())
                    self.assertEqual(attestation['vm_uuid'],UUID)
                    self.assertEqual(attestation['owner_disposition'],GOOD)
                else:
                    with self.assertRaisesRegex(ValueError,'failed_no_publication'):probe.run_owned(JOB,RELEASE)
                    self.assertEqual(published,[])
                    self.assertEqual(list(exports.iterdir()),[])
    def test_requested_stop_matching_uuid_and_closed_connection_can_publish(self):
        self.simulate(GOOD,True)
    def test_absence_alone_does_not_authorize_pass_on_unexpected_owner_disposition(self):
        for reason in ['guard_changed','limits_changed','qemu_exited','controller_lost','owner_error']:
            with self.subTest(reason=reason):self.simulate({**GOOD,'reason':reason},False)
    def test_missing_wrong_uuid_or_unclosed_owner_result_refuses(self):
        for owner in [None,{}, {**GOOD,'vm_uuid':'wrong'}, {**GOOD,'connection_closed':False},
                      {**GOOD,'connection_closed':1},{**GOOD,'reason':None}]:
            with self.subTest(owner=owner):self.simulate(owner,False)

class StoppedDiagnostic(unittest.TestCase):
    def setUp(self):
        lab = Path(__file__).resolve().parents[1] / 'lab/s14'
        self.enterContext(patch.object(sys, 'path', [str(lab), *sys.path]))

    def read(self, worker_delta=None, report_delta=None, serial=None, missing_worker=False):
        job = Path('/var/lib/paw-vm/jobs') / probe._PRIOR_JOB
        releases = Path('/opt/paw-vm/releases')
        audit = Path('/var/lib/paw-s14/control') / probe._PRIOR_AUDIT
        programs = {name: hashlib.sha256(name.encode()).hexdigest() for name in probe._PROGRAMS}
        worker = {'job': probe._PRIOR_JOB, 'release_sha': probe._PRIOR_RELEASE,
                  'result': 'FAIL', 'recipe': 'browser-owned-v1', 'real_samples_executed': 0,
                  'plain_http_probe_result': 'PASS', 'owned_mail_capture': {'status': 'completed'},
                  'error': 'owned_cdp_probe_failed_no_publication', **(worker_delta or {})}
        report = {'schema': 'paw-owned-cdp-probe-v1', 'job': probe._PRIOR_JOB,
                  'release_sha': probe._PRIOR_RELEASE, 'result': 'FAIL', 'programs': programs,
                  'real_connections': 0, 'actual_real_samples': 0,
                  'error': 'TimeoutError:guest_channel_deadline', 'writers_stopped': True,
                  'host_restored': True, **(report_delta or {})}
        files = {'results.json': json.dumps(report).encode(), 'owned-cdp-probe-serial.log': serial}

        def directory(path):
            self.assertIn(path, (job, releases, audit))
            if path == job and missing_worker:
                raise FileNotFoundError
            return nullcontext(path)

        def audit_read(fd, name, limit):
            self.assertEqual(fd, audit)
            self.assertEqual(limit, {'results.json': 256 * 1024, 'owned-cdp-probe-serial.log': 2 * 1024**2}[name])
            if files[name] is None:
                raise FileNotFoundError
            return files[name]

        manifest = {'files': {'paw/core/' + name: {'sha256': digest} for name, digest in programs.items()}}
        with patch('one_use_authorization.root_directory', side_effect=directory) as opened, \
                patch('one_use_authorization.read', side_effect=audit_read), \
                patch('vm_operator_host.private_json', return_value=worker) as state, \
                patch('vm_release_storage.verify', return_value=(manifest, {})) as snapshot, \
                patch.object(probe.os, 'geteuid', return_value=0):
            result = probe.previous_owned_cdp_failure()
            if missing_worker:
                opened.assert_called_once_with(job)
                snapshot.assert_not_called()
            else:
                state.assert_called_once_with(job, 'result.json')
                snapshot.assert_called_once_with(releases, probe._PRIOR_RELEASE, probe._PRIOR_MANIFEST)
            return result

    def test_stored_only_diagnostic_surfaces_deadline_and_finite_guest_progress(self):
        frames = [
            {'ready': True, 'network_interfaces': ['lo']},
            {'ok': True, 'id': 2, 'data': {'started': True}},
            {'ok': True, 'id': 3, 'data': {'done': False, 'stage': 'running'}},
            {'ok': True, 'id': 4, 'data': {'done': True, 'status': 'failed', 'writers_stopped': True,
                                          'error': 'ValueError:owned_whole_deadline', 'private': 'redact-this'}},
        ]
        serial = b'PAW14 {invalid}\n' + b''.join(b'PAW14 ' + json.dumps(v).encode() + b'\n' for v in frames)
        serial += b'Traceback (most recent call last):\r\nValueError: owned_actual_js_or_sandbox_missing\r\n'
        result = self.read(serial=serial)
        self.assertEqual(result['worker_error'], 'owned_cdp_probe_failed_no_publication')
        self.assertEqual(result['error'], 'guest_channel_deadline')
        self.assertEqual(result['serial'], {'ready': True, 'started': True, 'last_poll': 'running',
                                            'terminal': {'status': 'failed', 'error': 'owned_whole_deadline',
                                                         'writers_stopped': True},
                                            'traceback_seen': True, 'traceback_reason': 'owned_actual_js_or_sandbox_missing'})
        self.assertNotIn('redact-this', json.dumps(result))

    def test_unavailable_and_unclassified_keep_failure_and_never_copy_raw_reason(self):
        self.assertEqual(self.read(missing_worker=True), {'available': False, 'job': probe._PRIOR_JOB})
        result = self.read(report_delta={'error': 'sensitive path', 'cleanup_error': 'other private text'})
        self.assertEqual(result['audit_result'], 'FAIL')
        self.assertIsNone(result['serial'])
        self.assertEqual((result['error'], result['cleanup_error']), ('unclassified', 'unclassified'))

    def test_mismatched_identity_or_non_synthetic_record_refuses(self):
        with self.assertRaisesRegex(ValueError, 'historical_worker_binding'):
            self.read(worker_delta={'job': 'a' * 32})
        with self.assertRaisesRegex(ValueError, 'historical_audit_binding'):
            self.read(report_delta={'real_connections': 1})


if __name__=='__main__':unittest.main()
