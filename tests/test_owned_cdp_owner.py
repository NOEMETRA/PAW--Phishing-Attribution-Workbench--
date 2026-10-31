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

if __name__=='__main__':unittest.main()
