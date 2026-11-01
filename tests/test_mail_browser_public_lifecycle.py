"""Actual coordinator/publication flow with inert VM and PID1 boundaries."""
from contextlib import ExitStack,nullcontext
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace,ModuleType
import unittest
from unittest.mock import patch
from paw.core import mail_browser_public as p,mail_browser_native as native
from paw.core import mail_browser_custody as custody,browser_owned_broker as existing
from paw.core import browser_owned_broker_guest as guest
from test_mail_browser_owned import owned_case

B='a'*32;R='b'*40;J='c'*32;E='d'*32;U='00000000-0000-4000-8000-000000000001'
GOOD={'reason':'requested_stop','connection_closed':True,'vm_uuid':U}

def module(name,**fields):
    value=ModuleType(name);value.__dict__.update(fields);return value

class Lifecycle(unittest.TestCase):
    def simulate(self,owner=GOOD,*,bad_stop=False,bad_network_stop=False,transport_failure=False,
                 wrong_sandbox=False,partial_capture=False,after_snapshot=False):
        clock=[10**9]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);case=owned_case(root);request=json.loads(custody.prepare(case,0))
            control=root/'control';control.mkdir();exports=root/'exports';exports.mkdir()
            folder=root/'roles';folder.mkdir();(folder/'guard-created').write_bytes(b'')
            base=root/'base';base.write_bytes(b'owned base')
            browser=root/'browser';browser.write_bytes(b'owned browser')
            digest=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
            context={'image_sha256':digest(browser),'chrome_version':'inert Chrome','chrome_binary_sha256':'e'*64}
            approval={'batch_id':B,'release_sha':R,'context':{'browser':context,'ca_sha256':'f'*64,'uplink':{}}}
            binding={'job':J,'epoch':E,'slot':0}
            sandbox={k:True for k in ['all_uids_nonroot','renderer_nnp','renderer_seccomp','renderer_pid_namespace','renderer_seen']}
            if wrong_sandbox:sandbox['renderer_seen']=False
            published=[];events=[];channels=[]
            def mapped(value):
                path=Path(value)
                old=Path('/var/lib/paw-s14/control')
                return control/path.relative_to(old) if path==old or path.is_relative_to(old) else path
            def read(fd,name,cap):
                raw=(fd/name).read_bytes();assert len(raw)<=cap;return raw
            auth=module('browser_authorization',capture=lambda:dict(context),validate_context=lambda _:None,
                fs=SimpleNamespace(execution_lock=lambda:nullcontext(),root_directory=lambda path:nullcontext(path),
                                   read=read,IMAGE_SHA256=digest(base)))
            class Channel:
                def __init__(self):
                    self.completed=0;self.snapshot=False;self.capture_calls=[]
                    self.transfer=guest.Transfer(E,{'dom.html':b'owned DOM','screenshot.png':b'opaque inert PNG'},True)
                    channels.append(self)
                def terminal(self,status):
                    return {'done':True,'status':status,'writers_stopped':True,'network_interfaces':['lo'],
                            'sandbox':dict(sandbox),'capture_artifacts':self.transfer.manifest}
                def call(self,op,**kw):
                    if op=='inspect':return {**context,'network_interfaces':['lo']}
                    if op=='start':return {'started':True}
                    if op=='artifact':
                        self.capture_calls.append(kw['value'])
                        if partial_capture and kw['value']['name']=='screenshot.png':raise ValueError('inert PNG lost')
                        return self.transfer.read(kw['value'])
                    if op=='cancel':return self.terminal('failed')
                    if self.completed<1 or self.snapshot and after_snapshot:
                        return {'done':False,'network_request':{'nonce':E,'seq':self.completed,
                            'url':request['url'],'method':'GET','resource':'Document'}}
                    if not self.snapshot:
                        self.snapshot=True;return {'done':False,'network_quiescent':True}
                    return self.terminal('completed')
            class Gate:
                def __init__(self,args,**kw):
                    assert kw['phase']=='mail_public';assert kw['seed_config']['url']==request['url']
                    self.output=args.output;self.output.mkdir();self.active_vm=None
                    self.connection=SimpleNamespace(listAllDomains=lambda _:[],close=lambda:events.append('connection-close'))
                def snapshot_host(self):return {'unchanged':True}
                def start(self,*args):
                    if owner is not None:(self.output/'owner.json').write_text(json.dumps(owner))
                    self.active_vm={'node':{'uuid':U},'owner_result_path':str(self.output/'owner.json'),'channel':Channel()}
                    return self.active_vm
                def stop(self,vm):events.append('VM-stop');self.active_vm=None
            class Prep:
                def __init__(self,job,epoch,release,mode,actors):
                    self.owner=SimpleNamespace(observation={'role':'keeper'})
                    self.worker=SimpleNamespace(observation={'role':'probe'})
                    actors.extend([self.owner,self.worker]);events.append('roles-start')
                def poll(self):return True
            class Mediation:
                def __init__(self,*args):
                    self.budget=args[5];self.observations=[];self.bodies=[]
                    self.ledger=SimpleNamespace(close=lambda:{'scope':'inert'})
                def response(self,frame):
                    self.budget.request(0);self.budget.reserve(0)
                    if transport_failure:
                        self.budget.uncertain(0);raise ValueError('inert transport failed')
                    self.budget.complete(0,5);return {},b'owned'
                def stop(self):
                    events.append('network-stop')
                    if bad_network_stop:raise ValueError('inert early worker exit')
            def cleanup(actors):
                events.append('roles-stop')
                if bad_stop:raise ValueError('unknown process stop')
            modules={
                'browser_authorization':auth,
                'browser_vm':module('browser_vm',BrowserVM=Gate,BROWSER_BASE=browser,LIMITS={'unchanged':True}),
                'browser_offline_adapter':module('browser_offline_adapter',input_media=lambda *_:root/'owned.iso',available_memory=lambda:3*1024**3),
                'benign_guest_validation':module('benign_guest_validation',BASE=base,digest=digest),
                'vm_runtime_revalidation':module('vm_runtime_revalidation',network_state=lambda:{'unchanged':True}),
                'reader_export':module('reader_export',publish_reader_tree=published.append)}
            with ExitStack() as stack:
                for context_manager in [patch.dict(sys.modules,modules),patch.object(p,'Path',mapped),
                    patch.object(p,'EXPORT_ROOT',exports),patch.object(p,'require_idle'),
                    patch.object(p,'prepare_network',return_value=(folder,'f'*64)),
                    patch.object(p,'NetworkPreparation',Prep),patch.object(p,'Mediation',Mediation),
                    patch.object(p,'remove_tables',side_effect=lambda *a:events.append('guard-remove')),
                    patch.object(p.kernel,'cleanup_actors',side_effect=cleanup),patch.object(p.kernel,'vacant_ids'),
                    patch.object(native,'system_libvirt',return_value=(None,{})),
                    patch.object(native,'scope',return_value=approval),patch.object(native,'context',return_value=approval['context']),
                    patch.object(native,'_mkdir',side_effect=lambda path:path.mkdir(mode=0o700)),
                    patch.object(existing,'send_response',side_effect=lambda ch,*a:setattr(ch,'completed',ch.completed+1)),
                    patch.object(p.time,'sleep',side_effect=lambda _:clock.__setitem__(0,clock[0]+10**7)),
                    patch.object(p.time,'monotonic_ns',side_effect=lambda:clock[0]),
                    patch.object(p.time,'monotonic',side_effect=lambda:clock[0]/10**9)]:stack.enter_context(context_manager)
                known=owner==GOOD and owner.get('connection_closed') is True and not bad_stop
                if known:answer=p.run_capture(approval,binding,request,p.BatchBudget([request['url']]*3))
                else:
                    with self.assertRaisesRegex(ValueError,'unknown_stop_no_publication'):
                        p.run_capture(approval,binding,request,p.BatchBudget([request['url']]*3))
            self.assertIn('VM-stop',events);self.assertIn('connection-close',events)
            self.assertEqual(len(published),1 if known else 0)
            if known:
                receipt=p.validate_receipt((published[0]/'receipt.json').read_bytes(),request,B,0)
                failed=bad_network_stop or transport_failure or wrong_sandbox or partial_capture or after_snapshot
                self.assertEqual(answer['status'],'failed' if failed else 'completed')
                self.assertEqual(receipt['status'],answer['status'])
                if not failed:self.assertLess(events.index('network-stop'),events.index('VM-stop'))
                if partial_capture:
                    self.assertEqual([v['name'] for v in receipt['artifacts']],['dom.html','network.json'])
                    self.assertEqual(len(channels[0].capture_calls),3)
                if transport_failure:
                    self.assertEqual(answer['budget']['response_bytes_or_unrecoverable_reservations'][0],p.CASE_BYTES)
                if after_snapshot:
                    record=json.loads((published[0]/'network.json').read_bytes())
                    self.assertIn('network_after_snapshot',record['error'])
    def test_complete_flow_stops_network_before_capture_and_seals_only_after_external_stop(self):self.simulate()
    def test_domain_absence_cannot_replace_external_owner_disposition(self):
        for owner in [None,{}, {**GOOD,'connection_closed':1},{**GOOD,'reason':'guard_changed'},
                      {**GOOD,'vm_uuid':'00000000-0000-4000-8000-000000000002'}]:
            with self.subTest(owner=owner):self.simulate(owner)
    def test_unknown_network_writer_blocks_even_diagnostic_publication(self):self.simulate(bad_stop=True)
    def test_failed_worker_stop_never_publishes_completed(self):self.simulate(bad_network_stop=True)
    def test_missing_renderer_sandbox_publishes_only_failed_after_known_stop(self):self.simulate(wrong_sandbox=True)
    def test_transport_failure_charges_full_uncertain_reservation(self):self.simulate(transport_failure=True)
    def test_partial_capture_retains_DOM_and_does_not_restart_consumed_stream(self):self.simulate(partial_capture=True)
    def test_network_after_snapshot_cannot_reopen_roles(self):self.simulate(after_snapshot=True)

if __name__=='__main__':unittest.main()
