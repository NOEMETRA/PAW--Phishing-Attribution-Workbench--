"""Inert complete producer control flow, with fake Root/VM/roles only."""
from contextlib import nullcontext
import hashlib,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch,Mock
from paw.core import browser_owned_broker as p

R='b'*40;J='c'*32;U='00000000-0000-4000-8000-000000000001'
GOOD={'reason':'requested_stop','connection_closed':True,'vm_uuid':U}

class Owner(unittest.TestCase):
    def simulate(self,owner,*,cleanup_fail=False,guest_bad=False,worker_bad=False):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);repo=root/'releases'/R;core=repo/'paw/core';core.mkdir(parents=True)
            for name in p.PROGRAMS:(core/name).write_bytes(('inert program '+name).encode())
            control=root/'control';control.mkdir();exports=root/'exports';exports.mkdir()
            base=root/'base';base.write_bytes(b'owned base');browser=root/'browser';browser.write_bytes(b'owned browser')
            def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
            context={'image_sha256':digest(browser),'chrome_version':'owned Chrome','chrome_binary_sha256':'e'*64}
            def mapped(value):
                path=Path(value)
                for old,new in [(Path('/opt/paw-vm/releases'),root/'releases'),
                    (Path('/var/lib/paw-s14/control'),control),(Path('/var/lib/paw-vm-exports'),exports)]:
                    if path==old or path.is_relative_to(old):return new/path.relative_to(old)
                return path
            def read(fd,name,limit):
                raw=(fd/name).read_bytes();assert len(raw)<=limit;return raw
            def module(name,**values):v=types.ModuleType(name);v.__dict__.update(values);return v
            auth=module('browser_authorization',capture=lambda:dict(context),validate_context=lambda _:None,
                canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode(),
                fs=types.SimpleNamespace(execution_lock=lambda:nullcontext(),root_directory=lambda p:nullcontext(p),
                    read=read,IMAGE_SHA256=digest(base)))
            published=[];stops=[];partitions=[]
            sandbox={k:True for k in ['renderer_seen','renderer_nnp','renderer_seccomp','renderer_pid_namespace','all_uids_nonroot']}
            if guest_bad:sandbox['all_uids_nonroot']=False
            class Channel:
                def __init__(self,nonce):self.nonce=nonce;self.count=0
                def call(self,op,**kwargs):
                    if op=='inspect':return {**context,'network_interfaces':['lo']}
                    if op=='start':return {'started':True}
                    self.count+=1
                    if self.count<=2:
                        return {'done':False,'network_request':{'nonce':self.nonce,'seq':self.count-1,
                            'url':p.SEED,'method':'GET','resource':'Document'}}
                    return {'done':True,'status':'completed','writers_stopped':True,'network_interfaces':['lo'],'sandbox':sandbox}
            class Gate:
                def __init__(self,args,**kwargs):
                    self.output=args.output;self.output.mkdir();self.active_vm=None;self.nonce=kwargs['seed_config']['nonce']
                    self.connection=types.SimpleNamespace(listAllDomains=lambda _:[],close=lambda:None)
                def snapshot_host(self):return {'owned':'unchanged'}
                def start(self,*args):
                    if owner is not None:(self.output/'owner.json').write_text(json.dumps(owner))
                    self.active_vm={'node':{'uuid':U},'owner_result_path':str(self.output/'owner.json'),'channel':Channel(self.nonce)}
                    return self.active_vm
                def stop(self,vm):stops.append('VM');self.active_vm=None
            class Actor:
                def __init__(self,job,epoch,release,role,*args,registry=None,**kwargs):
                    self.unit=role+'.service';self.pid=123;self.role=role;self.errors=b''
                    self.process=types.SimpleNamespace(poll=lambda:0,wait=lambda timeout:0);self.observation={'role':role}
                    registry.append(self)
            class Mediation:
                def __init__(self,*args):
                    self.nonce=args[2];self.sequence=1;Mediation.latest=self
                    self.ledger=types.SimpleNamespace(used=0,closed=False,close=lambda:{'owned':'inert stats'})
                    self.observations=[{'operation':'http','tls_verified_by_broker':True}for _ in range(2)]
                def response(self,request):
                    if worker_bad:
                        self.ledger.closed=True;raise ValueError('inert worker protocol loss')
                    self.ledger.used+=1
                    if request['url'].startswith('http:'):
                        self.observations.append({'operation':'http','tls_verified_by_broker':False})
                        return {'http_status':200},('PAW-OWNED-'+self.nonce).encode()
                    return {},b'owned'
                def transaction(self,*args):return {'request_sequence':self.sequence-1,'operation':'stop','stopped':True},b''
                def control(self,*args):pass
            def cleanup(actors):
                stops.extend(a.role for a in actors)
                if cleanup_fail:raise ValueError('inert unknown process stop')
            modules={'browser_authorization':auth,
                'browser_vm':module('browser_vm',BrowserVM=Gate,BROWSER_BASE=browser,LIMITS={'owned':'unchanged'}),
                'browser_offline_adapter':module('browser_offline_adapter',input_media=lambda *_:root/'owned.iso',available_memory=lambda:3*1024**3),
                'benign_guest_validation':module('benign_guest_validation',BASE=base,digest=digest),
                'vm_runtime_revalidation':module('vm_runtime_revalidation',network_state=lambda:{'owned':'unchanged'}),
                'reader_export':module('reader_export',publish_reader_tree=published.append)}
            with patch.dict(sys.modules,modules),patch.object(sys,'path',list(sys.path)), \
                patch.object(p,'HERE',core/'browser_owned_broker.py'),patch.object(p,'Path',mapped), \
                patch.object(p.os,'geteuid',return_value=0),patch.object(p,'prepare',return_value=(root,'f'*64)), \
                patch.object(p,'partition',side_effect=lambda unit,restore=False:partitions.append(restore)), \
                patch.object(p.kernel,'owned_validation',return_value={'result':'PASS','vm_started':False,'attestation_sha256':'f'*64}),patch.object(p.kernel,'Managed',Actor), \
                patch.object(p.kernel,'live_role',return_value=123456),patch.object(p.kernel,'vacant_ids'), \
                patch.object(p.kernel,'cleanup_actors',side_effect=cleanup), \
                patch.object(p.kernel,'private_json',side_effect=lambda _: {'reason':'requested_stop','epoch':Mediation.latest.nonce,'namespace_inode':123456}), \
                patch.object(p.kernel,'unit_properties',side_effect=lambda unit:{'ActiveState':'active','MainPID':str(os.getpid())if unit.startswith('paw-vm-owned-')else'123','MemoryMax':str(512*1024**2),'TasksMax':'64'}), \
                patch.object(p.shutil,'disk_usage',return_value=types.SimpleNamespace(free=20*1024**3)), \
                patch.object(p,'Mediation',Mediation),patch.object(p,'send_response'):
                if owner==GOOD and owner.get('connection_closed')is True and not cleanup_fail and not guest_bad and not worker_bad:
                    answer=p.run_owned(J,R);self.assertEqual(answer['result'],'PASS')
                else:
                    with self.assertRaises(ValueError):p.run_owned(J,R)
            self.assertIn('VM',stops);self.assertEqual(partitions,[False,True])
            known=owner==GOOD and owner.get('connection_closed')is True and not cleanup_fail
            self.assertEqual(len(published),1 if known else 0)
            if known:
                attestation=json.loads((published[0]/'attestation.json').read_bytes())
                self.assertEqual(attestation['result'],'FAIL'if guest_bad or worker_bad else'PASS')
                self.assertTrue(attestation['writers_stopped']);self.assertEqual(attestation['real_connections'],0)
                self.assertFalse(attestation['production_grants_enabled'])
            else:self.assertEqual(list(exports.iterdir()),[])
    def test_owned_complete_path_needs_expected_external_owner_before_pass(self):self.simulate(GOOD)
    def test_domain_absence_does_not_replace_missing_changed_or_unclosed_owner(self):
        for value in [None,{}, {**GOOD,'vm_uuid':'wrong'}, {**GOOD,'connection_closed':1},
                      {**GOOD,'reason':'guard_changed'}, {**GOOD,'reason':'qemu_exited'}]:
            with self.subTest(owner=value):self.simulate(value)
    def test_unknown_network_stop_blocks_even_failure_publication(self):self.simulate(GOOD,cleanup_fail=True)
    def test_known_stop_can_publish_only_diagnostic_fail_for_missing_sandbox(self):self.simulate(GOOD,guest_bad=True)
    def test_worker_protocol_loss_cannot_publish_pass_after_known_stop(self):self.simulate(GOOD,worker_bad=True)
    def test_root_identity_or_workspace_is_refused_before_any_privileged_callback(self):
        with patch.object(p.kernel,'owned_validation')as privileged:
            with self.assertRaises(ValueError):p.run_owned(J,R)
            with patch.object(p.os,'geteuid',return_value=0),self.assertRaises(ValueError):p.run_owned(J,R)
            privileged.assert_not_called()

if __name__=='__main__':unittest.main()
