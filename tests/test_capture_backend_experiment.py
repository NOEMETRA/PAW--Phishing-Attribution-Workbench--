"""Ordinary inert boundary checks; no QEMU, imports of capture libraries or sockets."""
import hashlib,importlib.util,json,tempfile,unittest,sys
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'experiments/capture_backends'/(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
run=module('run_vm');guest=module('guest')
def terminal(nonce,first=None):
    rows=[{'mode':m,'case':c,'writers_stopped':True,'result':{'status':'failed_or_timeout','reason':'inert documented failure'}}
        for m in guest.MODES for c in guest.CASES]
    if first is not None:rows[0]['result']=first
    return {'event':'done','nonce':nonce,'schema':'paw-capture-backend-experiment-v1','network_interfaces':['lo'],
        'production_acceptance':False,'real_connections':0,'guest_writers_stopped':True,'runs':rows}
def export(receiver,name,raw):
    from browser_cdp import response_chunks
    seq=receiver.seq;receiver.feed({'event':'file','nonce':receiver.nonce,'seq':seq,'name':name,'bytes':len(raw),
        'sha256':hashlib.sha256(raw).hexdigest()})
    for row in response_chunks(receiver.nonce,seq,raw):receiver.feed({'event':'chunk','row':row})
class Protocol(unittest.TestCase):
    def test_real_binary_export_requires_declared_digest_nonce_order_and_safe_name(self):
        from browser_cdp import response_chunks
        n='a'*32;raw=b'owned artifact';header={'event':'file','nonce':n,'seq':0,'name':'playwrightcapture-http-js/dom.html',
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        for change in [{'name':'../escape'},{'name':'lacus-api-http-js/../../escape'},{'nonce':'b'*32},
            {'seq':True},{'seq':1},{'bytes':2*1024**2+1},{'extra':'accepted?'}]:
            with tempfile.TemporaryDirectory()as d,self.subTest(change=change),self.assertRaises(ValueError):
                run.Receiver(n,Path(d)).feed({**header,**change})
        with tempfile.TemporaryDirectory()as d:
            receiver=run.Receiver(n,Path(d));receiver.feed(header)
            for row in response_chunks(n,0,raw):receiver.feed({'event':'chunk','row':row})
            self.assertEqual((Path(d)/header['name']).read_bytes(),raw)
            with self.assertRaises(ValueError):receiver.feed(header)
        with tempfile.TemporaryDirectory()as d:
            receiver=run.Receiver(n,Path(d));receiver.feed({**header,'sha256':'0'*64})
            with self.assertRaises(ValueError):
                for row in response_chunks(n,0,raw):receiver.feed({'event':'chunk','row':row})
    def test_terminal_does_not_hide_truncated_export_or_missing_cases(self):
        with tempfile.TemporaryDirectory()as d:
            receiver=run.Receiver('a'*32,Path(d))
            with self.assertRaises(ValueError):receiver.feed({'event':'done','nonce':'a'*32,'runs':[]})
            with self.assertRaises(ValueError):receiver.feed({'event':'chunk','row':{}})
    def test_terminal_cannot_be_followed_by_another_artifact(self):
        n='a'*32
        with tempfile.TemporaryDirectory()as d:
            receiver=run.Receiver(n,Path(d));receiver.feed(terminal(n))
            with self.assertRaises(ValueError):receiver.feed({'event':'file','nonce':n,'seq':0,
                'name':'playwrightcapture-http-js/dom.html','bytes':0,'sha256':hashlib.sha256(b'').hexdigest()})
    def test_claimed_capture_requires_received_result_identity_and_exact_artifact_inventory(self):
        n='a'*32;body=b'owned';key='playwrightcapture-http-js';item={'name':'dom.html','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        result={'mode':'playwrightcapture','case':'http-js','nonce':n,'status':'partial','artifact_inventory':[item]}
        for change,send_body in [({'nonce':'b'*32},True),({},False),({'status':'captured'},True)]:
            with tempfile.TemporaryDirectory()as d,self.subTest(change=change,send_body=send_body):
                receiver=run.Receiver(n,Path(d));value={**result,**change}
                if send_body:export(receiver,key+'/dom.html',body)
                export(receiver,key+'/result.json',json.dumps(value).encode())
                with self.assertRaises(ValueError):receiver.feed(terminal(n,value))
        with tempfile.TemporaryDirectory()as d:
            receiver=run.Receiver(n,Path(d));export(receiver,key+'/dom.html',body)
            export(receiver,key+'/result.json',json.dumps(result).encode());receiver.feed(terminal(n,result))
            self.assertIsNotNone(receiver.done)
        with tempfile.TemporaryDirectory()as d:
            receiver=run.Receiver(n,Path(d));items=[]
            for name,raw in [('dom.html',body),('har.json',b'{"log":{}}'),('screenshot.png',b'\x89PNG\r\n\x1a\n')]:
                export(receiver,key+'/'+name,raw);items.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            value={**result,'status':'captured','artifact_inventory':items}
            export(receiver,key+'/result.json',json.dumps(value).encode());receiver.feed(terminal(n,value))
            self.assertIsNotNone(receiver.done)
    def test_error_only_upstream_response_is_failed_and_artifact_response_is_partial(self):
        async def error_only(*args):return {'error':'fixture TLS verification failed'}
        async def partial(*args):return {'error':'capture timed out','html':'<p>owned partial</p>'}
        async def empty(*args):return {'har':{},'html':'','png':b''}
        for callback,status,count in [(error_only,'failed',0),(partial,'partial',1),(empty,'partial',3)]:
            with tempfile.TemporaryDirectory()as d,self.subTest(status=status):
                root=Path(d);folder=root/'case';folder.mkdir()
                with patch.object(guest,'WORK',root),patch.object(guest,'capture',side_effect=callback),patch.object(guest.os,'geteuid',return_value=1000),patch.object(sys,'path',list(sys.path)):
                    guest.worker('playwrightcapture','http-js','a'*32,str(folder))
                value=json.loads((folder/'result.json').read_bytes());self.assertEqual(value['status'],status)
                self.assertEqual(len(value['artifact_inventory']),count)
    def test_collected_unit_status_one_requires_missing_unit_and_empty_cgroup(self):
        with tempfile.TemporaryDirectory()as d:
            group=Path(d)/'gone'
            stop=SimpleNamespace(returncode=5,stdout='')
            gone=SimpleNamespace(returncode=1,stdout='LoadState=not-found\nMainPID=0\nActiveState=inactive\n')
            with patch.object(guest.subprocess,'run',side_effect=[stop,gone]):
                self.assertEqual(guest.stop_unit('owned.service',group)['LoadState'],'not-found')
            group.mkdir();(group/'cgroup.procs').write_text('12345\n')
            with patch.object(guest.subprocess,'run',side_effect=[stop,gone]),self.assertRaises(ValueError):guest.stop_unit('owned.service',group)
            missing=SimpleNamespace(returncode=1,stdout='')
            with patch.object(guest.subprocess,'run',side_effect=[stop,missing]),self.assertRaises(ValueError):guest.stop_unit('owned.service',group)
    def test_renderer_sampling_tolerates_collection_but_not_unknown_read_errors(self):
        spec=importlib.util.spec_from_file_location('actual_renderer_witness',ROOT/'lab/s14/browser_sandbox.py')
        witness_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(witness_module)
        with tempfile.TemporaryDirectory()as d:
            group=Path(d)/'collected.service';group.mkdir();(group/'cgroup.procs').write_text('')
            self.assertTrue(group.exists());(group/'cgroup.procs').unlink();group.rmdir()
            witness=witness_module.RendererWitness()
            guest.observe_renderer(witness,group)
            self.assertFalse(witness.flags()['renderer_seen'])
            with patch.object(witness,'observe',side_effect=PermissionError('unknown read')),self.assertRaises(PermissionError):
                guest.observe_renderer(witness,group)
            with patch.object(witness,'observe',side_effect=ValueError('invalid PID')),self.assertRaises(ValueError):
                guest.observe_renderer(witness,group)
    def test_fixed_fixtures_exercise_JS_resource_redirect_and_never_accept_real_target(self):
        n='a'*32;status,_,body=guest.fixture(n,'/')
        self.assertEqual(status,200);self.assertIn(b"fetch('/owned-data')",body)
        self.assertEqual(guest.fixture(n,'/owned-data')[2],('PAW-OWNED-'+n).encode())
        self.assertEqual(guest.fixture(n,'/redirect')[:2],(302,{'Location':'/'}))
        for c in ['https://example.invalid/','../x','http-js?url=arbitrary']:
            with self.assertRaises(ValueError):guest.url(c)
        for c in guest.CASES:self.assertIn('127.0.0.1',guest.url(c))
    def test_host_qemu_has_no_NIC_host_share_or_network_monitor(self):
        args=run.command(Path('/owned/overlay'),Path('/owned/input.iso'))
        self.assertEqual(args[args.index('-nic')+1],'none');self.assertEqual(args[args.index('-monitor')+1],'none')
        self.assertFalse(any(v in args for v in ['-netdev','-virtfs','-fsdev','-vnc','-spice','-daemonize']))
        self.assertIn('readonly=on',args[-1]);self.assertIn('spawn=deny',args[args.index('-sandbox')+1])
if __name__=='__main__':unittest.main()
