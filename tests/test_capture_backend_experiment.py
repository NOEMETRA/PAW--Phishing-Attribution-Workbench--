"""Ordinary inert boundary checks; no QEMU, imports of capture libraries or sockets."""
import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'experiments/capture_backends'/(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
run=module('run_vm');guest=module('guest')
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
            receiver=run.Receiver(n,Path(d));receiver.feed({'event':'done','nonce':n,
                'schema':'paw-capture-backend-experiment-v1','network_interfaces':['lo'],
                'production_acceptance':False,'real_connections':0,'guest_writers_stopped':True,
                'runs':[{'mode':m,'case':c}for m in guest.MODES for c in guest.CASES]})
            with self.assertRaises(ValueError):receiver.feed({'event':'file','nonce':n,'seq':0,
                'name':'playwrightcapture-http-js/dom.html','bytes':0,'sha256':hashlib.sha256(b'').hexdigest()})
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
