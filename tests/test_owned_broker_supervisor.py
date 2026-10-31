"""Real bounded pipes and inert supervisor data; never Root/VM/network actions."""
import io,json,os,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from paw.core import browser_owned_broker as p,browser_owned_protocol as protocol
from paw.core import owned_kernel_runtime as kernel,browser_broker_wire as wire
from paw.core import browser_mediator as mediator,browser_cdp as cdp

J='a'*32;N='b'*32;R='c'*40

class Pipes(unittest.TestCase):
    def test_root_supervisor_receives_large_binary_body_after_small_ready_without_json_coercion(self):
        body=b'owned'*32768;encoded=wire.frame(N,0,'reply',{'operation':'http'},body)
        process=Mock(stdin=io.BytesIO(),stdout=io.BytesIO(b'{"ready":true,"witness":{"pid":12345}}\n'+encoded),stderr=io.BytesIO())
        registry=[]
        with patch.object(kernel,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'), \
             patch.object(kernel.os,'geteuid',return_value=0),patch.object(kernel.subprocess,'Popen',return_value=process), \
             patch.object(kernel.subprocess,'run',return_value=SimpleNamespace(returncode=0)), \
             patch.object(kernel,'unit_properties',return_value={'MainPID':'0','ActiveState':'inactive'}):
            try:
                actor=kernel.Managed(J,N,R,'probe',123,registry=registry,protocol=True)
                value=actor.receive();self.assertEqual(value['body'],body)
                self.assertEqual(value['wire']['body_sha256'],p.hashlib.sha256(body).hexdigest())
            finally:kernel.cleanup_actors(registry)
        self.assertFalse(any(t.is_alive()for t in actor.threads))

    def test_actual_blocked_private_pipe_expires_before_any_unbounded_write(self):
        read,write=os.pipe();os.set_blocking(write,False)
        try:
            while True:
                try:os.write(write,b'x'*4096)
                except BlockingIOError:break
            began=time.monotonic()
            with self.assertRaisesRegex(ValueError,'write_deadline'):p.write_private(write,b'owned',began+.04)
            self.assertLess(time.monotonic()-began,.5)
        finally:os.close(read);os.close(write)

class Endpoints(unittest.TestCase):
    def session(self):
        events=[];next_control=0;reply=[]
        def send(value):events.append(('kernel',value['op'],value.get('kind')));reply[:]=[{'accepted':True,'id':value['id']}]
        owner=SimpleNamespace(send=send,receive=lambda:reply[0])
        worker=SimpleNamespace(process=SimpleNamespace(stdin=SimpleNamespace(fileno=lambda:123)),receive=lambda _:replies.pop(0))
        replies=[];decoder=wire.Decoder(N,body_budget=0)
        def http(plan,remaining):
            metadata,body=protocol.fixed.fixture(N,{'nonce':N,'seq':plan['slot'],'url':plan['url'].replace('http://','https://'),
                'method':plan['method'],'resource':'Document'})
            return {'http_status':200,'headers':[[v['name'],v['value']]for v in metadata['headers']],
                'peer_ipv4':plan['peer_ipv4'],'tls_verified_by_broker':plan['scheme']=='https','body_bytes':len(body),
                'body_sha256':p.hashlib.sha256(body).hexdigest()},body
        dispatcher=protocol.OwnedTransport(N,time.monotonic_ns()+8*10**9,
            lambda host,ident,deadline:protocol.dns_response(protocol.dns.question(host,ident)),http)
        output=wire.Decoder(N)
        def write(fd,raw,deadline):
            self.assertEqual(fd,123)
            for header,body in decoder.feed(raw):
                events.append(('worker',header['kind']))
                fields,response=dispatcher.dispatch(N,header['sequence'],header['kind'],header['fields'],body)
                for received,payload in output.feed(wire.frame(N,header['sequence'],'reply',fields,response)):
                    replies.append({'wire':received,'body':payload})
        return p.Mediation(owner,worker,N,time.monotonic_ns()),events,write

    def test_actual_data_dispatch_and_wire_require_kernel_dns_then_tuple_before_bytes(self):
        session,events,write=self.session()
        with patch.object(p,'write_private',side_effect=write):
            metadata,body=session.response({'nonce':N,'seq':0,'url':p.SEED,'method':'GET','resource':'Document'})
        self.assertIn(b"fetch('/owned-data')",body)
        self.assertEqual(events,[('kernel','lease','dns'),('worker','dns'),('kernel','lease','https'),
            ('worker','http'),('kernel','revoke',None)])
        self.assertEqual(session.ledger.used,1);self.assertEqual(session.ledger.received,len(body))
        self.assertEqual(metadata['body_sha256'],p.hashlib.sha256(body).hexdigest())
        self.assertNotIn('body_b64',metadata);self.assertNotIn('tls_fingerprint_source',metadata)
        self.assertEqual(session.observations[-1]['tls_fingerprint_source'],'broker, not browser')

    def test_plain_http_probe_has_separate_tcp80_and_never_claims_tls(self):
        session,events,write=self.session()
        with patch.object(p,'write_private',side_effect=write):
            session.response({'nonce':N,'seq':0,'url':p.SEED,'method':'GET','resource':'Document'})
            metadata,body=session.response({'nonce':N,'seq':1,'url':'http://paw-owned.invalid/owned-data',
                'method':'GET','resource':'Fetch'})
        self.assertEqual(body,('PAW-OWNED-'+N).encode())
        self.assertEqual(events[-3:], [('kernel','lease','http'),('worker','http'),('kernel','revoke',None)])
        self.assertIs(session.observations[-1]['tls_verified_by_broker'],False)
        self.assertEqual(session.ledger.used,2)

    def test_post_wrong_seed_and_new_host_never_reach_dns_kernel_or_worker(self):
        for change in [{'method':'POST'},{'url':'https://elsewhere.invalid/'},{'nonce':'d'*32},{'seq':True}]:
            session,events,write=self.session()
            with patch.object(p,'write_private',side_effect=write),self.assertRaises(ValueError):
                session.response({'nonce':N,'seq':0,'url':p.SEED,'method':'GET','resource':'Document',**change})
            self.assertEqual(events,[]);self.assertEqual(session.ledger.used,0 if 'nonce'in change or'seq'in change else 1)

    def test_worker_protocol_loss_is_terminal_and_cannot_be_a_retryable_url_refusal(self):
        session,events,write=self.session()
        session.worker.receive=Mock(side_effect=ValueError('worker EOF'))
        with patch.object(p,'write_private',side_effect=write),self.assertRaises(ValueError):
            session.response({'nonce':N,'seq':0,'url':p.SEED,'method':'GET','resource':'Document'})
        self.assertTrue(session.ledger.closed);before=list(events)
        with self.assertRaises(ValueError):
            session.response({'nonce':N,'seq':1,'url':p.SEED,'method':'GET','resource':'Document'})
        self.assertEqual(events,before)

    def test_actual_isolated_flat_protocol_import_does_not_start_any_role(self):
        import tempfile,subprocess,sys
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            for name in p.PROGRAMS:(root/name).write_bytes(p.HERE.with_name(name).read_bytes())
            completed=subprocess.run([sys.executable,'-I','-S','-B','-c',
                'import runpy,sys;v=runpy.run_path(sys.argv[1]);assert callable(v["main"])',
                str(root/'browser_owned_protocol.py')],capture_output=True,timeout=5)
            self.assertEqual(completed.returncode,0,completed.stderr)

    def test_only_two_fixed_nonroot_roles_can_select_protocol_program(self):
        for role in ['probe','fixture']:
            unit,props,command=kernel.policy.service(J,N,R,role,123,protocol=True)
            self.assertEqual(command[4],'/opt/paw-code/browser_owned_protocol.py')
            self.assertEqual(props['RuntimeMaxSec'],'10');self.assertEqual(props['TimeoutStopSec'],'500ms')
            self.assertEqual(props['IPAddressDeny'],'any');self.assertEqual(props['RestrictAddressFamilies'],'AF_INET')
        for role,flag in [('keeper',True),('probe',1),('probe','other-program')]:
            with self.assertRaises(ValueError):kernel.policy.service(J,N,R,role,123,protocol=flag)

if __name__=='__main__':unittest.main()
