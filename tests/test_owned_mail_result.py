"""Fixed-owned receipt/stream integration with inert guest, never a VM or Root."""
import copy,hashlib,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from paw.core import owned_mail_channel as c,mail_browser_owned as m
from paw.core import browser_owned_broker as broker,browser_owned_broker_guest as guest,browser_cdp as cdp
from test_mail_browser_owned import owned_case
from test_owned_capture_controller import PNG

class Result(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        raw=Path(m.prepare(owned_case(self.root),self.root/'request')['request']).read_bytes();request=m.validate_request(raw)
        self.admission={'request':request,'raw':raw,'request_sha256':m.digest(raw),'job':'a'*32,
            'nonce':'b'*32,'release_sha':'c'*40,'admitted_at':request['created_at']}
        self.context={'context_sha256':'d'*64,'image_sha256':'e'*64,'chrome_binary_sha256':'f'*64}
        self.artifacts={'dom.html':b'<p data-owned="done">PAW-OWNED-'+b'1'*32+b'</p>','screenshot.png':PNG}
        self.a={'schema':'paw-owned-brokered-browser-v1','job':'a'*32,'release_sha':'c'*40,'fixture_nonce':'1'*32,
            'context_sha256':'d'*64,'writers_stopped':True,'host_restored':True,'real_connections':0,
            'real_samples_executed':0,'result':'PASS','vm_uuid':str(uuid.uuid4()),'stop_ns':12345,
            'guest':{'status':'completed','writers_stopped':True,'network_interfaces':['lo'],
                'dom_sha256':m.digest(self.artifacts['dom.html']),'sandbox':{k:True for k in m.SANDBOX}},
            'capture_artifacts':[{'name':n,'bytes':len(raw),'sha256':m.digest(raw)}for n,raw in self.artifacts.items()],
            'observations':[{'operation':'http','scope':'separate plain HTTP transport probe'}]}
    def test_bound_actual_bytes_raw_attestation_and_separate_network_coverage(self):
        raw=cdp.canonical(self.a);receipt,bodies=c.bound_result(self.admission,raw,self.context,self.artifacts)
        self.assertEqual(receipt['status'],'completed');self.assertEqual(receipt['runtime']['raw_attestation_sha256'],m.digest(raw))
        self.assertEqual(bodies['dom.html'],self.artifacts['dom.html']);self.assertEqual(bodies['screenshot.png'],PNG)
        network=m.decode(bodies['network.json'],m.ARTIFACTS['network.json'])
        self.assertIn('not complete browser HAR',network['scope']);self.assertIn('not browser',network['tls_verifier'])
    def test_missing_artifact_hash_job_nonce_release_context_or_stop_cannot_complete(self):
        changes=[{'job':'2'*32},{'release_sha':'2'*40},{'context_sha256':'2'*64},{'fixture_nonce':'2'*32},
            {'writers_stopped':False},{'host_restored':False},{'real_connections':True},
            {'stop_ns':12*10**9},{'capture_artifacts':[]},{'cleanup_errors':['unknown']},
            {'guest':{**self.a['guest'],'sandbox':{k:False for k in m.SANDBOX}}}]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):
                c.bound_result(self.admission,cdp.canonical({**self.a,**change}),self.context,self.artifacts)
        with self.assertRaises(ValueError):c.bound_result(self.admission,cdp.canonical(self.a),self.context,{**self.artifacts,'dom.html':b'changed'})
    def test_known_stopped_partial_is_failed_and_preserves_missing_inventory(self):
        a={**self.a,'result':'FAIL','guest':{'missing_coverage':['dom.html','screenshot.png']},'capture_artifacts':[]}
        receipt,bodies=c.bound_result(self.admission,cdp.canonical(a),self.context,{})
        self.assertEqual(receipt['status'],'failed');self.assertEqual(set(bodies),{'network.json'})
        self.assertFalse(any(receipt['runtime']['sandbox'].values()))
    def test_full_binary_transfer_through_supervisor_and_final_digest_binding(self):
        parts={'dom.html':b'd'*256*1024,'screenshot.png':bytes(range(256))*1024};transfer=guest.Transfer('1'*32,parts,True)
        calls=[]
        class Channel:
            def call(inner,op,**kw):
                calls.append(op);return transfer.read(kw['value'])
        items=broker.collect_capture(Channel(),'1'*32,{'writers_stopped':True,'capture_artifacts':transfer.manifest},self.root)
        for item in items:self.assertEqual((self.root/('capture-'+item['name'])).read_bytes(),parts[item['name']])
        self.assertEqual(calls,['artifact']*18);self.assertTrue(transfer.closed)
    def test_live_missing_or_corrupted_transfer_never_commits_an_artifact(self):
        for terminal in [{'writers_stopped':False,'capture_artifacts':[]},{'writers_stopped':True,'capture_artifacts':None}]:
            with self.assertRaises(ValueError):broker.collect_capture(None,'1'*32,terminal,self.root)
        transfer=guest.Transfer('1'*32,{'dom.html':b'owned'},True)
        class Channel:
            def call(inner,op,**kw):
                reply=transfer.read(kw['value']);reply['name']='screenshot.png';return reply
        with self.assertRaises(ValueError):broker.collect_capture(Channel(),'1'*32,{'writers_stopped':True,'capture_artifacts':transfer.manifest},self.root)
        self.assertFalse((self.root/'capture-dom.html').exists())
    def test_protected_publisher_binds_exact_private_request_marker_attestation_and_bytes(self):
        from contextlib import contextmanager
        import os,sys,types,json
        state=self.root/'state';exports=self.root/'exports';control=self.root/'control'
        job=self.admission['job'];rid=self.admission['request']['request_id'];nonce=self.a['fixture_nonce']
        (state/'jobs'/job).mkdir(parents=True);(state/'owned-mail-used').mkdir();exports.mkdir();control.mkdir()
        (state/'jobs'/job/'owned-mail-request.json').write_bytes(self.admission['raw'])
        (state/'owned-mail-used'/rid).write_bytes(m.canonical({'schema':'paw-fixed-owned-mail-consumed-v1',
            'job':job,'nonce':self.admission['nonce'],'request_sha256':self.admission['request_sha256'],
            'admitted_at':self.admission['admitted_at'],
            'authorization_basis':'compiled harmless source and fixed owned URL only'}))
        context={k:self.context[k]for k in ['image_sha256','chrome_binary_sha256']}
        a={**self.a,'context_sha256':m.digest(cdp.canonical(context))}
        producer=exports/('owned-broker-'+job);producer.mkdir();raw=cdp.canonical(a);(producer/'attestation.json').write_bytes(raw)
        private=control/('owned-broker-'+nonce);private.mkdir()
        for name,body in self.artifacts.items():(private/('capture-'+name)).write_bytes(body)
        @contextmanager
        def trusted(path):
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            try:yield fd
            finally:os.close(fd)
        def mapped(path):
            path=Path(path)
            for before,after in [(Path('/var/lib/paw-vm'),state),(Path('/var/lib/paw-vm-exports'),exports),
                                 (Path('/var/lib/paw-s14/control'),control)]:
                if path==before or path.is_relative_to(before):return after/path.relative_to(before)
            return path
        published=[];read=m.shared._read_regular
        modules={'browser_authorization':types.SimpleNamespace(capture=lambda:context,validate_context=lambda _:None,canonical=cdp.canonical),
                 'reader_export':types.SimpleNamespace(publish_reader_tree=published.append)}
        with patch.object(c,'_root',return_value=trusted),patch.object(c,'Path',side_effect=mapped),patch.dict(sys.modules,modules), \
             patch.object(m.shared,'_read_regular',side_effect=lambda *a,**k:read(*a,**{**k,'root_owned':False})):
            answer=c.publish(self.admission)
            self.assertEqual(answer['status'],'completed');self.assertEqual(len(published),1)
            exported=exports/('mail-browser-owned-'+rid);receipt=json.loads((exported/'receipt.json').read_bytes())
            self.assertEqual(receipt['runtime']['raw_attestation_sha256'],m.digest(raw))
            self.assertEqual(set(p.name for p in exported.iterdir()),{'request.json','receipt.json',*m.ARTIFACTS})
            with self.assertRaises(FileExistsError):c.publish(self.admission)

    def test_guest_commits_only_after_known_stop_and_cancel_can_transfer_without_restart(self):
        runtime=guest.Runtime();self.addCleanup(runtime.selector.close);runtime.nonce='1'*32
        runtime.process=object();runtime.driver=type('Driver',(),{'dom':b'owned','png':PNG})()
        stopped={'done':True,'writers_stopped':True,'status':'cancelled'}
        def finish(*args):runtime.done=stopped;return stopped
        with patch.object(guest.fixed.Runtime,'finish',side_effect=finish):
            session=guest.ConsoleSession(runtime)
            reply=session.command(cdp.canonical({'id':1,'op':'cancel'}));self.assertTrue(reply['data']['writers_stopped'])
            reply=session.command(cdp.canonical({'id':2,'op':'artifact','value':{'name':'dom.html','chunk':0}}))
            self.assertEqual(reply['data']['name'],'dom.html')
            with self.assertRaises(ValueError):session.command(cdp.canonical({'id':3,'op':'start'}))
        self.assertTrue(session.closed)

if __name__=='__main__':unittest.main()
