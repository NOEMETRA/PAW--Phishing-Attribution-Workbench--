import base64
import hashlib
import json
import unittest
from paw.core import browser_cdp as c

N='a'*32

def event(method='GET'):
    return {'method':'Fetch.requestPaused','sessionId':'SESSION1','params':{
        'requestId':'INTERCEPT1','resourceType':'Document','request':{'url':'https://owned.invalid/',
        'method':method,'headers':{'Cookie':'DO NOT FORWARD'},'postData':'DO NOT FORWARD'}}}

class Protocol(unittest.TestCase):
    def test_nul_delimited_chrome_pipe_handles_fragmentation(self):
        decoder=c.PipeDecoder();first={'id':1,'result':{}};second={'method':'owned.event','params':{}}
        wire=c.canonical(first)+b'\0'+c.canonical(second)+b'\0';rows=[]
        for i in range(0,len(wire),3):rows.extend(decoder.feed(wire[i:i+3]))
        self.assertEqual(rows,[first,second]);decoder.eof()
    def test_duplicate_nonfinite_nonobject_and_empty_json_poison_stream(self):
        for raw in [b'{"id":1,"id":2}\0',b'{"x":NaN}\0',b'[]\0',b'\0',b'{bad}\0']:
            d=c.PipeDecoder()
            with self.subTest(raw=raw),self.assertRaises(ValueError):d.feed(raw)
            with self.assertRaises(ValueError):d.feed(b'{}\0')
    def test_partial_or_flooded_stream_is_finite(self):
        d=c.PipeDecoder();d.feed(b'{')
        with self.assertRaises(ValueError):d.eof()
        d=c.PipeDecoder()
        with self.assertRaises(ValueError):
            for _ in range(13):d.feed(b'x'*32768)
        d=c.PipeDecoder()
        with self.assertRaises(ValueError):
            for _ in range(c.MAX_EVENTS+1):d.feed(b'{}\0')
    def test_full_four_mib_serial_body_roundtrip_stays_below_line_cap(self):
        body=b'owned!'*(4*1024**2//6);rows=c.response_chunks(N,0,body);a=c.ResponseAssembler(N,0,c.MAX_BODY)
        self.assertTrue(all(len(c.canonical(x))<60000 for x in rows))
        for row in rows[:-1]:self.assertIsNone(a.feed(row))
        self.assertEqual(a.feed(rows[-1]),body)
        with self.assertRaises(ValueError):a.feed(rows[-1])
    def test_empty_body_finishes_without_invented_chunk(self):
        rows=c.response_chunks(N,2,b'');self.assertEqual(len(rows),1)
        self.assertEqual(c.ResponseAssembler(N,2,0).feed(rows[0]),b'')
    def test_wrong_nonce_sequence_order_bytes_or_digest_poison_transfer(self):
        rows=c.response_chunks(N,0,b'owned')
        changes=[{'nonce':'b'*32},{'seq':True},{'seq':1},{'chunk':1},
                 {'data_b64':'!!!'},{'data_b64':base64.b64encode(b'longer').decode()}]
        for change in changes:
            a=c.ResponseAssembler(N,0,5)
            with self.subTest(change=change),self.assertRaises(ValueError):a.feed({**rows[0],**change})
            self.assertTrue(a.closed)
        a=c.ResponseAssembler(N,0,5);a.feed(rows[0])
        with self.assertRaises(ValueError):a.feed({**rows[-1],'body_sha256':'0'*64})
    def test_page_headers_and_postdata_never_reach_rpc(self):
        t=c.FetchTranslator(N,'SESSION1');frame=t.paused(event())
        self.assertEqual(set(frame),{'nonce','seq','url','method','resource'})
        self.assertNotIn('DO NOT FORWARD',json.dumps(frame))
        refused=t.refuse();self.assertEqual(refused['method'],'Fetch.failRequest')
        self.assertEqual(refused['params']['errorReason'],'BlockedByClient')
    def test_fulfillment_binds_body_and_sequence_without_live_continue(self):
        t=c.FetchTranslator(N,'SESSION1');t.paused(event());body=b'owned'
        row={'status':'response','slot':0,'http_status':200,'headers':[{'name':'Content-Type','value':'text/html'}],
             'body_bytes':5,'body_sha256':hashlib.sha256(body).hexdigest()}
        bad={**row,'slot':1}
        with self.assertRaises(ValueError):t.fulfill(bad,body)
        cmd=t.fulfill(row,body);self.assertEqual(cmd['method'],'Fetch.fulfillRequest')
        self.assertEqual(base64.b64decode(cmd['params']['body']),body)
        self.assertEqual(c.encode_command(cmd)[-1:],b'\0')
        with self.assertRaises(ValueError):t.fulfill(row,body)
        with self.assertRaises(ValueError):t.command('Fetch.continueRequest',{})
    def test_auth_is_always_cancelled_and_request_budget_is_shared(self):
        t=c.FetchTranslator(N,'SESSION1');auth=t.auth('AUTH1')
        self.assertEqual(auth['params']['authChallengeResponse'],{'response':'CancelAuth'})
        for _ in range(32):t.paused(event('POST'));t.refuse()
        with self.assertRaises(ValueError):t.paused(event())
    def test_wrong_session_pending_or_response_stage_refuse(self):
        for changed in [{'sessionId':'OTHER'},{'method':'Runtime.consoleAPICalled'}]:
            t=c.FetchTranslator(N,'SESSION1')
            with self.assertRaises(ValueError):t.paused({**event(),**changed})
        t=c.FetchTranslator(N,'SESSION1');t.paused(event())
        with self.assertRaises(ValueError):t.paused(event())
        t=c.FetchTranslator(N,'SESSION1');e=event();e['params']['responseStatusCode']=200
        with self.assertRaises(ValueError):t.paused(e)


class Controller(unittest.TestCase):
    def boot(self):
        sent=[];rpc=[];driver=c.GuestController('https://owned.invalid/','a'*32,sent.append,rpc.append);driver.start()
        methods=[]
        while driver.stage!='running':
            command=sent[-1];methods.append(command['method']);result={}
            if command['method']=='Target.createTarget':result={'targetId':'MAIN1'}
            elif command['method']=='Target.attachToTarget':result={'sessionId':'SESSION1'}
            reply={'id':command['id'],'result':result}
            if 'sessionId' in command:reply['sessionId']=command['sessionId']
            driver.accept(reply)
        return driver,sent,rpc,methods
    def test_no_navigation_until_download_permission_and_fetch_acks(self):
        d,sent,rpc,methods=self.boot()
        self.assertLess(methods.index('Browser.setDownloadBehavior'),methods.index('Target.createTarget'))
        self.assertLess(methods.index('Fetch.enable'),methods.index('Page.enable'))
        self.assertEqual(sent[-1]['method'],'Page.navigate');self.assertEqual(rpc,[])
        self.assertFalse(any(x['method']=='Fetch.continueRequest' for x in sent))
    def test_actual_broker_reply_translation_and_separate_dom_snapshot(self):
        d,sent,rpc,_=self.boot();d.accept(event());self.assertEqual(rpc[0]['seq'],0)
        body=b'<p>owned</p>';meta={'status':'response','slot':0,'http_status':200,'headers':[],
            'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()}
        d.response(meta,body);self.assertEqual(sent[-1]['method'],'Fetch.fulfillRequest')
        d.snapshot();cmd=sent[-1]
        d.accept({'id':cmd['id'],'sessionId':'SESSION1','result':{'root':{'nodeId':1}}})
        cmd=sent[-1];self.assertEqual(cmd['method'],'DOM.getOuterHTML')
        d.accept({'id':cmd['id'],'sessionId':'SESSION1','result':{'outerHTML':'<p>owned</p>'}})
        self.assertEqual(d.dom,body);self.assertEqual(d.stage,'snapshot_ready')
        self.assertEqual(d.stop()['writers_stopped'],'not established by this controller')
    def test_child_targets_close_without_runtime_resume_and_auth_cancels(self):
        d,sent,rpc,_=self.boot()
        d.accept({'method':'Target.attachedToTarget','sessionId':'SESSION1','params':{'targetInfo':{'targetId':'WORKER1','type':'worker'},'sessionId':'WORKERSESSION','waitingForDebugger':True}})
        self.assertEqual(sent[-1]['method'],'Target.closeTarget');self.assertTrue(d.missing)
        self.assertFalse(any(x['method']=='Runtime.runIfWaitingForDebugger' for x in sent))
        d.accept({'method':'Fetch.authRequired','sessionId':'SESSION1','params':{'requestId':'AUTH1'}})
        self.assertEqual(sent[-1]['params']['authChallengeResponse'],{'response':'CancelAuth'})
    def test_snapshot_boundary_refuses_new_network_and_records_missing_coverage(self):
        d,sent,rpc,_=self.boot();d.snapshot();d.accept(event())
        self.assertEqual(sent[-1]['method'],'Fetch.failRequest');self.assertEqual(rpc,[])
        self.assertIn({'kind':'snapshot_network_cutoff'},d.missing)
    def test_pending_requests_are_serial_bounded_and_refusal_does_not_skip_slot(self):
        d,sent,rpc,_=self.boot();d.accept(event());d.accept(event())
        self.assertEqual(len(rpc),1);d.refused();self.assertEqual(len(rpc),2);self.assertEqual(rpc[1]['seq'],1)
        with self.assertRaises(ValueError):d.snapshot()
        for _ in range(30):d.accept(event())
        with self.assertRaises(ValueError):d.accept(event())
        self.assertEqual(d.stage,'failed')
    def test_unknown_reply_cdp_error_and_bad_dom_stop_instead_of_continue(self):
        for reply in [{'id':999,'result':{}},{'id':9,'sessionId':'SESSION1','error':{'message':'owned failure'}}]:
            d,sent,rpc,_=self.boot()
            with self.assertRaises(ValueError):d.accept(reply)
            self.assertEqual(d.stage,'failed')
        d,sent,rpc,_=self.boot();d.snapshot();cmd=sent[-1]
        d.accept({'id':cmd['id'],'sessionId':'SESSION1','result':{'root':{'nodeId':1}}});cmd=sent[-1]
        with self.assertRaises(ValueError):d.accept({'id':cmd['id'],'sessionId':'SESSION1','result':{'outerHTML':'x'*(256*1024+1)}})
        self.assertEqual(d.stage,'failed')

if __name__=='__main__':unittest.main()
