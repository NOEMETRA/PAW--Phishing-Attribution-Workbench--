"""Actual owned TLS bytes -> private wire -> ledger -> typed guest assembler.

Numeric route/CA path are explicit loopback simulations. No Root/VM/network gate,
real DNS, browser, public target or custody claim is established by this test.
"""
import hashlib,importlib.util,pathlib,time,unittest
from unittest.mock import patch
from paw.core import browser_broker_wire as wire
from paw.core import browser_cdp as cdp
from paw.core import browser_owned_protocol as broker
from paw.core import browser_owned_broker_guest as guest
from paw.core import browser_broker_console as channel

D=pathlib.Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v

from paw.core import browser_mediator as m
tls=module('actual_owned_tls',D/'test_broker_owned_tls.py')

class Chain(unittest.TestCase):
    def test_actual_owned_tls_binary_wire_accounted_and_filtered_before_guest(self):
        fixture=tls.OwnedTLS();fixture.setUp();self.addCleanup(fixture.tearDown)
        nonce='a'*32;ledger=m.BrowserRequestLedger('https://paw-owned.invalid/',nonce,time.monotonic_ns())
        request={'nonce':nonce,'seq':0,'url':ledger.seed['url'],'method':'GET','resource':'Document'}
        plan=ledger.admit(request,['93.184.216.34'],0,5*10**9,time.monotonic_ns())
        worker=broker.OwnedTransport(nonce,time.monotonic_ns()+8*10**9,
            lambda *_:self.fail('DNS not used in this TLS seam'),m.transport_response)
        with patch.object(m.socket,'socket',side_effect=fixture.transport),patch.object(m,'TRUST_FILE',str(fixture.cert)):
            fields,body=worker.dispatch(nonce,0,'http',{'plan':plan,'remaining_bytes':m.LIMITS['bytes']})
        decoder=wire.Decoder(nonce);encoded=wire.frame(nonce,0,'reply',fields,body);rows=[]
        for offset in range(0,len(encoded),23):rows+=decoder.feed(encoded[offset:offset+23])
        decoder.eof();header,received=rows[0];facts=header['fields']['transport']
        metadata=ledger.complete(plan,facts['http_status'],facts['headers'],received,facts['peer_ipv4'],
            facts['tls_verified_by_broker'],time.monotonic_ns())
        self.assertTrue(metadata['tls_verified_by_broker']);self.assertEqual(metadata['tls_fingerprint_source'],'broker, not browser')
        self.assertEqual(ledger.received,10);self.assertEqual(received,b'owned-data')
        runtime=guest.Runtime();self.addCleanup(runtime.selector.close)
        class Driver:
            stage='running'
            def response(self,meta,raw):self.result=(meta,raw)
        runtime.driver=Driver();runtime.nonce=nonce;runtime.started=time.monotonic();runtime._request(request)
        allowed={k:metadata[k]for k in ['status','slot','http_status','headers','body_bytes','body_sha256']}
        raw=cdp.canonical(allowed);session=guest.ConsoleSession(runtime);identifier=1
        session.command(channel.encode(identifier,{'kind':'begin','nonce':nonce,'seq':0,
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
        for section,payload in [('metadata',raw),('body',received)]:
            for row in cdp.response_chunks(nonce,0,payload):
                identifier+=1
                session.command(channel.encode(identifier,{'kind':'part','nonce':nonce,'seq':0,'section':section,'row':row}))
        self.assertEqual(runtime.driver.result,(allowed,b'owned-data'))
        self.assertEqual(runtime.network_bytes,10);self.assertIsNone(runtime.network_pending)
        self.assertTrue(any(v['name']=='Content-Security-Policy'for v in allowed['headers']))
        fixture.thread.join(timeout=2);self.assertEqual(len(fixture.requests),1)
        self.assertNotIn(b'Cookie:',fixture.requests[0]);self.assertNotIn(b'Authorization:',fixture.requests[0])

if __name__=='__main__':unittest.main()
