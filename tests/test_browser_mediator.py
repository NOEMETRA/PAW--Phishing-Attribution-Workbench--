import base64
import copy
import hashlib
import os
import socket
import ssl
import tempfile
from pathlib import Path
import time
import unittest
from unittest.mock import patch
from paw.core import browser_mediator as b

START=10**12
NS='a'*32
URL='https://owned.invalid/path?token=opaque%2Fowned'

def ledger(dynamic=False):return b.BrowserRequestLedger(URL,NS,START,allow_dynamic_public_hosts=dynamic)
def frame(seq=0,url=URL,method='GET',resource='Document'):
    return {'nonce':NS,'seq':seq,'url':url,'method':method,'resource':resource}
def admit(l,f=None,answers=None,now=START):
    return l.admit(frame() if f is None else f,['93.184.216.34'] if answers is None else answers,0,30*10**9,now)
def complete(l,p,body=b'owned',headers=None,code=200,now=START+1):
    return l.complete(p,code,[['Content-Type','text/html'],['Content-Length',str(len(body))]] if headers is None else headers,body,p['peer_ipv4'],p['scheme']=='https',now)

class Ledger(unittest.TestCase):
    def test_data_only_positive_roundtrip_and_no_network(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network')),patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS')):
            l=ledger();p=admit(l);r=complete(l,p)
        self.assertEqual(base64.b64decode(r['body_b64']),b'owned')
        self.assertEqual(r['body_sha256'],hashlib.sha256(b'owned').hexdigest())
        self.assertEqual(r['tls_fingerprint_source'],'broker, not browser')
        self.assertEqual(l.close()['network_stopped'],'not established by this inert ledger')

    def test_initial_refusal_cannot_skip_exact_seed(self):
        l=ledger(True)
        with self.assertRaisesRegex(ValueError,'initial_seed'):admit(l,frame(url='https://other.invalid/'))
        with self.assertRaisesRegex(ValueError,'initial_seed'):admit(l,frame(seq=1,url='https://other.invalid/'))
        self.assertEqual(admit(l,frame(seq=2))['url'],URL)

    def test_consumed_sequence_pending_replay_and_forged_plan(self):
        l=ledger();p=admit(l)
        with self.assertRaisesRegex(ValueError,'pending'):admit(l,frame(seq=1))
        forged={**p,'peer_ipv4':'127.0.0.1'}
        with self.assertRaisesRegex(ValueError,'forged'):complete(l,forged)
        complete(l,p)
        with self.assertRaisesRegex(ValueError,'identity'):admit(l,frame())
        with self.assertRaisesRegex(ValueError,'forged'):complete(l,p)

    def test_page_cannot_select_methods_or_code_arguments(self):
        for method in ['POST','PUT','DELETE','CONNECT','OPTIONS',[],True]:
            l=ledger();p=admit(l);complete(l,p)
            with self.subTest(method=method),self.assertRaises(ValueError):admit(l,frame(seq=1,method=method))
            self.assertEqual(l.used,2)
        f=frame();f['command']='/bin/sh'
        with self.assertRaises(ValueError):admit(ledger(),f)

    def test_mixed_special_ipv6_noncanonical_and_rebound_dns_refuse(self):
        for answers in [[],['93.184.216.34','127.0.0.1'],['169.254.169.254'],['192.168.1.1'],
                        ['198.18.43.10'],['::ffff:93.184.216.34'],['93.184.216.034'],['93.184.216.34']*2]:
            with self.subTest(answers=answers),self.assertRaises(ValueError):admit(ledger(),answers=answers)
        l=ledger();p=admit(l);complete(l,p)
        with self.assertRaisesRegex(ValueError,'rebinding'):admit(l,frame(seq=1),['8.8.8.8'])

    def test_exact_lease_deadline_and_age_do_not_regain_time(self):
        l=ledger();p=admit(l)
        with self.assertRaisesRegex(ValueError,'expired'):l.lease(p,p['expires_ns'])
        for age,ttl,now in [(10*10**9,30*10**9,START),(True,30*10**9,START),
                            (0,True,START),(0,30*10**9,START+15*10**9),(0,30*10**9,START-1)]:
            with self.subTest(age=age,ttl=ttl,now=now),self.assertRaises(ValueError):ledger().admit(frame(),['93.184.216.34'],age,ttl,now)

    def test_dynamic_host_discovery_is_explicit_and_bounded(self):
        l=ledger();p=admit(l);complete(l,p)
        with self.assertRaisesRegex(ValueError,'unregistered'):admit(l,frame(seq=1,url='https://other.invalid/a'))
        l=ledger(True);p=admit(l);complete(l,p)
        for i in range(1,8):p=admit(l,frame(seq=i,url=f'https://owned{i}.invalid/a'));complete(l,p)
        with self.assertRaisesRegex(ValueError,'host_budget'):admit(l,frame(seq=8,url='https://ninth.invalid/a'))

    def test_32_requests_is_finite_even_when_refused(self):
        l=ledger();p=admit(l);complete(l,p)
        for i in range(1,32):
            with self.assertRaises(ValueError):admit(l,frame(seq=i,method='POST'))
        with self.assertRaisesRegex(ValueError,'request_budget'):admit(l,frame(seq=32))

    def test_failed_response_bytes_still_exhaust_aggregate(self):
        l=ledger();p=admit(l)
        with self.assertRaisesRegex(ValueError,'http_status'):complete(l,p,body=b'x'*(4*1024**2),code=101)
        self.assertEqual(l.received,4*1024**2);p=admit(l,frame(seq=1))
        with self.assertRaisesRegex(ValueError,'response_budget'):complete(l,p,body=b'x')

    def test_response_crlf_length_encoding_and_ambiguity_refuse(self):
        for headers in [[['X-Test','bad\r\nInjected:x']], [['Content-Length','1'],['Content-Length','1']],
                        [['Content-Encoding','gzip']], [['Location','/a'],['Location','/b']],
                        [['Content-Length','6']], [['X-Test','x'*8193]]]:
            l=ledger();p=admit(l)
            with self.subTest(headers=headers),self.assertRaises(ValueError):complete(l,p,headers=headers)
            self.assertEqual(l.received,5)

    def test_form_csp_cookies_auth_and_hop_headers(self):
        l=ledger();p=admit(l);r=complete(l,p,headers=[['Set-Cookie','secret=bad'],['WWW-Authenticate','Basic'],
            ['Connection','close'],['Content-Type','text/html'],['Content-Security-Policy',"script-src 'self'"]])
        names=[x['name'].lower() for x in r['headers']]
        self.assertNotIn('set-cookie',names);self.assertNotIn('www-authenticate',names);self.assertNotIn('connection',names)
        self.assertEqual(names.count('content-security-policy'),2)
        self.assertTrue(any("form-action 'none'" in x['value'] for x in r['headers']))
        r=b.response_headers([['X-Private','drop'],['Connection','X-Private']])[0]
        self.assertNotIn('x-private',[x['name'].lower() for x in r])
        with self.assertRaises(ValueError):b.response_headers([['Connection','Content-Security-Policy']])

    def test_redirect_is_metadata_only_and_has_global_hard_ceiling(self):
        l=ledger()
        for i in range(5):p=admit(l,frame(seq=i));complete(l,p,body=b'',headers=[['Location','/next']],code=302)
        p=admit(l,frame(seq=5))
        with self.assertRaisesRegex(ValueError,'redirect_budget'):complete(l,p,body=b'',headers=[['Location','/next']],code=302)

    def test_plain_http_never_claims_tls_and_wrong_peer_refuses(self):
        url='http://owned.invalid/a';l=b.BrowserRequestLedger(url,NS,START);p=admit(l,frame(url=url));r=complete(l,p)
        self.assertIs(r['tls_verified_by_broker'],False)
        l=ledger();p=admit(l)
        with self.assertRaisesRegex(ValueError,'peer_or_tls'):l.complete(p,200,[],b'','127.0.0.1',True,START+1)

    def test_close_and_failed_connection_do_not_restore_quota(self):
        l=ledger();p=admit(l);r=l.fail(p,'timeout',p['expires_ns']+1)
        self.assertEqual(r['reason'],'timeout');self.assertEqual(l.used,1)
        l.close()
        with self.assertRaisesRegex(ValueError,'closed'):admit(l,frame(seq=1))


class Wire(unittest.TestCase):
    def decode(self,wire,method='GET',remaining=4096):
        # An actual local TCP pair exercises stream fragmentation and EOF. This
        # is an owned parser fixture, not proof of public pin/kernel isolation.
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        listener.bind(('127.0.0.1',0));listener.listen(1)
        client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            client.connect(listener.getsockname());server,_=listener.accept()
            with server:
                server.sendall(wire);server.shutdown(socket.SHUT_WR)
                return b.read_http_response(client,method,remaining,time.monotonic_ns()+2*10**9)
        finally:client.close();listener.close()

    def test_actual_loopback_fixed_chunked_and_close_delimited(self):
        cases=[(b'Content-Length: 5\r\n',b'owned'),
               (b'Transfer-Encoding: chunked\r\n',b'2\r\now\r\n3\r\nned\r\n0\r\n\r\n'),
               (b'',b'owned')]
        for headers,payload in cases:
            with self.subTest(headers=headers):
                code,rows,body=self.decode(b'HTTP/1.1 200 OK\r\n'+headers+b'\r\n'+payload)
                self.assertEqual(code,200);self.assertEqual(body,b'owned')

    def test_ambiguous_unsupported_truncated_or_oversized_wire_refuses(self):
        for wire in [b'HTTP/1.1 101 Switching Protocols\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nowned',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\now',
                     b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\n bad: folded\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=x\r\na\r\n0\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: x\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nX-Test: '+b'x'*8192+b'\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n',
                     b'HTTP/1.1 200 OK\r\n\r\n'+b'x'*4097]:
            with self.subTest(prefix=wire[:100]),self.assertRaises(ValueError):self.decode(wire)

    def test_head_and_bodyless_response_do_not_invent_body(self):
        self.assertEqual(self.decode(b'HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n','HEAD')[2],b'')
        self.assertEqual(self.decode(b'HTTP/1.1 204 No Content\r\n\r\n')[2],b'')

    def test_absolute_deadline_stops_slow_headers(self):
        client,server=socket.socketpair()
        try:
            server.sendall(b'HTTP/1.1 200 OK\r\nX')
            started=time.monotonic()
            with self.assertRaises((TimeoutError,ValueError)):
                b.read_http_response(client,'GET',4096,time.monotonic_ns()+50_000_000)
            self.assertLess(time.monotonic()-started,0.8)
        finally:client.close();server.close()

    def test_transport_has_no_dns_proxy_or_page_headers_and_does_not_follow_redirects(self):
        class Stream:
            def __init__(self):self.wire=bytearray(b'HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /next\r\n\r\n');self.sent=b'';self.closed=False
            def settimeout(self,value):self.timeout=value
            def connect(self,address):self.address=address
            def getpeername(self):return ('93.184.216.34',80)
            def sendall(self,data):self.sent+=data
            def recv(self,count):v=bytes(self.wire[:count]);del self.wire[:count];return v
            def close(self):self.closed=True
        stream=Stream();url='http://owned.invalid/?opaque=%2Fowned'
        l=b.BrowserRequestLedger(url,NS,time.monotonic_ns());p=admit(l,frame(url=url),now=time.monotonic_ns())
        with patch.object(socket,'socket',return_value=stream) as create,patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS')):
            r=b.exchange(l,p)
        create.assert_called_once_with(socket.AF_INET,socket.SOCK_STREAM)
        self.assertEqual(stream.address,('93.184.216.34',80));self.assertTrue(stream.closed)
        self.assertIn(b'GET /?opaque=%2Fowned HTTP/1.1\r\n',stream.sent)
        self.assertNotIn(b'Cookie:',stream.sent);self.assertNotIn(b'Authorization:',stream.sent)
        self.assertEqual(r['http_status'],302);self.assertFalse(r['tls_verified_by_broker']);self.assertEqual(l.used,1)

    def test_bad_peer_and_tls_certificate_failure_close_and_exhaust_session(self):
        for failure in ['peer','tls']:
            l=b.BrowserRequestLedger(URL,NS,time.monotonic_ns());p=admit(l,now=time.monotonic_ns())
            from unittest.mock import MagicMock
            stream=MagicMock();stream.getpeername.return_value=('127.0.0.1' if failure=='peer' else p['peer_ipv4'],443)
            context=MagicMock();context.wrap_socket.side_effect=ssl.SSLCertVerificationError('owned invalid certificate')
            with patch.object(socket,'socket',return_value=stream),patch.object(ssl,'SSLContext',return_value=context):
                with self.assertRaises((ValueError,ssl.SSLError)):b.exchange(l,p)
            stream.sendall.assert_not_called();stream.close.assert_called_once()
            self.assertTrue(l.closed);self.assertEqual(l.received,b.LIMITS['bytes']);self.assertIsNone(l._pending)
            if failure=='tls':context.wrap_socket.assert_called_once_with(stream,server_hostname='owned.invalid')

    def test_tls_ignores_caller_ca_and_keylog_environment(self):
        # Actual stdlib context construction, no TLS connection or certificate
        # exchange. Capture it at the wrap boundary after fixed trust loading.
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'empty.pem').write_bytes(b'');(root/'certs').mkdir()
            env={'SSL_CERT_FILE':str(root/'empty.pem'),'SSL_CERT_DIR':str(root/'certs'),
                 'SSLKEYLOGFILE':str(root/'keylog')}
            contexts=[]
            def stop_at_wrap(context,*args,**kwargs):
                contexts.append(context);raise ssl.SSLError('owned capture, no connection')
            l=b.BrowserRequestLedger(URL,NS,time.monotonic_ns());p=admit(l,now=time.monotonic_ns())
            stream=MagicMock();stream.getpeername.return_value=(p['peer_ipv4'],443)
            with patch.dict(os.environ,env),patch.object(socket,'socket',return_value=stream), \
                 patch.object(ssl.SSLContext,'wrap_socket',stop_at_wrap):
                with self.assertRaises(ssl.SSLError):b.exchange(l,p)
            context,=contexts
            self.assertGreater(context.cert_store_stats()['x509_ca'],0)
            self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED);self.assertTrue(context.check_hostname)
            self.assertGreaterEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
            self.assertIsNone(context.keylog_filename);self.assertFalse((root/'keylog').exists())


if __name__=='__main__':unittest.main()
