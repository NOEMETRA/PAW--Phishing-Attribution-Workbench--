"""Actual owned loopback TLS, with an explicitly simulated numeric route.

The test adapter maps one numeric public-looking peer to our127.0.0.1 listener.
It does NOT verify kernel pinning, namespace confinement, public DNS or egress.
No browser, sample URL or public destination is contacted.
"""
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from paw.core import browser_mediator as m


class OwnedTLS(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.root=Path(self.directory.name)
        self.cert=self.root/'owned.pem';self.key=self.root/'owned.key'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=paw-owned.invalid','-addext','subjectAltName=DNS:paw-owned.invalid',
            '-keyout',str(self.key),'-out',str(self.cert)],check=True,stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,timeout=10)
        self.real_socket=socket.socket;self.listener=self.real_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1',0));self.listener.listen(1);self.listener.settimeout(3)
        self.port=self.listener.getsockname()[1];self.requests=[];self.errors=[]
        def server():
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.cert,self.key)
            try:
                raw,_=self.listener.accept();raw.settimeout(3)
                with context.wrap_socket(raw,server_side=True) as stream:
                    request=bytearray()
                    while b'\r\n\r\n' not in request:
                        piece=stream.recv(1024)
                        if not piece:break
                        request.extend(piece)
                        if len(request)>4096:raise ValueError('owned request limit')
                    self.requests.append(bytes(request))
                    stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\nowned-data')
            except (OSError,ValueError) as error:self.errors.append(type(error).__name__)
            finally:self.listener.close()
        self.thread=threading.Thread(target=server,daemon=True);self.thread.start()

    def tearDown(self):
        self.thread.join(timeout=4);self.listener.close();self.directory.cleanup()
        self.assertFalse(self.thread.is_alive())

    def transport(self,*args,**kwargs):
        # socket.accept() constructs the already accepted local descriptor on
        # the fixture thread; do not redirect or validate that constructor as
        # if it were the broker's outbound connect operation.
        if threading.current_thread() is self.thread:
            return self.real_socket(*args,**kwargs)
        self.assertEqual(args,(socket.AF_INET,socket.SOCK_STREAM));self.assertEqual(kwargs,{})
        outer=self
        class OwnedNumericAdapter:
            def __init__(self):self.raw=outer.real_socket(*args,**kwargs)
            def __getattr__(self,name):return getattr(self.raw,name)
            def connect(self,peer):
                outer.assertEqual(peer,('93.184.216.34',443))
                self.raw.connect(('127.0.0.1',outer.port))
            def getpeername(self):return ('93.184.216.34',443)
        return OwnedNumericAdapter()

    def ledger(self,host='paw-owned.invalid'):
        ledger=m.BrowserRequestLedger('https://'+host+'/', 'a'*32,time.monotonic_ns())
        plan=ledger.admit({'nonce':'a'*32,'seq':0,'url':ledger.seed['url'],'method':'GET',
            'resource':'Document'},['93.184.216.34'],0,10**9,time.monotonic_ns())
        return ledger,plan

    def test_actual_tls_hostname_and_owned_trust_then_fixed_http_response(self):
        ledger,plan=self.ledger();keylog=self.root/'caller-keylog'
        with patch.object(m.socket,'socket',side_effect=self.transport), \
             patch.object(m,'TRUST_FILE',str(self.cert)), \
             patch.dict('os.environ',{'SSLKEYLOGFILE':str(keylog)}):
            result=m.exchange(ledger,plan)
        self.assertTrue(result['tls_verified_by_broker']);self.assertEqual(result['body_bytes'],10)
        self.assertEqual(result['tls_fingerprint_source'],'broker, not browser')
        self.assertFalse(keylog.exists());self.thread.join(timeout=2)
        self.assertEqual(len(self.requests),1)
        self.assertIn(b'Host: paw-owned.invalid\r\n',self.requests[0])
        self.assertNotIn(b'Cookie:',self.requests[0]);self.assertNotIn(b'Authorization:',self.requests[0])

    def test_actual_wrong_hostname_never_sends_http_and_exhausts_session(self):
        ledger,plan=self.ledger('other-owned.invalid')
        with patch.object(m.socket,'socket',side_effect=self.transport), \
             patch.object(m,'TRUST_FILE',str(self.cert)), self.assertRaises(ssl.SSLCertVerificationError):
            m.exchange(ledger,plan)
        self.assertTrue(ledger.closed);self.assertEqual(ledger.received,m.LIMITS['bytes'])
        self.thread.join(timeout=2);self.assertEqual(self.requests,[])

    def test_actual_untrusted_certificate_cannot_use_environment_ca_override(self):
        ledger,plan=self.ledger()
        with patch.object(m.socket,'socket',side_effect=self.transport), \
             patch.dict('os.environ',{'SSL_CERT_FILE':str(self.cert),'SSL_CERT_DIR':str(self.root)}), \
             self.assertRaises(ssl.SSLCertVerificationError):
            m.exchange(ledger,plan)
        self.assertTrue(ledger.closed);self.thread.join(timeout=2);self.assertEqual(self.requests,[])

if __name__=='__main__':unittest.main()

