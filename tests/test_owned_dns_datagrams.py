"""Owned UDP loopback transport; fixed resolver patched only in this test.

No OS resolver, sample hostname, public resolver or actual public peer is used.
The returned public-looking A record is inert data, never connected to here.
"""
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

from paw.core import mail_browser_dns as dns


class OwnedDatagrams(unittest.TestCase):
    def probe(self,*,address='93.184.216.34',wrong_id=False,truncated=False):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server.bind(('127.0.0.1',0));server.settimeout(2);endpoint=server.getsockname();seen=[];fail=[]
        def fixture():
            try:
                wire,peer=server.recvfrom(513);seen.append(wire)
                ident,flags,qd,an,ns,ar=struct.unpack('!6H',wire[:12])
                if (flags,qd,an,ns,ar)!=(0x100,1,0,0,0):raise ValueError('owned question shape')
                flags=0x8180| (0x0200 if truncated else 0)
                answer=struct.pack('!6H',(ident+1)%65536 if wrong_id else ident,flags,1,1,0,0)+wire[12:]
                answer+=b'\xc0\x0c'+struct.pack('!2HIH',1,1,30,4)+socket.inet_aton(address)
                server.sendto(answer,peer)
            except Exception as error:fail.append(type(error).__name__)
            finally:server.close()
        thread=threading.Thread(target=fixture,daemon=True);thread.start()
        try:
            with patch.object(dns,'RESOLVER',endpoint):
                try:result=dns.resolve_a('paw-owned.invalid',time.monotonic_ns()+2*10**9)
                except Exception as error:result=error
        finally:thread.join(timeout=3);server.close()
        self.assertFalse(thread.is_alive());self.assertEqual(fail,[]);self.assertEqual(len(seen),1)
        self.assertIn(b'\x09paw-owned\x07invalid\0',seen[0])
        return result

    def test_one_real_connected_udp_exchange_binds_question_transaction_and_ttl(self):
        before=time.monotonic_ns();result=self.probe();after=time.monotonic_ns()
        self.assertEqual(result['answers'],['93.184.216.34']);self.assertEqual(result['ttl_ns'],30*10**9)
        self.assertTrue(before<=result['observed_ns']<=after)
        self.assertEqual(result['canonical_name'],'paw-owned.invalid')
        self.assertIn('not established',result['dnssec'])

    def test_wrong_transaction_and_truncation_refuse_without_retry_or_fallback(self):
        for options in [{'wrong_id':True},{'truncated':True}]:
            with self.subTest(options=options):self.assertIsInstance(self.probe(**options),ValueError)

    def test_real_datagram_private_and_metadata_answers_stay_refused(self):
        for address in ['127.0.0.1','169.254.169.254','192.168.1.1']:
            with self.subTest(address=address):self.assertIsInstance(self.probe(address=address),ValueError)

if __name__=='__main__':unittest.main()

