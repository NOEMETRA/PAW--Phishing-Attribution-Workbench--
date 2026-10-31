"""Actual owned OS pipes, no namespace, Root, browser or public destination."""
import json,os,threading,time,unittest
from unittest.mock import patch
from paw.core import browser_cdp as cdp
from paw.core import browser_broker_console as g

N='a'*32
class Console(unittest.TestCase):
    def value(self):
        return {'kind':'part','nonce':N,'seq':0,'section':'body',
            'row':cdp.response_chunks(N,0,b'x'*32768)[0]}

    def test_maximum_fragment_crosses_real_pipe_with_short_writes(self):
        raw=g.encode(1,self.value());self.assertGreater(len(raw),4096);self.assertLess(len(raw),60000)
        read,write=os.pipe();os.set_blocking(write,False);pieces=[]
        def reader():
            while True:
                part=os.read(read,511)
                if not part:break
                pieces.append(part)
        thread=threading.Thread(target=reader);thread.start();real_write=os.write
        try:
            with patch.object(g.os,'write',side_effect=lambda fd,data:real_write(fd,data[:137])):
                g.write_all(write,raw,time.monotonic()+2)
        finally:os.close(write);thread.join(timeout=3);os.close(read)
        self.assertFalse(thread.is_alive());self.assertEqual(b''.join(pieces),raw)
        self.assertEqual(json.loads(raw)['value'],self.value())

    def test_full_pipe_expires_without_unbounded_write(self):
        read,write=os.pipe();os.set_blocking(write,False)
        try:
            while True:
                try:os.write(write,b'x'*4096)
                except BlockingIOError:break
            start=time.monotonic()
            with self.assertRaisesRegex(ValueError,'deadline'):g.write_all(write,b'owned',start+.04)
            self.assertLess(time.monotonic()-start,.5)
        finally:os.close(read);os.close(write)

    def test_no_generic_command_body_or_unbound_fragment(self):
        for change in [{'op':'shell'},{'nonce':'b'*32},{'seq':True},{'section':'arbitrary'},
            {'row':{'nonce':N,'seq':0,'chunk':True,'data_b64':'eA=='}},
            {'row':{'nonce':N,'seq':0,'chunk':0,'data_b64':'x'*60000}}]:
            with self.subTest(change=change),self.assertRaises(ValueError):g.encode(1,{**self.value(),**change})
        for identifier in [True,0,4097]:
            with self.assertRaises(ValueError):g.encode(identifier,self.value())

if __name__=='__main__':unittest.main()
