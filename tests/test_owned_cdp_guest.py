import base64
import hashlib
import os
from pathlib import Path
import selectors
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from paw.core import browser_owned_cdp_guest as guest

N='a'*32
def frame(url=guest.SEED):return {'nonce':N,'seq':0,'url':url,'method':'GET','resource':'Document'}

class OwnedGuest(unittest.TestCase):
    def test_browser_executable_hash_streams_without_whole_binary_allocation(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'owned-binary';block=b'owned'*13107;expected=hashlib.sha256()
            with path.open('wb') as stream:
                for _ in range(40):stream.write(block);expected.update(block)
            with patch.object(Path,'read_bytes',side_effect=AssertionError('whole binary read')):
                self.assertEqual(guest.file_digest(path),expected.hexdigest())
    def test_fixed_local_responses_never_connect_or_spawn(self):
        with patch.object(socket,'socket',side_effect=AssertionError('socket')), \
             patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS')), \
             patch.object(guest.subprocess,'Popen',side_effect=AssertionError('process')):
            head,body=guest.fixture(N,frame());self.assertIn(b"fetch('/owned-data')",body)
            self.assertEqual(head['body_sha256'],hashlib.sha256(body).hexdigest())
            head,body=guest.fixture(N,frame(guest.SEED+'owned-data'))
            self.assertEqual(body,('PAW-OWNED-'+N).encode())
    def test_arbitrary_public_private_file_or_post_never_get_response(self):
        for url in ['https://other.invalid/','http://169.254.169.254/','https://paw-owned.invalid/?extra=x',
                    'file:///etc/shadow','javascript:alert(1)']:
            with self.subTest(url=url):self.assertEqual(guest.fixture(N,frame(url)),(None,None))
        row=frame();row['method']='POST';self.assertEqual(guest.fixture(N,row),(None,None))
    def test_invalid_nonce_shape_index_and_types_refuse(self):
        for change in [{'nonce':'b'*32},{'command':'/bin/sh'},{'seq':True},{'seq':32},{'url':[]},{'method':{}}]:
            with self.subTest(change=change),self.assertRaises(ValueError):guest.fixture(N,{**frame(),**change})
    def test_fixed_chrome_pipe_arguments_keep_sandbox_and_owned_blank_page(self):
        args=guest.fixed_arguments()
        self.assertEqual(args[0],'/opt/google/chrome/chrome');self.assertEqual(args[-1],'about:blank')
        self.assertIn('--remote-debugging-pipe',args)
        for forbidden in ['--no-sandbox','--disable-web-security','--ignore-certificate-errors']:
            self.assertNotIn(forbidden,args)
        self.assertFalse(any(x.startswith('--remote-debugging-port') for x in args))
    def test_host_uid_cannot_start_guest_launcher(self):
        with patch.object(guest.os,'geteuid',return_value=1000), \
             patch.object(guest.subprocess,'Popen',side_effect=AssertionError('must not launch')):
            with self.assertRaisesRegex(ValueError,'owned_guest_no_nic'):guest.Runtime().start()
    def test_actual_private_pipe_eof_requests_immediate_stop_before_deadline(self):
        runtime=guest.Runtime();read,write=os.pipe();os.close(write)
        runtime.selector.register(read,selectors.EVENT_READ,'cdp')
        runtime.process=MagicMock();runtime.witness=MagicMock();runtime.started=time.monotonic()
        runtime.finish=MagicMock(return_value={'status':'failed'})
        try:
            with patch.object(guest.os,'listdir',return_value=['lo']):
                self.assertEqual(runtime.tick(),{'status':'failed'})
            runtime.finish.assert_called_once()
            self.assertEqual(runtime.finish.call_args.args[0],'failed')
            self.assertIn('owned_cdp_pipe_eof',runtime.finish.call_args.args[1])
            self.assertLess(time.monotonic()-runtime.started,1)
        finally:os.close(read);runtime.selector.close()

if __name__=='__main__':unittest.main()
