import array,importlib.util,json,os,socket,tempfile,time,unittest,uuid
from unittest.mock import patch
from pathlib import Path
from paw.core import mail_browser_owned as custody
from paw.core import owned_mail_channel as c
from test_mail_browser_owned import owned_case
class Channel(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  if os.getuid()!=1000:self.skipTest('finite operator is specifically enrolled for UID1000')
  value=json.loads(Path(custody.prepare(owned_case(self.root),self.root/'prepared')['request']).read_bytes())
  value.update(request_id=uuid.uuid4().hex,created_at=int(time.time()),expires_at=int(time.time())+900)
  self.raw=custody.canonical(value);self.path=self.root/'request';self.path.write_bytes(self.raw);self.path.chmod(0o400)
  self.fd=os.open(self.path,os.O_RDONLY);self.job='a'*32;self.nonce='b'*32
 def tearDown(self):os.close(self.fd);self.tmp.cleanup()
 def pair(self):return socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
 def test_actual_readonly_descriptor_and_nonce_bound_request(self):
  a,b=self.pair()
  with a,b:
   c.send(a,self.job,self.nonce,self.fd);got=c.receive(b,self.job,self.nonce)
  self.assertEqual(got['raw'],self.raw);self.assertEqual(got['authority'],'fixed data only; Root admission and execution required')
 def test_wrong_job_nonce_duplicateFD_and_missingFD_refuse_without_leaks(self):
  for mode in ['job','nonce','two','none']:
   a,b=self.pair()
   with a,b:
    before=len(os.listdir('/proc/self/fd'));env={'kind':'owned-mail-request-fd-v1','job':self.job,'nonce':self.nonce}
    if mode in {'job','nonce'}:env[mode]='c'*32
    descriptors=[self.fd,self.fd]if mode=='two'else[]if mode=='none'else[self.fd]
    a.sendmsg([custody.canonical(env)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',descriptors))]if descriptors else[])
    with self.assertRaises(ValueError):c.receive(b,self.job,self.nonce)
    self.assertEqual(len(os.listdir('/proc/self/fd')),before)
 def test_writable_mode_writeonly_or_hardlink_descriptor_refuse(self):
  for mode in ['bits','writeonly','hardlink']:
   with self.subTest(mode=mode):
    if mode in {'bits','writeonly'}:self.path.chmod(0o600)
    if mode=='hardlink':os.link(self.path,self.root/'linked')
    fd=os.open(self.path,os.O_WRONLY if mode=='writeonly'else os.O_RDONLY)
    if mode=='writeonly':self.path.chmod(0o400)
    try:
     with self.assertRaises(ValueError):c.descriptor(fd)
    finally:os.close(fd)
    self.path.chmod(0o400)
 def test_unprivileged_or_workspace_activation_refuses_before_root_filesystem_operations(self):
  with self.assertRaises(ValueError):c.admit(self.job,'c'*40,lambda _:self.fail('unexpected activation'))
  with patch.object(c.os,'getuid',return_value=0),patch.object(c.os,'geteuid',return_value=0):
   with self.assertRaises(ValueError):c.admit(self.job,'c'*40,lambda _:self.fail('workspace activation'))
 def test_payload_substitution_refuses_before_any_admission(self):
  self.path.chmod(0o600);self.path.write_bytes(b'{"approved":true}');self.path.chmod(0o400)
  a,b=self.pair()
  with a,b:
   c.send(a,self.job,self.nonce,self.fd)
   with self.assertRaises(ValueError):c.receive(b,self.job,self.nonce)
if __name__=='__main__':unittest.main()
