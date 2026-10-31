"""Actual UNIX handoff with explicit fake Root filesystem, no privilege execution."""
from contextlib import contextmanager
import json,os,queue,socket,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
from paw.core import owned_mail_channel as c,mail_browser_owned as m
from test_mail_browser_owned import owned_case

class Admission(unittest.TestCase):
    def test_data_snapshot_consumption_and_same_request_replay_before_any_VM(self):
        if os.getuid()!=1000:self.skipTest('operator enrolled UID1000')
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);state=root/'state';exports=root/'exports';(state/'jobs').mkdir(parents=True);exports.mkdir()
            request=Path(m.prepare(owned_case(root),root/'request')['request']);raw=request.read_bytes();value=m.validate_request(raw)
            @contextmanager
            def trusted(path):
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
                try:yield fd
                finally:os.close(fd)
            def mapped(path):
                path=Path(path)
                for before,after in [(Path('/var/lib/paw-vm'),state),(Path('/var/lib/paw-vm-exports'),exports)]:
                    if path==before or path.is_relative_to(before):return after/path.relative_to(before)
                return path
            for index in range(2):
                job=str(index)*32;(state/'jobs'/job).mkdir();notice=queue.Queue();result=queue.Queue()
                def run():
                    try:result.put(c.admit(job,'c'*40,notice.put))
                    except Exception as error:result.put(error)
                with patch.object(c,'_root',return_value=trusted),patch.object(c,'Path',side_effect=mapped),patch.object(c.os,'chown'):
                    thread=threading.Thread(target=run);thread.start();announcement=notice.get(timeout=3)
                    fd=os.open(request,os.O_RDONLY)
                    try:
                        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)as peer:
                            peer.settimeout(3);peer.connect(str(exports/('owned-mail-input-'+job)/'request.sock'))
                            c.send(peer,job,announcement['nonce'],fd);ack=peer.recv(4096)
                    finally:os.close(fd)
                    thread.join(4);self.assertFalse(thread.is_alive());answer=result.get(timeout=1)
                self.assertEqual((state/'jobs'/job/'owned-mail-request.json').read_bytes(),raw)
                if index==0:
                    self.assertEqual(answer['raw'],raw);self.assertTrue(json.loads(ack)['accepted'])
                    marker=json.loads((state/'owned-mail-used'/value['request_id']).read_bytes());self.assertEqual(marker['job'],job)
                else:self.assertIsInstance(answer,FileExistsError);self.assertEqual(ack,b'')
                self.assertFalse((exports/('owned-mail-input-'+job)).exists())
            self.assertEqual(len(list((state/'owned-mail-used').iterdir())),1)

if __name__=='__main__':unittest.main()
