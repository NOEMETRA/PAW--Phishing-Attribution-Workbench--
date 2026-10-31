import importlib.util,unittest
from pathlib import Path
from paw.core import browser_cdp as cdp
from paw.core import browser_owned_broker_guest as m
class Transfer(unittest.TestCase):
 def test_actual_maximum_binary_DOM_and_png_chunks_bind_length_digest_and_nonce_after_stop(self):
  parts={'dom.html':b'd'*(256*1024),'screenshot.png':bytes(range(256))*1024};t=m.Transfer('a'*32,parts,True)
  for meta in t.manifest:
   a=cdp.ResponseAssembler('a'*32,meta['stream'],meta['bytes']);raw=None;n=0
   while raw is None:
    reply=t.read({'name':meta['name'],'chunk':n});raw=a.feed(reply['row']);n+=1
   self.assertEqual(raw,parts[meta['name']])
  self.assertTrue(t.closed)
  with self.assertRaises(ValueError):t.read({'name':'dom.html','chunk':0})
 def test_no_transfer_from_live_writers_and_no_unknown_paths_or_oversize(self):
  for parts,stop in [({'dom.html':b'x'},False),({'../x':b'x'},True),({'dom.html':b'x'*(256*1024+1)},True)]:
   with self.assertRaises(ValueError):m.Transfer('a'*32,parts,stop)
 def test_wrong_name_index_or_boolean_permanently_closes_transfer(self):
  for value in [{'name':'screenshot.png','chunk':0},{'name':'dom.html','chunk':1},{'name':'dom.html','chunk':False}]:
   t=m.Transfer('a'*32,{'dom.html':b'owned'},True)
   with self.assertRaises(ValueError):t.read(value)
   with self.assertRaises(ValueError):t.read({'name':'dom.html','chunk':0})
if __name__=='__main__':unittest.main()
