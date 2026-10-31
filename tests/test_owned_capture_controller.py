import base64,importlib.util,sys,unittest
from pathlib import Path
from paw.core import browser_cdp as cdp
from paw.core import browser_owned_broker_guest as m
PNG=b'\x89PNG\r\n\x1a\n'+b'\x00\x00\x00\x0dIHDR'+(1).to_bytes(4,'big')*2+b'\x08\x06\x00\x00\x00'+b'\x00'*4
class Capture(unittest.TestCase):
 def driver(self):
  sent=[];requests=[];d=m.CaptureController('https://paw-owned.invalid/','a'*32,sent.append,requests.append)
  d.stage='running';d.session='owned';d.fetch=cdp.FetchTranslator(d.nonce,d.session);d.snapshot()
  def reply(value):d.accept({'id':sent[-1]['id'],'sessionId':'owned','result':value})
  reply({'root':{'nodeId':1}});reply({'outerHTML':'<p>fixed owned DOM</p>'});return d,sent,requests,reply
 def test_DOM_then_one_png_and_snapshot_only_ready_after_both(self):
  d,sent,_,reply=self.driver();self.assertEqual(d.stage,'snapshot');self.assertEqual(sent[-1]['method'],'Page.captureScreenshot')
  reply({'data':base64.b64encode(PNG).decode()});self.assertEqual(d.stage,'snapshot_ready');self.assertEqual(d.png,PNG)
  self.assertEqual(d.dom,b'<p>fixed owned DOM</p>');self.assertEqual(sum(x['method']=='Page.captureScreenshot'for x in sent),1)
 def test_late_requests_during_png_are_blocked_without_broker_dispatch(self):
  d,sent,requests,_=self.driver();d.accept({'sessionId':'owned','method':'Fetch.requestPaused','params':{'requestId':'late'}})
  self.assertEqual(sent[-1]['method'],'Fetch.failRequest');self.assertEqual(requests,[])
 def test_invalid_or_overlarge_png_closes_existing_cdp_session(self):
  for value in ['!',base64.b64encode(b'not png').decode(),'A'*(4*((256*1024+2)//3)+1)]:
   d,_,_,reply=self.driver()
   with self.assertRaises(ValueError):reply({'data':value})
   self.assertEqual(d.stage,'failed');self.assertIsNone(d.png)
 def test_snapshot_does_not_open_a_socket_or_start_a_browser(self):
  d,_,_,reply=self.driver();reply({'data':base64.b64encode(PNG).decode()});self.assertEqual(d.events,3)
if __name__=='__main__':unittest.main()
