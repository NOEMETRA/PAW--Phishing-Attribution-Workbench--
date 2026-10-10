"""Real HTTP transport on loopback with protocol fixtures; no live registry claim."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from paw.core.network_policy import offline_policy, violations
from paw.core.profiler import _domain_registration, observe_domain_age
from paw.core.scoring import score_case


def main():
    good={'objectClassName':'domain','ldhName':'EXAMPLE.COM.',
          'registrar':{'name':'Supplied fixture registrar'},
          'events':[{'eventAction':'registration','eventDate':'2026-10-09T00:00:00Z'}]}
    bad={**good,'ldhName':'other.com'}
    multiple={**good,'events':good['events']+[{'eventAction':'registration','eventDate':'2026-10-01T00:00:00Z'}]}
    bodies={'/good':good,'/bad':bad,'/multiple':multiple,'/wrong-class':{**good,'objectClassName':'entity'},
            '/no-name':{key:value for key,value in good.items() if key!='ldhName'}}
    visits=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            visits.append(self.path)
            if self.path=='/redirect':
                self.send_response(302); self.send_header('Location','/bad'); self.end_headers(); return
            status=404 if self.path=='/missing' else 200
            body=b'not json' if self.path=='/invalid-json' else json.dumps(bodies.get(self.path,{})).encode()
            self.send_response(status); self.send_header('Content-Type','application/rdap+json')
            self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    base=f'http://127.0.0.1:{server.server_address[1]}'
    try:
        cases=(('/good','registration_event_observed'),('/bad','domain_mismatch'),
               ('/multiple','ambiguous_registration_events'),('/wrong-class','not_domain_object'),
               ('/no-name','ldh_name_unavailable_or_invalid'),('/missing','http_status_unavailable'),
               ('/invalid-json','request_or_json_failed'),('/redirect','domain_mismatch'))
        for path,reason in cases:
            result=_domain_registration('example.com',base+path)
            observation=result['rdap_registration']
            assert observation['reason_code']==reason,observation
            assert observation['request_url']==base+path and observation['verified'] is False
            assert observation['response_url']==base+('/bad' if path=='/redirect' else path)
            age=observe_domain_age(result['created'],reference_time='2026-10-10T00:00:00Z')['age_days']
            score=score_case({}, {}, {'domain':'example.com','nrd_days':age},headers={'from':'a@example.com'})
            expected=.35 if path=='/good' else 0
            assert abs(score['score_components']['sender_domain_heuristics']-expected)<1e-12
            if path=='/good':
                assert result['registrar']=='Supplied fixture registrar' and observation['domain_match'] is True
            elif path in ('/bad','/wrong-class','/no-name','/redirect'):
                assert result['registrar'] is None and result['created'] is None
        assert len(visits)==9
        count=len(visits); before=len(violations())
        with offline_policy(True):
            skipped=_domain_registration('example.com',base+'/good')
        assert len(visits)==count and len(violations())==before
        assert skipped['created'] is None and skipped['rdap_registration']['reason_code']=='no_egress'
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        assert not thread.is_alive()
    print('PASS: 8 real loopback HTTP contracts, redirect/JSON/status/name binding/event ambiguity; no-egress adds no request. Supplied protocol fixtures are not live registry evidence or analysis labels.')


if __name__=='__main__': main()
