"""Real loopback HTTP/PTR, controller threads and SQLite; constructed protocol data.

No email target, live provider, browser, calibrated risk or OS isolation claim.
An audit hook refuses non-loopback DNS lookups/connect/sendto and subprocess attempts.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import hashlib
import gzip
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs, unquote

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from paw.core.network_policy import offline_policy, violations
from paw.sentinel.config import SentinelConfig
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.monitor import SentinelMonitor
from paw.sentinel.ip_analyzer import IPAnalyzer
from paw.sentinel.transport import fetch_http

DENIED = []


def loopback_only(event, args):
    destination = None
    if event in ('socket.getaddrinfo','socket.gethostbyname','socket.gethostbyaddr'):
        destination = args[0]
    elif event == 'socket.connect': destination = args[1][0]
    elif event == 'socket.sendto': destination = args[-1][0]
    forbidden = destination is not None and destination not in ('127.0.0.1',b'127.0.0.1')
    if forbidden or event in ('subprocess.Popen','os.system','os.posix_spawn','os.spawn'):
        DENIED.append(event); raise AssertionError('Integration permits only owned loopback transport')


class SentinelModuleIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.visits = []; cls.status = 200; cls.body = b'owned body A'
        cls.entered = threading.Event(); cls.release = threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                cls.visits.append(self.path); path = urlsplit(self.path).path
                try:
                    if path == '/hold':
                        cls.entered.set(); cls.release.wait(5)
                    if path == '/redirect':
                        self.send_response(302); self.send_header('Location','http://outbound.invalid/never')
                        self.send_header('Content-Length','0'); self.end_headers(); return
                    if path == '/drip':
                        self.send_response(200); self.send_header('Content-Length','12'); self.end_headers()
                        for _ in range(12): self.wfile.write(b'x'); self.wfile.flush(); time.sleep(.06)
                        return
                    if path == '/broken':
                        self.send_response(200); self.send_header('Content-Length','100'); self.end_headers()
                        self.wfile.write(b'x'); self.wfile.flush(); return
                    status = cls.status if path == '/campaign' else 200
                    body = cls.body
                    encoded = path == '/compressed'
                    if encoded: body = gzip.compress(b'x'*(4*1024**2))
                    if path == '/oversize': body = b'x'*(256*1024)
                    elif path.startswith('/ipapi/'):
                        address = unquote(path.rsplit('/',1)[1])
                        body = json.dumps({'status':'success','query':address,'country':'Fixture land',
                                           'countryCode':'XX','lat':0,'lon':0}).encode()
                    elif path.startswith('/mismatch/'):
                        body = json.dumps({'status':'success','query':'8.8.4.4','country':'Wrong binding'}).encode()
                    elif path.startswith('/duplicate/'):
                        body = b'{"status":"success","query":"8.8.8.8","query":"8.8.4.4"}'
                    elif path.startswith('/invalid/'): body = b'not JSON'
                    elif path.startswith('/huge/'): body = b'x'*(256*1024)
                    elif path == '/ipify':
                        address = parse_qs(urlsplit(self.path).query)['ipAddress'][0]
                        body = json.dumps({'ip':address,'location':{'country':'XX','lat':0,'lng':12}}).encode()
                    self.send_response(status); self.send_header('Content-Length',str(len(body)))
                    if encoded: self.send_header('Content-Encoding','gzip')
                    self.end_headers(); self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError): pass
        cls.server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.server.daemon_threads = False; cls.server.block_on_close = True
        cls.thread = threading.Thread(target=cls.server.serve_forever,name='owned-sentinel-http')
        cls.thread.start(); cls.base = f'http://127.0.0.1:{cls.server.server_address[1]}'
        sys.addaudithook(loopback_only)

    @classmethod
    def tearDownClass(cls):
        cls.release.set(); cls.server.shutdown(); cls.server.server_close(); cls.thread.join(3)
        assert not cls.thread.is_alive()
        assert not DENIED,DENIED
        assert not [t.name for t in threading.enumerate() if t.name.startswith('paw-sentinel')]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='paw-sentinel-module-real-')
        self.root = Path(self.temp.name); self.config = SentinelConfig(str(self.root/'config.json'))
        self.config._config['monitoring']['timeout_seconds'] = 3
        self.config._config['alerts']['alert_on_up'] = True
        self.db = CampaignDatabase(str(self.root/'saved.db'))
        self.campaign = self.db.add_campaign('owned',self.base+'/campaign')
        self.monitor = SentinelMonitor(self.config,self.db)
        type(self).status = 200; type(self).body = b'owned body A'
        self.entered.clear(); self.release.clear()

    def tearDown(self):
        self.release.set(); self.assertTrue(self.monitor.stop(3))
        self.temp.cleanup()

    def ip(self, prefix='/ipapi'):
        return IPAnalyzer(timeout=.5,use_proxy=False,provider_urls={
            'ip-api':self.base+prefix,'ipify':self.base+'/ipify'})

    def test_actual_http_transitions_commit_previous_ids_and_callback_sources(self):
        complete,down,up,changed,alerts = [],[],[],[],[]
        for method,target in ((self.monitor.on_check_complete,complete),(self.monitor.on_campaign_down,down),
                (self.monitor.on_campaign_up,up),(self.monitor.on_content_changed,changed),(self.monitor.on_alert,alerts)):
            method(target.append)
        first, = self.monitor.check_now(self.campaign)
        self.assertEqual(first['content_hash'],hashlib.sha256(self.body).hexdigest())
        self.assertEqual(base64.b64decode(first['metadata']['http_observation']['body_base64']),self.body)
        type(self).status = 503; type(self).body = b'owned body B'
        self.monitor.check_now(self.campaign)
        type(self).status = 200
        self.monitor.check_now(self.campaign)
        self.assertEqual(tuple(map(len,(complete,down,up,changed,alerts))),(3,1,1,1,3))
        self.assertEqual(complete[1]['previous_check_id'],complete[0]['check_id'])
        self.assertEqual(len(self.db.get_recent_checks(self.campaign)),3)
        self.assertEqual(len(self.db.get_unacknowledged_alerts()),3)
        with self.db.connection() as conn:
            stored = json.loads(conn.execute('SELECT metadata FROM checks ORDER BY id LIMIT 1').fetchone()[0])
        self.assertEqual(base64.b64decode(stored['source_metadata']['http_observation']['body_base64']),b'owned body A')
        self.assertFalse(first['metadata']['http_observation']['verified'])
        self.assertEqual(first['metadata']['screenshot']['status'],'unavailable')

    def test_redirect_does_not_follow_external_location(self):
        before = len(self.visits); result = fetch_http(self.base+'/redirect',timeout=.5)
        self.assertEqual(result['http_status'],302); self.assertFalse(result['redirects_followed'])
        self.assertEqual(len(self.visits)-before,1)
        self.assertIn(['Location','http://outbound.invalid/never'],result['response_headers']['entries'])

    def test_compressed_body_is_retained_without_unbounded_content_decoding(self):
        result = fetch_http(self.base+'/compressed',timeout=2,max_bytes=8192)
        self.assertEqual(result['content_encoding'],'gzip'); self.assertEqual(result['body_status'],'completed')
        self.assertLess(len(result['body']),8192)
        self.assertEqual(result['content_sha256'],hashlib.sha256(result['body']).hexdigest())

    def test_direct_transport_ignores_environment_proxy(self):
        with patch.dict(os.environ,{'HTTP_PROXY':'http://outbound.invalid:9','HTTPS_PROXY':'http://outbound.invalid:9',
                                     'ALL_PROXY':'http://outbound.invalid:9','NO_PROXY':''}):
            result = fetch_http(self.base+'/campaign',timeout=2)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['transport_route'],'direct; environment proxies ignored')

    def test_partial_body_has_retained_digest_but_no_complete_hash(self):
        result = fetch_http(self.base+'/oversize',timeout=.5,max_bytes=64)
        self.assertEqual(result['body_status'],'partial'); self.assertIsNone(result['content_sha256'])
        self.assertLessEqual(len(result['body']),65)
        self.assertEqual(result['retained_sha256'],hashlib.sha256(result['body']).hexdigest())

    def test_slow_drip_reaches_deadline_without_full_chunk_fill(self):
        started = time.monotonic(); result = fetch_http(self.base+'/drip',timeout=.15)
        self.assertLess(time.monotonic()-started,1)
        self.assertEqual(result['body_status'],'partial'); self.assertIsNone(result['content_sha256'])

    def test_broken_body_is_transport_error_not_down_alert(self):
        campaign = self.db.add_campaign('owned-broken',self.base+'/broken')
        result, = self.monitor.check_now(campaign)
        self.assertEqual(result['status'],'error'); self.assertIsNone(result['content_hash'])
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_stop_is_false_until_actual_network_worker_exits_then_storage_stable(self):
        self.db.remove_campaign(self.campaign)
        self.db.add_campaign('owned-hold',self.base+'/hold')
        self.config._config['monitoring']['timeout_seconds'] = 2
        try:
            self.monitor.start(); self.assertTrue(self.entered.wait(2))
            self.assertFalse(self.monitor.stop(.01)); self.assertTrue(self.monitor.is_running())
            self.assertEqual(self.monitor.get_runtime_state()['state'],'stopping')
            with self.assertRaises(RuntimeError): self.monitor.start()
        finally: self.release.set()
        self.assertTrue(self.monitor.stop(3)); self.assertFalse(self.monitor.is_running())
        before = (self.root/'saved.db').read_bytes(); time.sleep(.05)
        self.assertEqual((self.root/'saved.db').read_bytes(),before)
        with self.db.connection() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM checks').fetchone()[0],0)

    def test_callback_can_signal_stop_without_self_join_or_overlap(self):
        stops = []; self.monitor.on_check_complete(lambda value:stops.append(self.monitor.stop(.01)))
        self.monitor.check_now(self.campaign)
        self.assertEqual(stops,[False]); self.assertTrue(self.monitor.stop(2))
        self.assertFalse(self.monitor.is_running())

    def test_read_only_monitor_refuses_before_request(self):
        reader = CampaignDatabase(str(self.root/'saved.db'),read_only=True)
        monitor = SentinelMonitor(self.config,reader); before = len(self.visits)
        for operation in (monitor.start,monitor.check_now,lambda:monitor._check_campaign({'id':self.campaign,'url':self.base+'/campaign'})):
            with self.assertRaises(RuntimeError): operation()
        self.assertEqual(len(self.visits),before)

    def test_provider_raw_binding_zero_coordinates_lazy_fallback_and_cache_copy(self):
        analyzer = self.ip(); before = len(self.visits)
        with patch.dict(os.environ,{'PAW_IPIFY_API_KEY':'fixture-secret'}):
            result = analyzer.geolocate_ip('8.8.8.8')
        self.assertEqual(result['status'],'observed'); self.assertEqual(result['lat'],0)
        self.assertEqual(result['lon'],0); self.assertFalse(result['verified'])
        raw = base64.b64decode(result['provider_evidence']['body_base64'])
        self.assertEqual(json.loads(raw)['query'],'8.8.8.8')
        result['country'] = 'caller mutation'
        cached = analyzer.geolocate_ip('8.8.8.8')
        self.assertEqual(cached['country'],'Fixture land'); self.assertTrue(cached['cache']['hit'])
        self.assertEqual(len(self.visits)-before,1)

    def test_ipv6_provider_binding_uses_complete_canonical_literal(self):
        result = self.ip().geolocate_ip('2001:4860:4860::8888')
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['provider_payload']['query'],'2001:4860:4860::8888')

    def test_invalid_provider_attempts_keep_raw_sources_and_do_not_invent_country(self):
        with patch.dict(os.environ,{},clear=False):
            old = os.environ.pop('PAW_IPIFY_API_KEY',None)
            try:
                for prefix in ('/mismatch','/duplicate','/invalid','/huge'):
                    with self.subTest(prefix=prefix):
                        result = self.ip(prefix).geolocate_ip('8.8.8.8')
                        self.assertEqual(result['status'],'unavailable')
                        self.assertNotIn('country',result)
                        evidence = result['attempts'][0]['provider_evidence']
                        self.assertLessEqual(len(base64.b64decode(evidence['body_base64'])),128*1024+1)
                        self.assertFalse(evidence['verified'])
            finally:
                if old is not None: os.environ['PAW_IPIFY_API_KEY'] = old

    def test_real_fallback_provider_redacts_credential_and_maps_longitude(self):
        with patch.dict(os.environ,{'PAW_IPIFY_API_KEY':'fixture-secret'}):
            result = self.ip('/mismatch').geolocate_ip('8.8.8.8')
        self.assertEqual(result['source'],'ipify'); self.assertEqual(result['lon'],12)
        self.assertEqual(len(result['attempts']),2)
        self.assertNotIn('fixture-secret',json.dumps(result))
        self.assertIn('redacted',result['provider_evidence']['response_url'])

    def test_actual_loopback_ptr_answer_is_unverified_not_identity(self):
        import dns.message
        import dns.rrset
        import dns.resolver
        listener = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); listener.bind(('127.0.0.1',0))
        listener.settimeout(2); requests = []; errors = []
        def serve():
            try:
                raw,peer = listener.recvfrom(4096); query = dns.message.from_wire(raw)
                requests.append(str(query.question[0].name))
                response = dns.message.make_response(query)
                response.answer.append(dns.rrset.from_text(query.question[0].name,60,'IN','PTR','fixture.ptr.invalid.'))
                listener.sendto(response.to_wire(),peer)
            except Exception as error: errors.append(type(error).__name__)
        thread = threading.Thread(target=serve,name='owned-sentinel-ptr'); thread.start()
        resolver = dns.resolver.Resolver(configure=False); resolver.nameservers = ['127.0.0.1']
        resolver.port = listener.getsockname()[1]
        analyzer = self.ip(); analyzer._ptr_resolver = resolver
        try: self.assertEqual(analyzer.reverse_dns_lookup('8.8.8.8'),'fixture.ptr.invalid')
        finally: thread.join(3); listener.close()
        self.assertFalse(thread.is_alive()); self.assertEqual(errors,[])
        self.assertEqual(requests,['8.8.8.8.in-addr.arpa.'])

    def test_batch_real_provider_results_preserve_source_order_and_unique_addresses(self):
        analyzer = self.ip()
        # Avoid system DNS: serve a declared negative PTR observation. HTTP is real.
        with patch.object(analyzer,'reverse_dns_lookup',return_value=None):
            result = analyzer.batch_analyze_ips(['8.8.8.8','1.1.1.1','8.8.8.8'],2)
        self.assertEqual(list(result),['8.8.8.8','1.1.1.1'])
        for value in result.values():
            self.assertEqual(value['geolocation']['status'],'observed')
            self.assertEqual(value['availability']['identity'],'unavailable')

    def test_no_egress_refuses_all_new_transport_before_request(self):
        before = len(self.visits); prior = len(violations())
        with offline_policy():
            for operation in (lambda:fetch_http(object()),self.monitor.start,self.monitor.check_now,
                    lambda:self.ip().geolocate_ip(object()),lambda:self.ip().batch_analyze_ips(object())):
                with self.assertRaises(RuntimeError): operation()
        self.assertEqual(len(self.visits),before); self.assertEqual(len(violations()),prior)


if __name__=='__main__': unittest.main(verbosity=2)
