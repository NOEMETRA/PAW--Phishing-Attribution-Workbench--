"""Actual ordinary-UID loopback DNS/HTTP/TLS fixtures, no Root/namespace/VM."""
import importlib.util,pathlib,socket,ssl,subprocess,tempfile,threading,time,unittest
from paw.core import browser_owned_protocol as fixture
from paw.core import mail_browser_dns as dns

class Server(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=pathlib.Path(self.temp.name)
        cert=root/'cert.pem';key=root/'key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=paw-owned.invalid','-addext','subjectAltName=DNS:paw-owned.invalid',
            '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        self.client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);self.client.load_verify_locations(cafile=cert)
        self.sockets={};self.ports={}
        for name in ['dns','http','https']:
            stream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if name=='dns'else socket.SOCK_STREAM)
            stream.bind(('127.0.0.1',0))
            if name!='dns':stream.listen(4)
            self.sockets[name]=stream;self.ports[name]=stream.getsockname()[1]
        self.server=fixture.Server('a'*32,self.sockets,context,time.monotonic_ns()+5*10**9)
        self.thread=threading.Thread(target=self.server.run,daemon=True);self.thread.start()
    def tearDown(self):
        self.server.closed=True;self.thread.join(timeout=2);self.assertFalse(self.thread.is_alive());self.temp.cleanup()
    def fetch(self,kind,method=b'GET',path=b'/owned-data',extra=b''):
        with socket.socket()as raw:
            raw.settimeout(1);raw.connect(('127.0.0.1',self.ports[kind]))
            stream=self.client.wrap_socket(raw,server_hostname='paw-owned.invalid')if kind=='https'else raw
            with stream:
                stream.sendall(method+b' '+path+b' HTTP/1.1\r\nHost: paw-owned.invalid\r\n'+extra+b'\r\n')
                response=bytearray()
                while True:
                    try:part=stream.recv(4096)
                    except ConnectionResetError:break
                    if not part:break
                    response.extend(part)
                return bytes(response)
    def test_actual_dns_and_http_tls_resources_match_fixed_owned_nonce(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as stream:
            stream.settimeout(1);stream.sendto(dns.question(fixture.HOST,42),('127.0.0.1',self.ports['dns']))
            raw,_=stream.recvfrom(4096)
        self.assertEqual(dns.parse_answer(raw,fixture.HOST,42)['answers'],['93.184.216.34'])
        for kind in ['http','https']:
            self.assertTrue(self.fetch(kind).endswith(b'PAW-OWNED-'+b'a'*32))
        self.assertEqual(self.server.counts['dns'],1);self.assertEqual(self.server.counts['http'],1)
        self.assertEqual(self.server.counts['https'],1)
    def test_actual_auth_header_unknown_method_and_path_are_refused(self):
        for method,path,extra in [(b'GET',b'/',b'Cookie: x=y\r\n'),(b'POST',b'/',b''),(b'GET',b'/unknown',b'')]:
            self.assertEqual(self.fetch('https',method,path,extra),b'')
        self.assertEqual(self.server.counts['refused'],3)
    def test_actual_head_has_no_body_and_redirect_remains_unfollowed(self):
        self.assertTrue(self.fetch('https',b'HEAD').endswith(b'\r\n\r\n'))
        response=self.fetch('http',path=b'/redirect')
        self.assertTrue(response.startswith(b'HTTP/1.1 302'));self.assertIn(b'Location: /\r\n',response)
        self.assertTrue(response.endswith(b'\r\n\r\n'))
    def test_fixed_browser_icon_probe_receives_empty_http_instead_of_transport_eof(self):
        for kind in ['http','https']:
            response=self.fetch(kind,path=b'/favicon.ico')
            self.assertTrue(response.startswith(b'HTTP/1.1 404 Not Found\r\n'),response)
            self.assertIn(b'Content-Length: 0\r\n',response)
            self.assertTrue(response.endswith(b'\r\n\r\n'))
        self.assertEqual(self.server.counts['refused'],0)

if __name__=='__main__':unittest.main()
