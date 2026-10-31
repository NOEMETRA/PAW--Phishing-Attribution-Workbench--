import unittest
from paw.core import mail_browser_dns as dns
from paw.core import browser_mediator as mediator
from paw.core import browser_owned_protocol as fixture

N='a'*32
class Fixture(unittest.TestCase):
    def request(self,path=b'/',method=b'GET'):
        return method+b' '+path+b' HTTP/1.1\r\nHost: paw-owned.invalid\r\n\r\n'
    def test_owned_dns_packet_is_parsed_by_actual_strict_codec(self):
        raw=dns.question('paw-owned.invalid',42)
        result=dns.parse_answer(fixture.dns_response(raw),'paw-owned.invalid',42)
        self.assertEqual(result['answers'],['93.184.216.34']);self.assertEqual(result['ttl_ns'],10**10)
        with self.assertRaises(ValueError):dns.parse_answer(fixture.dns_response(raw,'private'),'paw-owned.invalid',42)
        changed=dns.parse_answer(fixture.dns_response(raw,'changed'),'paw-owned.invalid',42)
        self.assertEqual(changed['answers'],['93.184.216.35'])
        with self.assertRaises(ValueError):fixture.dns_response(dns.question('other.invalid',42))
    def test_generated_script_and_nonce_resource_are_exact_owned_fixture(self):
        html,meta=fixture.http_response(self.request(),N)
        self.assertIn(b"fetch('/owned-data')",html);self.assertEqual(meta['http_status'],200)
        response,meta=fixture.http_response(self.request(b'/owned-data'),N)
        self.assertTrue(response.endswith(('PAW-OWNED-'+N).encode()));self.assertIn(b'Set-Cookie:',response)
        response,meta=fixture.http_response(self.request(b'/owned-data',b'HEAD'),N)
        self.assertTrue(response.endswith(b'\r\n\r\n'));self.assertEqual(meta['sent_body_bytes'],0)
    def test_redirect_loop_and_overflow_are_finite_owned_cases(self):
        for path in [b'/redirect',b'/loop']:
            response,meta=fixture.http_response(self.request(path),N)
            self.assertEqual(meta['http_status'],302);self.assertIn(b'Location:',response)
        response,meta=fixture.http_response(self.request(b'/overflow'),N)
        self.assertEqual(meta['sent_body_bytes'],mediator.LIMITS['bytes']+1)
    def test_no_generic_request_or_response_input_is_accepted(self):
        bad=[self.request(b'/arbitrary'),self.request(method=b'POST'),self.request()+b'body',
            self.request().replace(b'Host: paw-owned.invalid',b'Host: elsewhere.invalid'),
            self.request().replace(b'\r\n\r\n',b'\r\nCookie: private\r\n\r\n')]
        for raw in bad:
            with self.subTest(raw=raw),self.assertRaises(ValueError):fixture.http_response(raw,N)
        with self.assertRaises(ValueError):fixture.http_response(self.request(),'invalid nonce')

if __name__=='__main__':unittest.main()
