import hashlib,time,unittest
from unittest.mock import Mock
from paw.core import browser_broker_wire as wire
from paw.core import mail_browser_dns as dns
from paw.core import browser_owned_protocol as fixture
from paw.core import browser_owned_protocol as broker

N='a'*32
class Transport(unittest.TestCase):
    def test_owned_document_declares_inline_icon_without_an_extra_HTTP_request(self):
        from html.parser import HTMLParser
        class Page(HTMLParser):
            def __init__(self):super().__init__();self.icons=[]
            def handle_starttag(self,tag,attrs):
                data=dict(attrs)
                if tag=='link'and data.get('rel')=='icon':self.icons.append(data.get('href'))
        raw,_=fixture.http_response(b'GET / HTTP/1.1\r\nHost: paw-owned.invalid\r\n\r\n',N)
        headers,body=raw.split(b'\r\n\r\n',1)
        page=Page();page.feed(body.decode('ascii'))
        self.assertEqual(page.icons,['data:,'])
        self.assertIn(b'Content-Length: '+str(len(body)).encode(),headers)
        self.assertIn(b"fetch('/owned-data')",body)

    def session(self):
        dns_transport=Mock(side_effect=lambda host,ident,deadline:fixture.dns_response(dns.question(host,ident)))
        body=b'owned response'
        http=Mock(return_value=({'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()},body))
        session=broker.OwnedTransport(N,time.monotonic_ns()+8*10**9,dns_transport,http)
        return session,dns_transport,http
    def test_owned_dns_crosses_actual_binary_framing_then_strict_parser(self):
        session,transport,_=self.session()
        fields,body=session.dispatch(N,0,'dns',{'host':'paw-owned.invalid','ident':42,'deadline_ns':session.deadline})
        decoder=wire.Decoder(N);raw=wire.frame(N,0,'reply',fields,body);rows=[]
        for offset in range(0,len(raw),17):rows.extend(decoder.feed(raw[offset:offset+17]))
        decoder.eof();header,response=rows[0]
        actual=dns.parse_answer(response,header['fields']['host'],header['fields']['ident'])
        self.assertEqual(actual['answers'],['93.184.216.34']);transport.assert_called_once()
    def test_bad_identity_public_host_or_extra_fields_close_before_transport(self):
        for nonce,sequence,fields in [('b'*32,0,{'host':'paw-owned.invalid','ident':42,'deadline_ns':1}),
            (N,True,{}),(N,1,{}),(N,0,{'host':'sample.invalid','ident':42,'deadline_ns':1}),
            (N,0,{'host':'paw-owned.invalid','ident':42,'deadline_ns':1,'command':'shell'})]:
            session,dns_transport,http=self.session()
            with self.subTest(fields=fields),self.assertRaises(ValueError):session.dispatch(nonce,sequence,'dns',fields)
            self.assertTrue(session.closed);dns_transport.assert_not_called();http.assert_not_called()
    def test_stop_is_terminal_and_cannot_include_a_command(self):
        session,dns_transport,http=self.session();fields,body=session.dispatch(N,0,'stop',{})
        self.assertTrue(fields['stopped']);self.assertEqual(body,b'')
        with self.assertRaises(ValueError):session.dispatch(N,1,'stop',{})
        dns_transport.assert_not_called();http.assert_not_called()
        session,_,_=self.session()
        with self.assertRaises(ValueError):session.dispatch(N,0,'stop',{'command':'other'})

if __name__=='__main__':unittest.main()
