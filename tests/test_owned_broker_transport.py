import hashlib,time,unittest
from unittest.mock import Mock
from paw.core import browser_broker_wire as wire
from paw.core import mail_browser_dns as dns
from paw.core import browser_owned_protocol as fixture
from paw.core import browser_owned_protocol as broker

N='a'*32
class Transport(unittest.TestCase):
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
