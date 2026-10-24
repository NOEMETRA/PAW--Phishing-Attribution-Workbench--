"""Inert admission/quarantine contracts. No VM, packet, DNS or live target."""
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch

from gw_admission import (Refused, admit_url, admit_addresses, strict_json,
    public_ipv4, encode_name, decode_name, dns_lookup, dns_response, question)
from gw_quarantine import publish, validate_records

class Admission(unittest.TestCase):
    def test_url_allowlist_and_every_ambiguous_literal(self):
        hosts=['allow.fixture.invalid']
        self.assertEqual(admit_url('https://allow.fixture.invalid:8443/a?q=x',hosts)['path'],'/a?q=x')
        for url in ['file:///etc/passwd','http://allow.fixture.invalid:80/',
                    'http://allow.fixture.invalid:18080/#x','http://x@allow.fixture.invalid:18080/',
                    'http://allow.fixture.invalid.:18080/','http://%61llow.fixture.invalid:18080/',
                    'http://allow.fixture.invalid:18080/\r\nX:x','http://allow.fixture.invalid:18080/%0dX',
                    'http://allow.fixture.invalid:18080/\\x','http://unknown.fixture.invalid:18080/',
                    'http://127.1:18080/','http://2130706433:18080/','http://0177.0.0.1:18080/',
                    'http://0x7f000001:18080/','http://[::ffff:127.0.0.1]:18080/']:
            with self.subTest(url=url),self.assertRaises(Refused):admit_url(url,hosts)

    def test_all_dns_answers_and_unavailable_live_mode(self):
        self.assertEqual(admit_addresses(['198.18.40.10'],'offline-fixture'),'198.18.40.10')
        for values in [[],['198.18.40.10','127.0.0.1'],['198.18.40.11'],['::ffff:198.18.40.10'],['169.254.169.254'],[True],['8.8.8.8']]:
            with self.subTest(values=values),self.assertRaises(Refused):admit_addresses(values,'offline-fixture')
        with self.assertRaises(Refused):admit_addresses(['198.18.40.10'],'live')

    def test_public_classifier_has_no_network_side_effect(self):
        with patch.object(socket,'socket',side_effect=AssertionError('no network')):
            for value in ['127.0.0.1','192.168.1.1','169.254.169.254','198.18.40.10','0.0.0.0','224.0.0.1','::1','::ffff:8.8.8.8','bad']:
                self.assertFalse(public_ipv4(value),value)
            self.assertTrue(public_ipv4('8.8.8.8'))

    def test_strict_json_duplicates_nonfinite_overflow(self):
        self.assertEqual(strict_json('{"a":1.25}'),{'a':1.25})
        for value in ['{"a":1,"a":2}','NaN','Infinity','-Infinity','1e999','-1e999']:
            with self.subTest(value=value),self.assertRaises(Refused):strict_json(value)

    def test_dns_bounded_wire_and_pointer_loop(self):
        query=struct.pack('!6H',0x1414,0x100,1,0,0,0)+encode_name('allow.fixture.invalid')+b'\0\1\0\1'
        answer=dns_response(query,['198.18.40.10'])
        self.assertEqual(question(answer)[2],'allow.fixture.invalid')
        self.assertEqual(answer[-4:],socket.inet_aton('198.18.40.10'))
        for data,offset in [(b'\xc0\x00',0),(b'\xff',0),(b'\x3fshort',0)]:
            with self.assertRaises(Refused):decode_name(data,offset)
        with self.assertRaises(Refused):question(b'x'*513)

    def test_dns_transport_pins_peer_and_validates_reply(self):
        class Client:
            def __init__(self,mutation):self.mutation=mutation
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def settimeout(self,value):pass
            def connect(self,peer):self.peer=peer
            def send(self,data):self.data=data
            def recv(self,count):
                answer=dns_response(self.data,['198.18.40.10'])
                if self.mutation=='id':answer=bytes([answer[0]^1])+answer[1:]
                elif self.mutation=='trailing':answer+=b'x'
                elif self.mutation=='tc':answer=answer[:2]+bytes([answer[2]|2])+answer[3:]
                return answer
        for mutation in ['valid','id','trailing','tc']:
            client=Client(mutation)
            with patch.object(socket,'socket',return_value=client):
                if mutation=='valid':self.assertEqual(dns_lookup('allow.fixture.invalid'),['198.18.40.10'])
                else:
                    with self.assertRaises(Refused):dns_lookup('allow.fixture.invalid')
            self.assertEqual(client.peer,('198.18.40.10',5353))

class Quarantine(unittest.TestCase):
    def record(self,name='active.html',data=b'<script>opaque</script>'):
        return {'name':name,'bytes_hex':data.hex(),'sha256':hashlib.sha256(data).hexdigest(),'scope':'opaque'}
    def test_paths_duplicate_digest_sizes_and_types_reject(self):
        record=self.record()
        cases=[[self.record('../escape')],[self.record('/absolute')],[self.record('bad name')],
               [record,record],[{**record,'sha256':'0'*64}],[self.record(data=b'x'*1025)],
               [record]*5,[{**record,'bytes_hex':'0Z'}],[{**record,'name':True}],{'x':record}]
        for records in cases:
            with self.subTest(records=str(records)[:80]),self.assertRaises(ValueError):validate_records(records)
    def test_stop_precedes_any_publication_and_validation_is_batch_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'output'
            with self.assertRaises(ValueError):publish(directory,[self.record()],False)
            self.assertFalse(directory.exists())
            with self.assertRaises(ValueError):publish(directory,[self.record(),self.record('../x')],True)
            self.assertFalse(directory.exists())
            manifest=publish(directory,[self.record()],True)
            self.assertEqual(manifest[0]['stored_as'],'artifact-00.bin')
            self.assertEqual((directory/'artifact-00.bin').read_bytes(),b'<script>opaque</script>')
            self.assertEqual((directory/'artifact-00.bin').stat().st_mode&0o777,0o600)
            self.assertFalse((directory/'active.html').exists())
            with self.assertRaises(FileExistsError):publish(directory,[self.record()],True)

if __name__=='__main__':unittest.main()
