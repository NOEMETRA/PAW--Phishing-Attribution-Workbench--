import ipaddress
from pathlib import Path
import socket
import struct
import sys
import time
import unittest
from unittest.mock import patch,MagicMock

from paw.core import mail_browser_dns as d

HOST='owned.invalid';ID=42
def name(value):return b''.join(bytes([len(x)])+x.encode() for x in value.split('.'))+b'\0'
def record(owner,kind,raw,ttl=30):
    return owner+struct.pack('!2HIH',kind,1,ttl,len(raw))+raw
def answer(records,flags=0x8180,ident=ID):
    return struct.pack('!6H',ident,flags,1,len(records),0,0)+d.question(HOST,ID)[12:]+b''.join(records)
def a(ip='93.184.216.34',owner=b'\xc0\x0c',ttl=30):return record(owner,1,ipaddress.IPv4Address(ip).packed,ttl)

class DNS(unittest.TestCase):
    def test_question_and_actual_compressed_response_codec_are_inert(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network')),patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS')):
            q=d.question(HOST,ID);result=d.parse_answer(answer([a()]),HOST,ID)
        self.assertEqual(struct.unpack('!6H',q[:12]),(42,0x100,1,0,0,0))
        self.assertEqual(result['answers'],['93.184.216.34']);self.assertEqual(result['ttl_ns'],30*10**9)
        self.assertIn('not established',result['dnssec'])
    def test_cname_chain_uses_minimum_ttl_and_terminal_address(self):
        msg=answer([record(b'\xc0\x0c',5,name('alias.invalid'),7),a(owner=name('alias.invalid'))])
        result=d.parse_answer(msg,HOST,ID)
        self.assertEqual(result['canonical_name'],'alias.invalid');self.assertEqual(result['ttl_ns'],7*10**9)
    def test_private_mixed_duplicate_and_special_answers_refuse(self):
        for records in [[a('127.0.0.1')],[a(),a('169.254.169.254')],[a(),a()],
                        [a('192.168.1.2')],[a('192.0.2.1')],[a('100.64.0.1')],
                        [a('198.18.43.10')],[a('224.0.0.1')]]:
            with self.subTest(records=records),self.assertRaises(ValueError):d.parse_answer(answer(records),HOST,ID)
    def test_id_question_flags_truncation_counts_and_trailing_refuse(self):
        good=answer([a()])
        bad=[answer([a()],ident=43),answer([a()],flags=0x8380),answer([a()],flags=0x8183),
             answer([a()],flags=0x0180),good[:-1],good+b'x',b'x'*4097,
             good[:4]+struct.pack('!H',2)+good[6:],d.question(HOST,ID)]
        for packet in bad:
            with self.subTest(prefix=packet[:12]),self.assertRaises(ValueError):d.parse_answer(packet,HOST,ID)
        with self.assertRaises(ValueError):d.parse_answer(good,'other.invalid',ID)
        with self.assertRaises(ValueError):d.parse_answer(good,HOST,True)
    def test_pointer_loop_header_forward_and_invalid_label_refuse(self):
        for owner in [b'\xc0\x00',b'\xff\xff',b'\x40',b'\x03bad\xc0\x10']:
            with self.subTest(owner=owner),self.assertRaises(ValueError):d.parse_answer(answer([a(owner=owner)]),HOST,ID)
    def test_cname_loop_conflict_unrelated_and_incomplete_refuse(self):
        bad=[[record(b'\xc0\x0c',5,name(HOST))],
             [record(b'\xc0\x0c',5,name('alias.invalid')),a()],
             [record(b'\xc0\x0c',5,name('alias.invalid'))],
             [a(),a('8.8.8.8',owner=name('unrelated.invalid'))],
             [record(b'\xc0\x0c',28,b'\0'*16)],
             [a(ttl=0)],[a(ttl=3601)]]
        for records in bad:
            with self.subTest(records=records),self.assertRaises(ValueError):d.parse_answer(answer(records),HOST,ID)
    def test_explicit_transport_uses_only_numeric_fixed_resolver_and_never_host_lookup(self):
        stream=MagicMock();stream.__enter__.return_value=stream;stream.recv.return_value=answer([a()])
        with patch.object(socket,'socket',return_value=stream) as create, \
             patch.object(socket,'getaddrinfo',side_effect=AssertionError('host resolver')), \
             patch.object(d.secrets,'randbelow',return_value=ID):
            result=d.resolve_a(HOST,time.monotonic_ns()+10**9)
        create.assert_called_once_with(socket.AF_INET,socket.SOCK_DGRAM)
        stream.connect.assert_called_once_with(('9.9.9.9',53));stream.send.assert_called_once_with(d.question(HOST,ID))
        self.assertEqual(result['resolver_ipv4'],'9.9.9.9')
    def test_actual_application_offline_policy_denies_before_socket(self):
        from paw.core.network_policy import offline_policy,EgressDenied
        with offline_policy(),self.assertRaises(EgressDenied):d.resolve_a(HOST,time.monotonic_ns()+10**9)

if __name__=='__main__':unittest.main()

