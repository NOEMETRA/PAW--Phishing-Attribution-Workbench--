import hashlib
import json
import os
import struct
import unittest

from paw.core import browser_broker_wire as w

N='a'*32

class Wire(unittest.TestCase):
    def test_actual_owned_os_pipe_roundtrip_with_fragmented_binary_body(self):
        read_fd,write_fd=os.pipe();body=b'owned\0data'*65536
        raw=w.frame(N,0,'reply',{'scope':'owned OS pipe only'},body);d=w.Decoder(N);out=[]
        try:
            for offset in range(0,len(raw),997):
                part=memoryview(raw[offset:offset+997])
                while part:
                    count=os.write(write_fd,part);part=part[count:]
                    out.extend(d.feed(os.read(read_fd,count)))
            os.close(write_fd);write_fd=None;self.assertEqual(os.read(read_fd,1),b'');d.eof()
        finally:
            os.close(read_fd)
            if write_fd is not None:os.close(write_fd)
        self.assertEqual(len(out),1);self.assertEqual(out[0][1],body)

    def test_fragmented_maximum_body_and_metadata_have_separate_limits(self):
        body=b'owned\0'*(w.BODY_MAX//6)+b'x'*(w.BODY_MAX%6)
        raw=w.frame(N,0,'reply',{'status':200},body);d=w.Decoder(N);out=[]
        for offset in range(0,len(raw),65536):out.extend(d.feed(raw[offset:offset+65536]))
        self.assertEqual(len(out),1);self.assertEqual(out[0][1],body);self.assertEqual(d.body_used,w.BODY_MAX)
        d.eof();self.assertTrue(d.closed)

    def test_stream_order_replay_wrong_nonce_and_bool_identity_close_session(self):
        for nonce,seq in [('b'*32,0),(N,1),(N,False)]:
            header={'nonce':nonce,'sequence':seq,'kind':'dns','fields':{},'body_bytes':0,
                    'body_sha256':hashlib.sha256(b'').hexdigest()};raw=w.canonical(header)
            d=w.Decoder(N)
            with self.subTest(nonce=nonce,seq=seq),self.assertRaises(ValueError):d.feed(struct.pack('!II',len(raw),0)+raw)
            self.assertTrue(d.closed)
        d=w.Decoder(N);raw=w.frame(N,0,'dns',{});d.feed(raw)
        with self.assertRaises(ValueError):d.feed(raw)

    def test_declarations_refuse_before_any_body_allocation(self):
        for header,body in [(w.HEADER_MAX+1,0),(1,w.BODY_MAX+1),(0,0)]:
            d=w.Decoder(N)
            with self.assertRaises(ValueError):d.feed(struct.pack('!II',header,body))
            self.assertEqual(d.buffer,b'');self.assertTrue(d.closed)

    def test_aggregate_body_budget_and_digest_do_not_reset_between_frames(self):
        d=w.Decoder(N,body_budget=3);d.feed(w.frame(N,0,'reply',{},b'abc'))
        with self.assertRaises(ValueError):d.feed(w.frame(N,1,'reply',{},b'd'))
        d=w.Decoder(N);raw=w.frame(N,0,'reply',{},b'abc')
        with self.assertRaises(ValueError):d.feed(raw[:-1]+b'd')

    def test_truncated_header_and_body_are_not_complete_messages(self):
        raw=w.frame(N,0,'reply',{},b'abc')
        for cut in [1,7,9,len(raw)-1]:
            d=w.Decoder(N);self.assertEqual(d.feed(raw[:cut]),[])
            with self.assertRaises(ValueError):d.eof()
            self.assertTrue(d.closed)

    def test_duplicate_noncanonical_nonfinite_and_nested_unknown_metadata_refuse(self):
        for raw in [b'{"x":1,"x":2}',b'{ "x":1}',b'{"x":NaN}',b'['*1200+b']'*1200]:
            d=w.Decoder(N)
            with self.assertRaises(ValueError):d.feed(struct.pack('!II',len(raw),0)+raw)
        h=json.loads(w.frame(N,0,'dns',{})[8:]);h['unexpected']=True;raw=w.canonical(h)
        with self.assertRaises(ValueError):w.Decoder(N).feed(struct.pack('!II',len(raw),0)+raw)

    def test_requests_cannot_carry_response_body_or_unknown_operation(self):
        for kind in ['dns','http','refusal','stop','shell']:
            with self.subTest(kind=kind),self.assertRaises(ValueError):w.frame(N,0,kind,{},b'x')

    def test_multiple_frames_and_finite_message_count(self):
        d=w.Decoder(N);raw=b''.join(w.frame(N,i,'dns',{'host':'owned.example'}) for i in range(w.FRAME_MAX))
        out=d.feed(raw);self.assertEqual(len(out),w.FRAME_MAX)
        raw=w.frame(N,0,'stop',{})
        with self.assertRaises(ValueError):d.feed(raw)

if __name__=='__main__':unittest.main()

