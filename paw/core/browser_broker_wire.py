"""Bounded private-pipe framing; no network, subprocess or authority.

Descriptors must be established by the future trusted runtime. Passing this
decoder a stream establishes neither peer identity nor a protected Root grant.
Only data crosses it: canonical JSON metadata plus a separately bounded body.
"""
import hashlib
import json
import re
import struct

HEADER_MAX=65536
BODY_MAX=4*1024**2
WIRE_MAX=8*1024**2
FRAME_MAX=128


def require(value,reason):
    if not value:raise ValueError(reason)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _pairs(rows):
    result={}
    for key,value in rows:
        require(key not in result,'wire_duplicate_key');result[key]=value
    return result


def _constant(value):raise ValueError('wire_nonfinite')


def metadata(raw):
    try:value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=_constant)
    except (ValueError,TypeError,UnicodeError,RecursionError) as error:raise ValueError('wire_json') from error
    require(type(value) is dict and canonical(value)==raw,'wire_canonical_object')
    return value


def frame(nonce,sequence,kind,fields,body=b''):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and
        type(sequence) is int and 0<=sequence<FRAME_MAX and
        type(kind) is str and kind in {'dns','http','reply','refusal','stop'} and
        type(fields) is dict and type(body) is bytes and len(body)<=BODY_MAX,'wire_envelope')
    require(kind=='reply' or not body,'wire_body_operation')
    header={'nonce':nonce,'sequence':sequence,'kind':kind,'fields':fields,
            'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()}
    raw=canonical(header);require(len(raw)<=HEADER_MAX,'wire_header_budget')
    return struct.pack('!II',len(raw),len(body))+raw+body


class Decoder:
    def __init__(self,nonce,*,body_budget=BODY_MAX):
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and
                type(body_budget) is int and 0<=body_budget<=BODY_MAX,'wire_session')
        self.nonce=nonce;self.next=0;self.used=0;self.body_used=0;self.body_budget=body_budget
        self.buffer=bytearray();self.closed=False;self.header=None;self.body_size=None

    def feed(self,raw):
        require(not self.closed,'wire_closed')
        try:
            require(type(raw) is bytes and len(raw)<=65536 and self.used+len(raw)<=WIRE_MAX,'wire_input_budget')
            self.used+=len(raw);self.buffer.extend(raw);result=[]
            while True:
                if self.header is None:
                    if len(self.buffer)<8:break
                    header_size,body_size=struct.unpack('!II',self.buffer[:8])
                    require(1<=header_size<=HEADER_MAX and body_size<=self.body_budget-self.body_used and
                            self.next<FRAME_MAX,'wire_declared_budget')
                    if len(self.buffer)<8+header_size:break
                    header=metadata(bytes(self.buffer[8:8+header_size]))
                    require(set(header)=={'nonce','sequence','kind','fields','body_bytes','body_sha256'} and
                        header['nonce']==self.nonce and type(header['sequence']) is int and
                        header['sequence']==self.next and header['kind'] in {'dns','http','reply','refusal','stop'} and
                        type(header['fields']) is dict and type(header['body_bytes']) is int and
                        header['body_bytes']==body_size and type(header['body_sha256']) is str and
                        re.fullmatch('[0-9a-f]{64}',header['body_sha256']) and
                        (header['kind']=='reply' or body_size==0),'wire_identity_or_shape')
                    del self.buffer[:8+header_size];self.header=header;self.body_size=body_size
                if len(self.buffer)<self.body_size:break
                body=bytes(self.buffer[:self.body_size]);del self.buffer[:self.body_size]
                require(hashlib.sha256(body).hexdigest()==self.header['body_sha256'],'wire_body_digest')
                result.append((self.header,body));self.next+=1;self.body_used+=self.body_size
                self.header=None;self.body_size=None
            return result
        except (ValueError,TypeError,KeyError,OverflowError,RecursionError):
            self.closed=True;self.buffer.clear();self.header=None;raise ValueError('wire_protocol_closed')

    def eof(self):
        if self.buffer or self.header is not None:
            self.closed=True;self.buffer.clear();self.header=None;raise ValueError('wire_truncated')
        self.closed=True

