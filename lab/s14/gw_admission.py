"""Finite offline-gateway URL/DNS admission; live transport is unavailable."""
import ipaddress
import json
import math
import re
import secrets
import socket
import struct
import urllib.parse

FIXTURE_IP = '198.18.40.10'
HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z')

class Refused(ValueError):
    pass

def strict_json(value):
    def pairs(items):
        result={}
        for key,item in items:
            require(key not in result,'duplicate_json_key');result[key]=item
        return result
    def constant(_):raise Refused('nonfinite_json')
    def finite(value):
        number=float(value);require(math.isfinite(number),'nonfinite_json');return number
    return json.loads(value,object_pairs_hook=pairs,parse_constant=constant,parse_float=finite)

def require(condition, reason):
    if not condition: raise Refused(reason)

def public_ipv4(value):
    try: address = ipaddress.ip_address(value)
    except ValueError: return False
    return (address.version == 4 and address.is_global and not address.is_multicast
            and not address.is_reserved and not address.is_unspecified)

def admit_url(value, allowed_hosts):
    require(type(value) is str and 0 < len(value) <= 2048, 'url_size_or_type')
    require(not any(ord(c) <= 32 or ord(c) >= 127 for c in value), 'url_non_ascii_or_control')
    require('\\' not in value and not re.search(r'%0[ad]', value, re.I), 'url_ambiguous_separator')
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error: raise Refused('url_parse') from error
    require(parsed.scheme in {'http','https'} and parsed.netloc and host, 'scheme_or_host')
    require(parsed.username is None and parsed.password is None and not parsed.fragment, 'userinfo_or_fragment')
    require('%' not in parsed.netloc and '[' not in parsed.netloc and '@' not in parsed.netloc, 'encoded_or_literal_host')
    require(HOST.fullmatch(host) is not None and not host.endswith('.'), 'host_grammar')
    require(host in allowed_hosts, 'host_not_admitted')
    require(port == (18080 if parsed.scheme == 'http' else 8443), 'port_not_admitted')
    path = parsed.path or '/'
    if parsed.query: path += '?' + parsed.query
    return {'scheme': parsed.scheme, 'host': host, 'port': port, 'path': path,
            'url': urllib.parse.urlunsplit((parsed.scheme, f'{host}:{port}', parsed.path or '/', parsed.query, ''))}

def admit_addresses(values, mode):
    require(mode == 'offline-fixture', 'live_transport_unavailable')
    require(type(values) is list and 0 < len(values) <= 8, 'dns_address_count')
    for value in values:
        try: address = ipaddress.ip_address(value)
        except (ValueError,TypeError) as error: raise Refused('dns_address_parse') from error
        require(address.version == 4 and str(address) == FIXTURE_IP, 'dns_forbidden_address')
    return FIXTURE_IP

def encode_name(name):
    require(type(name) is str and len(name) <= 253 and HOST.fullmatch(name), 'dns_name')
    return b''.join(bytes([len(label)])+label.encode('ascii') for label in name.split('.'))+b'\0'

def decode_name(data, offset):
    labels=[]; cursor=offset; end=None; visited=set()
    for _ in range(32):
        require(cursor < len(data) and cursor not in visited, 'dns_name_bounds_or_loop')
        visited.add(cursor); length=data[cursor];cursor+=1
        if length == 0: return '.'.join(labels).lower(), end if end is not None else cursor
        if length & 0xc0 == 0xc0:
            require(cursor < len(data), 'dns_pointer_bounds')
            target=((length&0x3f)<<8)|data[cursor]
            if end is None:end=cursor+1
            cursor=target;continue
        require(length <= 63 and cursor+length <= len(data), 'dns_label_bounds')
        try:label=data[cursor:cursor+length].decode('ascii')
        except UnicodeError as error:raise Refused('dns_label_encoding') from error
        labels.append(label);cursor+=length
    raise Refused('dns_name_depth')

def question(data):
    require(12 <= len(data) <= 512, 'dns_wire_size')
    ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',data)
    require(qd == 1, 'dns_question_count')
    name,end=decode_name(data,12)
    require(end+4 <= len(data), 'dns_question_bounds')
    kind,cls=struct.unpack_from('!HH',data,end)
    require(cls == 1 and kind in {1,28}, 'dns_question_type')
    return ident,flags,name,kind,end+4

def dns_lookup(name, timeout=1):
    ident=secrets.randbelow(65536)
    query=struct.pack('!6H',ident,0x100,1,0,0,0)+encode_name(name)+b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(timeout);client.connect((FIXTURE_IP,5353));client.send(query);data=client.recv(513)
    received,flags,got_name,kind,end=question(data)
    require(received == ident and got_name == name and kind == 1, 'dns_reply_identity')
    require(flags&0x8000 and not flags&0x0200 and flags&15 == 0, 'dns_reply_status')
    an=struct.unpack_from('!H',data,6)[0]
    require(0 < an <= 8, 'dns_answer_count')
    values=[]
    for _ in range(an):
        owner,end=decode_name(data,end)
        require(end+10 <= len(data), 'dns_answer_bounds')
        typ,cls,ttl,size=struct.unpack_from('!HHIH',data,end);end+=10
        require(owner == name and typ == 1 and cls == 1 and size == 4 and end+4 <= len(data),'dns_answer_type')
        values.append(socket.inet_ntoa(data[end:end+4]));end+=4
    require(end == len(data), 'dns_trailing_or_unsupported_records')
    return values

def dns_response(query, values=None, refused=False):
    ident,flags,name,kind,end=question(query)
    require(not flags&0x8000, 'dns_not_query')
    values=values or []
    if kind == 28:values=[]
    answer=struct.pack('!6H',ident,0x8183 if refused else 0x8180,1,len(values),0,0)+query[12:end]
    for value in values:
        answer+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton(value)
    return answer
