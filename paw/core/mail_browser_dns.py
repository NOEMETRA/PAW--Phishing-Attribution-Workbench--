"""Bounded A/CNAME DNS codec and explicit fixed-resolver transport.

Codec operations are inert. resolve_a is explicit UDP transport for a future
confined broker only; no host CLI/API uses it. Development tests never call the
public resolver. Answers establish observations, never DNSSEC/authentic origin.
"""
import ipaddress
import secrets
import socket
import struct
import time

if __package__:
    from .browser_mediator import endpoint,public_answers
else:
    from browser_mediator import endpoint,public_answers

RESOLVER=('9.9.9.9',53)


def require(value,reason):
    if not value:raise ValueError(reason)


def host_name(host):
    require(type(host) is str and endpoint('https://'+host+'/')['host']==host,'dns_host')
    return host


def question(host,ident):
    host_name(host);require(type(ident) is int and 0<=ident<=65535,'dns_transaction')
    labels=host.encode('ascii').split(b'.')
    name=b''.join(bytes([len(label)])+label for label in labels)+b'\0'
    return struct.pack('!6H',ident,0x0100,1,0,0,0)+name+struct.pack('!2H',1,1)


def _name(raw,offset):
    labels=[];end=None;seen=set();expanded=0
    while True:
        require(12<=offset<len(raw) and offset not in seen and len(seen)<128,'dns_name_pointer')
        seen.add(offset);size=raw[offset]
        if size==0:return '.'.join(labels),offset+1 if end is None else end
        if size&0xc0==0xc0:
            require(offset+1<len(raw),'dns_pointer_truncated')
            target=((size&0x3f)<<8)|raw[offset+1]
            require(12<=target<offset,'dns_forward_or_header_pointer')
            if end is None:end=offset+2
            offset=target;continue
        require(size&0xc0==0 and 1<=size<=63 and offset+size<len(raw),'dns_label_size')
        try:label=raw[offset+1:offset+1+size].decode('ascii').lower()
        except UnicodeDecodeError as error:raise ValueError('dns_label_ascii') from error
        labels.append(label);expanded+=size+1;require(expanded<=254,'dns_name_length')
        offset+=size+1


def parse_answer(raw,host,ident):
    host_name(host)
    require(type(ident) is int and 0<=ident<=65535,'dns_transaction')
    require(type(raw) is bytes and 12<=len(raw)<=4096,'dns_packet_budget')
    tid,flags,qd,an,ns,ar=struct.unpack('!6H',raw[:12])
    require(tid==ident and flags&0x8000 and not flags&0x7800 and not flags&0x0200 and
        not flags&0x0040 and flags&15==0 and qd==1 and 1<=an<=16 and ns==ar==0,
        'dns_response_shape_or_unavailable')
    name,cursor=_name(raw,12)
    require(cursor+4<=len(raw) and name==host and raw[cursor:cursor+4]==b'\0\1\0\1','dns_question_binding')
    cursor+=4;addresses={};aliases={};ttls=[];owners=set()
    for _ in range(an):
        owner,cursor=_name(raw,cursor);host_name(owner)
        require(cursor+10<=len(raw),'dns_rr_header')
        kind,cls,ttl,size=struct.unpack('!2HIH',raw[cursor:cursor+10]);cursor+=10
        require(cls==1 and 0<ttl<=3600 and cursor+size<=len(raw),'dns_rr_class_ttl_size')
        owners.add(owner);ttls.append(ttl)
        if kind==1:
            require(size==4,'dns_a_size')
            addresses.setdefault(owner,[]).append(str(ipaddress.IPv4Address(raw[cursor:cursor+4])))
        elif kind==5:
            target,after=_name(raw,cursor);host_name(target)
            require(after==cursor+size and owner not in aliases,'dns_cname_size_or_duplicate')
            aliases[owner]=target
        else:raise ValueError('dns_unsupported_record')
        cursor+=size
    require(cursor==len(raw) and not set(aliases).intersection(addresses),'dns_trailing_or_ambiguous')
    visited=set();current=host
    while current in aliases:
        require(current not in visited and len(visited)<8,'dns_cname_loop_or_depth')
        visited.add(current);current=aliases[current]
    visited.add(current)
    require(owners<=visited and current in addresses,'dns_unrelated_or_incomplete_answer')
    # Reject every supplied A in the finite answer, not only the chosen peer.
    all_addresses=[ip for rows in addresses.values() for ip in rows]
    pins=public_answers(all_addresses)
    require(pins==sorted(addresses[current]),'dns_nonterminal_addresses')
    return {'answers':pins,'ttl_ns':min(ttls)*10**9,'canonical_name':current,
            'dnssec':'not established by this UDP observation'}


def resolve_a(host,deadline_ns):
    """One connected UDP query, no host resolver/search/proxy/retry/TCP fallback.

    A trusted runtime must first consume its request slot and establish its fixed
    resolver-only kernel lease. Deadline and the enclosing job are monotonic.
    Never invoke this on development-host sample domains.
    """
    require(type(deadline_ns) is int and deadline_ns>time.monotonic_ns(),'dns_deadline')
    ident=secrets.randbelow(65536);wire=question(host,ident)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
        stream.settimeout(min(1,(deadline_ns-time.monotonic_ns())/10**9))
        stream.connect(RESOLVER);stream.send(wire);raw=stream.recv(4097)
    observed=time.monotonic_ns();require(observed<deadline_ns,'dns_expired_response')
    return {**parse_answer(raw,host,ident),'observed_ns':observed,'resolver_ipv4':RESOLVER[0]}

