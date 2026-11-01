"""Fixed owned protocol roles in the measured private loopback namespace.

Only immutable Root bootstrap, fixed vacant nonroot identities and fixed owned
hosts/peers. Not a public launcher, real-source grant or caller-selected input.
"""
import hashlib
import re
import struct
import os
import socket
import ssl
import sys
import time
from pathlib import Path
if __package__:
    from . import browser_owned_cdp_guest as fixed,mail_browser_dns as dns
    from . import browser_mediator as mediator,browser_broker_wire as wire
    from . import owned_kernel_runtime as kernel
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import browser_owned_cdp_guest as fixed,mail_browser_dns as dns
    import browser_mediator as mediator,browser_broker_wire as wire
    import owned_kernel_runtime as kernel

HOST='paw-owned.invalid'
ADDRESS=bytes([93,184,216,34])

def require(value,reason):
    if not value:raise ValueError(reason)

def dns_response(raw,mode='public'):
    require(type(raw)is bytes and 12<=len(raw)<=512 and type(mode)is str and
        mode in {'public','private','changed'},'owned_dns_fixture_input')
    ident=struct.unpack('!H',raw[:2])[0]
    require(raw==dns.question(HOST,ident),'owned_dns_fixture_question')
    address=ADDRESS if mode=='public' else bytes([127,0,0,1])if mode=='private' else bytes([93,184,216,35])
    return struct.pack('!6H',ident,0x8180,1,1,0,0)+raw[12:]+b'\xc0\x0c'+struct.pack('!2HIH',1,1,10,4)+address

def http_response(raw,nonce):
    require(type(raw)is bytes and 0<len(raw)<=4096 and raw.endswith(b'\r\n\r\n')and
        type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'owned_http_fixture_input')
    lines=raw[:-4].split(b'\r\n');start=lines.pop(0).split(b' ')
    require(len(start)==3 and start[0]in {b'GET',b'HEAD'}and start[2]==b'HTTP/1.1','owned_http_fixture_method')
    headers={}
    for line in lines:
        require(b':'in line,'owned_http_fixture_header');name,value=line.split(b':',1);name=name.lower()
        require(name not in headers and name in {b'host',b'user-agent',b'accept',b'accept-encoding',b'connection'},
            'owned_http_fixture_header_policy')
        headers[name]=value.strip()
    require(headers.get(b'host')==HOST.encode() and b'\x00'not in raw,'owned_http_fixture_host')
    path=start[1];status=200;reason='OK';extra=[]
    if path in {b'/',b'/owned-data'}:
        meta,body=fixed.fixture(nonce,{'nonce':nonce,'seq':0,'url':fixed.SEED+path[1:].decode(),
            'method':'GET','resource':'Document'if path==b'/'else'Fetch'})
        if path==b'/':
            # This owned fixture needs the document and its scripted Fetch.
            # Suppress Chrome's unrelated implicit favicon HTTP/TLS exchange
            # so it cannot consume the remaining fixed browser/lease window.
            body=body.replace(b'<title>',b'<link rel="icon" href="data:,"><title>',1)
        content=next(v['value']for v in meta['headers']if v['name']=='Content-Type')
    elif path in {b'/redirect',b'/loop'}:
        status=302;reason='Found';body=b'';content='text/plain'
        extra=[('Location','/'if path==b'/redirect'else'/loop')]
    elif path==b'/overflow':body=b'x'*(4*1024**2+1);content='application/octet-stream'
    elif path==b'/favicon.ico':
        # A browser may probe this fixed icon after the document loads. An
        # empty valid HTTP response must not masquerade as transport loss.
        status=404;reason='Not Found';body=b'';content='image/x-icon'
    else:raise ValueError('owned_http_fixture_unknown_path')
    header=('HTTP/1.1 '+str(status)+' '+reason+'\r\nContent-Type: '+content+
        '\r\nContent-Length: '+str(len(body))+'\r\nConnection: close\r\n'+
        'Set-Cookie: owned=must-be-filtered\r\n'+''.join(k+': '+v+'\r\n'for k,v in extra)+'\r\n').encode('ascii')
    result=header+(b''if start[0]==b'HEAD'else body)
    return result,{'http_status':status,'resource_bytes':len(body),'sent_body_bytes':0 if start[0]==b'HEAD'else len(body),
        'body_sha256':hashlib.sha256(body).hexdigest(),'method':start[0].decode(),'owned_path':path.decode()}


class Server:
    """Owned fixture I/O on prebound descriptors; no bind/Root entry or URLs.

    Only the immutable launcher may supply its three fixed namespace
    sockets and fixed owned-only SSL context. Ordinary tests use loopback.
    """
    def __init__(self,nonce,sockets,tls_context,deadline_ns,*,dns_mode='public'):
        import time
        require(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce) and
            type(sockets)is dict and set(sockets)=={'dns','http','https'} and
            type(deadline_ns)is int and time.monotonic_ns()<deadline_ns<=time.monotonic_ns()+8*10**9 and
            dns_mode in {'public','private','changed'},'owned_fixture_server_config')
        self.nonce=nonce;self.sockets=sockets;self.context=tls_context
        self.deadline=deadline_ns;self.mode=dns_mode;self.closed=False
        self.counts={'dns':0,'http':0,'https':0,'refused':0,'sent_bytes':0}

    def run(self):
        import selectors,socket,time,ssl
        selected=selectors.DefaultSelector()
        for name,stream in self.sockets.items():
            stream.setblocking(False);selected.register(stream,selectors.EVENT_READ,name)
        operations=0
        try:
            while not self.closed and operations<66 and time.monotonic_ns()<self.deadline:
                for key,_ in selected.select(.03):
                    if operations>=66 or self.closed:break
                    operations+=1
                    try:
                        if key.data=='dns':
                            raw,peer=key.fileobj.recvfrom(513)
                            response=dns_response(raw,self.mode)
                            self.counts['dns']+=1;key.fileobj.sendto(response,peer)
                            self.counts['sent_bytes']+=len(response)
                            continue
                        stream,_=key.fileobj.accept()
                        with stream:
                            stream.settimeout(min(.5,max(.001,(self.deadline-time.monotonic_ns())/10**9)))
                            if key.data=='https':
                                stream=self.context.wrap_socket(stream,server_side=True)
                            try:
                                raw=bytearray()
                                while not raw.endswith(b'\r\n\r\n'):
                                    piece=stream.recv(min(1024,4097-len(raw)))
                                    require(piece and len(raw)+len(piece)<=4096,'owned_fixture_request_budget')
                                    raw.extend(piece)
                                response,_=http_response(bytes(raw),self.nonce)
                                require(self.counts['sent_bytes']+len(response)<=8*1024**2,
                                        'owned_fixture_aggregate_body_budget')
                                self.counts[key.data]+=1
                                stream.sendall(response);self.counts['sent_bytes']+=len(response)
                            finally:
                                if key.data=='https':stream.close()
                    except (OSError,ValueError,ssl.SSLError):self.counts['refused']+=1
        finally:
            selected.close()
            for stream in self.sockets.values():stream.close()
            self.closed=True


class OwnedTransport:
    def __init__(self,nonce,deadline_ns,dns_transport,http_transport):
        require(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce) and
            type(deadline_ns)is int and time.monotonic_ns()<deadline_ns<=time.monotonic_ns()+10*10**9,
            'owned_transport_session')
        self.nonce=nonce;self.deadline=deadline_ns;self.dns=dns_transport;self.http=http_transport
        self.next=0;self.received=0;self.closed=False

    def dispatch(self,nonce,sequence,kind,fields,body=b''):
        require(not self.closed,'owned_transport_closed')
        try:
            require(nonce==self.nonce and type(sequence)is int and sequence==self.next and self.next<66 and
                kind in {'dns','http','stop'} and type(fields)is dict and body==b'' and type(body)is bytes and
                time.monotonic_ns()<self.deadline,'owned_transport_envelope')
            self.next+=1
            if kind=='stop':
                require(not fields,'owned_transport_stop_shape');self.closed=True
                return {'request_sequence':sequence,'operation':'stop','stopped':True},b''
            if kind=='dns':
                require(set(fields)=={'host','ident','deadline_ns'}and fields['host']==HOST and
                    type(fields['ident'])is int and 0<=fields['ident']<=65535 and
                    type(fields['deadline_ns'])is int and time.monotonic_ns()<fields['deadline_ns']<=self.deadline,
                    'owned_transport_dns_shape')
                raw=self.dns(HOST,fields['ident'],fields['deadline_ns'])
                require(type(raw)is bytes and 12<=len(raw)<=4096,'owned_transport_dns_bytes')
                self.received+=len(raw);require(self.received<=4*1024**2,'owned_transport_body_budget')
                return {'request_sequence':sequence,'operation':'dns','host':HOST,'ident':fields['ident'],
                        'received_ns':time.monotonic_ns()},raw
            require(set(fields)=={'plan','remaining_bytes'}and type(fields['plan'])is dict and
                type(fields['remaining_bytes'])is int and 0<=fields['remaining_bytes']<=4*1024**2,
                'owned_transport_http_shape')
            plan=fields['plan'];target=mediator.endpoint(plan.get('url'))
            require(target['host']==HOST and plan.get('nonce')==self.nonce and
                plan.get('peer_ipv4')=='93.184.216.34' and plan.get('all_ipv4')==['93.184.216.34'] and
                type(plan.get('expires_ns'))is int and plan['expires_ns']<=self.deadline,
                'owned_transport_fixed_peer')
            allowance=min(fields['remaining_bytes'],4*1024**2-self.received)
            metadata,raw=self.http(plan,allowance)
            require(type(metadata)is dict and type(raw)is bytes and len(raw)<=allowance and
                metadata.get('body_bytes')==len(raw) and metadata.get('body_sha256')==hashlib.sha256(raw).hexdigest(),
                'owned_transport_http_bytes')
            self.received+=len(raw)
            return {'request_sequence':sequence,'operation':'http','transport':metadata},raw
        except Exception:
            self.closed=True
            raise


def dns_bytes(host,ident,deadline_ns):
    require(host==HOST and type(deadline_ns)is int and deadline_ns>time.monotonic_ns(),
            'owned_protocol_dns_deadline')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as stream:
        stream.settimeout(min(1,(deadline_ns-time.monotonic_ns())/10**9))
        stream.connect(dns.RESOLVER);stream.send(dns.question(host,ident));raw=stream.recv(4097)
    require(time.monotonic_ns()<deadline_ns,'owned_protocol_dns_expired')
    return raw


def write_frame(raw):
    view=memoryview(raw)
    while view:
        count=os.write(1,view);require(count>0,'owned_protocol_closed_output');view=view[count:]


def transport_main(job,epoch,release):
    kernel.role_entry(job,epoch,release,'probe')
    witness=kernel.status()
    require(all(int(witness[k],16)==0 for k in ['cap_eff','cap_prm','cap_inh','cap_amb']),
            'owned_protocol_transport_privilege')
    kernel.emit({'ready':True,'role':'probe','witness':witness})
    session=OwnedTransport(epoch,time.monotonic_ns()+8*10**9,dns_bytes,mediator.transport_response)
    decoder=wire.Decoder(epoch,body_budget=0);written=0
    while not session.closed:
        raw=os.read(0,32768)
        if not raw:decoder.eof();return
        for header,body in decoder.feed(raw):
            require(header['kind']in {'dns','http','stop'},'owned_protocol_request_kind')
            fields,response=session.dispatch(header['nonce'],header['sequence'],header['kind'],header['fields'],body)
            encoded=wire.frame(epoch,header['sequence'],'reply',fields,response)
            written+=len(encoded);require(written<=wire.WIRE_MAX,'owned_protocol_output_budget')
            write_frame(encoded)


def fixture_main(job,epoch,release):
    kernel.role_entry(job,epoch,release,'fixture');sockets={}
    try:
        for name,address,port in [('dns','9.9.9.9',53),('http','93.184.216.34',80),
                                  ('https','93.184.216.34',443)]:
            stream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if name=='dns'else socket.SOCK_STREAM)
            sockets[name]=stream;stream.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            stream.bind((address,port))
            if name!='dns':stream.listen(4)
        kernel.capabilities(0);witness=kernel.status()
        require(all(int(witness[k],16)==0 for k in ['cap_eff','cap_prm','cap_inh','cap_amb']),
                'owned_protocol_fixture_privilege')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('/etc/paw-owned-cert.pem','/etc/paw-owned-key.pem')
        server=Server(epoch,sockets,context,time.monotonic_ns()+8*10**9)
        kernel.emit({'ready':True,'role':'fixture','witness':witness})
        server.run()
    finally:
        for stream in sockets.values():stream.close()


def main():
    require(os.geteuid()==0 and Path(__file__).resolve()==Path('/opt/paw-code/browser_owned_protocol.py') and
        len(sys.argv)==5 and sys.argv[1]in {'--fixture','--probe'},'owned_protocol_fixed_entry')
    {'--fixture':fixture_main,'--probe':transport_main}[sys.argv[1]](*sys.argv[2:])


if __name__=='__main__':main()
