"""Bounded accounting and HTTP transport for a future no-NIC browser broker.

Import and ledger operations have no network effects. exchange() is an explicit
numeric-pin HTTP(S) transport; it is not wired to the CLI, API or Root operator.
It creates no approval/grant or OS confinement. A trusted caller must establish
protected authority, real DNS facts and kernel isolation before invoking it.
"""
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
import urllib.parse

LIMITS = {'requests': 32, 'hosts': 8, 'redirects': 5, 'bytes': 4*1024**2,
          'seconds': 15, 'lease_seconds': 5, 'header_bytes': 32768}
DENIED = tuple(ipaddress.ip_network(x) for x in (
    '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8',
    '169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24',
    '192.88.99.0/24','192.168.0.0/16','198.18.0.0/15',
    '198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4'))
HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z')
RESOURCES = {'Document','Stylesheet','Image','Media','Font','Script','XHR','Fetch','Other'}
TRUST_FILE = '/etc/ssl/certs/ca-certificates.crt'


def require(condition, reason):
    if not condition: raise ValueError(reason)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


def endpoint(url):
    require(type(url) is str and 0<len(url)<=2048 and all(33<=ord(c)<127 for c in url)
            and '\\' not in url, 'broker_url_bytes')
    try:
        p=urllib.parse.urlsplit(url);port=p.port;host=p.hostname
    except ValueError as e:raise ValueError('broker_url_parse') from e
    require(p.scheme in {'http','https'} and host and len(host)<=253 and HOST.fullmatch(host)
            and host.rsplit('.',1)[-1][0].isalpha(), 'broker_url_host')
    require(p.username is p.password is None and not p.fragment and '#' not in url
            and '%' not in p.netloc and '[' not in p.netloc,'broker_url_authority')
    default=443 if p.scheme=='https' else 80
    require(p.netloc in {host,host+':'+str(default)} and port in {None,default},'broker_url_port')
    return {'url':url,'scheme':p.scheme,'host':host,'port':default,
            'url_sha256':hashlib.sha256(url.encode('ascii')).hexdigest()}


def public_answers(values):
    require(type(values) is list and 1<=len(values)<=4 and all(type(v) is str for v in values)
            and len(set(values))==len(values),'broker_dns_shape')
    for value in values:
        try:address=ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as e:raise ValueError('broker_dns_ipv4') from e
        require(str(address)==value and not any(address in n for n in DENIED),'broker_dns_special')
    return sorted(values)


def response_headers(rows):
    require(type(rows) is list and len(rows)<=64,'broker_header_count')
    result=[];size=0;lengths=[];locations=[];hop=set()
    for row in rows:
        require(type(row) is list and len(row)==2 and all(type(v) is str for v in row),'broker_header_shape')
        name,value=row;size+=len(name.encode('utf-8'))+len(value.encode('utf-8'))
        require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}",name) and
                len(value)<=8192 and not any(ord(c)<32 and c!='\t' or ord(c)==127 for c in value)
                and size<=LIMITS['header_bytes'],'broker_header_bytes')
        key=name.lower()
        if key=='connection':
            tokens=value.lower().split(',')
            require(all(re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+",t.strip()) for t in tokens),
                    'broker_connection_tokens')
            hop.update(t.strip() for t in tokens)
        if key=='content-length':lengths.append(value)
        if key=='location':locations.append(value)
        if key=='content-encoding':require(value.strip().lower()=='identity','broker_encoding')
        if key in {'connection','proxy-connection','keep-alive','transfer-encoding','te','trailer',
                   'upgrade','set-cookie','set-cookie2','www-authenticate','proxy-authenticate',
                   'content-length'}:continue
        result.append({'name':name,'value':value})
    # Connection can name a header appearing earlier in the response.
    # Do not let it strip security/framing fields before they are validated.
    require(not hop.intersection({'content-length','transfer-encoding','content-encoding',
                                  'location','content-security-policy'}),'broker_connection_framing')
    result=[row for row in result if row['name'].lower() not in hop]
    require(len(lengths)<=1 and all(re.fullmatch('[0-9]{1,10}',v) for v in lengths),
            'broker_content_length')
    require(len(locations)<=1,'broker_ambiguous_location')
    # Deliberate browser observation restriction, not a network/OS claim.
    result.append({'name':'Content-Security-Policy','value':"form-action 'none'; object-src 'none'"})
    return result, None if not lengths else int(lengths[0]), locations


class BrowserRequestLedger:
    """One sequential, bounded data ledger; not an execution-authority object.

    A privileged runtime must first independently verify source/case/URL bytes,
    protected per-hash approval and a fresh tested context. DNS facts passed to
    admit() must be collected by its trusted resolver, never supplied by a page.
    Public-host discovery is permitted only when that approved policy says so.
    """
    def __init__(self,seed_url,nonce,started_ns,*,allow_dynamic_public_hosts=False):
        seed=endpoint(seed_url)
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'broker_nonce')
        require(type(started_ns) is int and started_ns>=0,'broker_start_time')
        require(type(allow_dynamic_public_hosts) is bool,'broker_host_policy')
        self.seed=seed;self.nonce=nonce;self.started_ns=started_ns
        self.deadline_ns=started_ns+LIMITS['seconds']*10**9
        self.dynamic=allow_dynamic_public_hosts;self.used=0;self.received=0;self.redirects=0
        self.pins={};self._pending=None;self._key=secrets.token_bytes(32);self.closed=False
        self.seed_admitted=False

    def _time(self,now_ns):
        require(type(now_ns) is int and self.started_ns<=now_ns<self.deadline_ns,
                'broker_session_expired')
        require(not self.closed,'broker_session_closed')

    def admit(self,frame,answers,age_ns,ttl_ns,now_ns):
        self._time(now_ns);require(self._pending is None,'broker_pending_request')
        require(self.used<LIMITS['requests'],'broker_request_budget')
        require(type(frame) is dict and set(frame)=={'nonce','seq','url','method','resource'},'broker_frame_shape')
        require(frame['nonce']==self.nonce and type(frame['seq']) is int and frame['seq']==self.used,
                'broker_frame_identity')
        slot=self.used;self.used+=1  # Refused requests still consume work budget.
        require(type(frame['method']) is str and frame['method'] in {'GET','HEAD'} and
                type(frame['resource']) is str and frame['resource'] in RESOURCES,'broker_method_or_resource')
        target=endpoint(frame['url'])
        if not self.seed_admitted:
            require(frame['url']==self.seed['url'] and frame['method']=='GET' and
                    frame['resource']=='Document','broker_initial_seed')
        if not self.dynamic:require(target['host']==self.seed['host'],'broker_unregistered_host')
        pins=public_answers(answers)
        require(type(age_ns) is int and type(ttl_ns) is int and
                0<=age_ns<min(ttl_ns,10*10**9) and 0<ttl_ns<=3600*10**9,
                'broker_stale_dns')
        if target['host'] in self.pins:require(self.pins[target['host']]==pins,'broker_dns_rebinding')
        else:
            require(len(self.pins)<LIMITS['hosts'],'broker_host_budget');self.pins[target['host']]=pins
        deadline=min(self.deadline_ns,now_ns+min(LIMITS['lease_seconds']*10**9,ttl_ns-age_ns))
        require(deadline>now_ns,'broker_lease_expired')
        plan={**target,'method':frame['method'],'slot':slot,'peer_ipv4':pins[0],
              'all_ipv4':pins,'issued_ns':now_ns,'expires_ns':deadline,'nonce':self.nonce}
        token=hmac.new(self._key,canonical(plan),hashlib.sha256).hexdigest()
        plan['lease_id']=token;self._pending=copy.deepcopy(plan);self.seed_admitted=True
        return copy.deepcopy(plan)

    def lease(self,plan,now_ns):
        self._time(now_ns)
        require(type(plan) is dict and self._pending is not None and
                canonical(plan)==canonical(self._pending) and now_ns<plan['expires_ns'],
                'broker_forged_or_expired_lease')
        return copy.deepcopy(self._pending)

    def complete(self,plan,status,headers,body,peer_ipv4,tls_verified,now_ns):
        expected=self.lease(plan,now_ns)
        # Consume the response slot before parsing attacker-controlled bytes.
        self._pending=None
        require(type(body) is bytes,'broker_response_type')
        if self.received+len(body)>LIMITS['bytes']:
            self.received=LIMITS['bytes'];self.closed=True
            raise ValueError('broker_response_budget')
        self.received+=len(body)  # Malformed/failed responses still consume bytes.
        require(type(status) is int and 200<=status<=599,'broker_http_status')
        require(peer_ipv4==expected['peer_ipv4'] and type(tls_verified) is bool and
                tls_verified==(expected['scheme']=='https'),'broker_peer_or_tls')
        filtered,length,locations=response_headers(headers)
        if expected['method']=='HEAD' or status in {204,304}:require(body==b'','broker_unexpected_body')
        elif length is not None:require(length==len(body),'broker_incomplete_body')
        if status in {301,302,303,307,308}:
            self.redirects+=1;require(self.redirects<=LIMITS['redirects'] and locations,
                                      'broker_redirect_budget_or_location')
            # Record/validate only. A following browser request gets new DNS,
            # pin, method, quota and time admission; no automatic fetch here.
            endpoint(urllib.parse.urljoin(expected['url'],locations[0]))
        filtered.append({'name':'Content-Length','value':str(len(body))})
        return {'status':'response','slot':expected['slot'],'http_status':status,
                'headers':filtered,'body_b64':base64.b64encode(body).decode('ascii'),
                'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),
                'peer_ipv4':peer_ipv4,'tls_verified_by_broker':tls_verified,
                'tls_fingerprint_source':'broker, not browser'}

    def fail(self,plan,reason,now_ns):
        require(type(plan) is dict and self._pending is not None and
                canonical(plan)==canonical(self._pending),'broker_failed_request_identity')
        require(type(now_ns) is int and now_ns>=self.started_ns,'broker_failure_time')
        require(type(reason) is str and reason in
                {'timeout','tls','dns','peer','protocol','io','response_budget'},'broker_failure_code')
        self._pending=None
        return {'status':'unavailable','slot':plan['slot'],'reason':reason}

    def close(self):
        self.closed=True;self._pending=None
        return {'requests_consumed':self.used,'response_bytes':self.received,
                'redirect_responses':self.redirects,'public_hosts':len(self.pins),
                'network_stopped':'not established by this inert ledger'}


class _Reader:
    """Finite socket reader with an absolute deadline, including slow headers."""
    def __init__(self, stream, deadline_ns):
        self.stream=stream;self.deadline_ns=deadline_ns;self.buffer=bytearray()

    def receive(self, count):
        remaining=(self.deadline_ns-time.monotonic_ns())/10**9
        require(remaining>0,'broker_transport_expired')
        self.stream.settimeout(remaining)
        return self.stream.recv(count)

    def line(self, limit):
        while True:
            end=self.buffer.find(b'\r\n')
            if end>=0:
                require(end+2<=limit,'broker_http_line_limit')
                value=bytes(self.buffer[:end]);del self.buffer[:end+2];return value
            require(len(self.buffer)<limit,'broker_http_line_limit')
            chunk=self.receive(min(512,limit-len(self.buffer)))
            require(chunk,'broker_http_truncated');self.buffer.extend(chunk)

    def exact(self, count):
        while len(self.buffer)<count:
            chunk=self.receive(min(32768,count-len(self.buffer)))
            require(chunk,'broker_http_truncated');self.buffer.extend(chunk)
        value=bytes(self.buffer[:count]);del self.buffer[:count];return value


def read_http_response(stream, method, remaining_bytes, deadline_ns):
    """Decode one bounded HTTP/1 response, without redirects or content decoding.

    Chunk extensions, trailers, interim responses, ambiguous framing and encoded
    bodies refuse. This limited decoder does not execute or interpret HTML/JS.
    Caller charges received bytes even when subsequent parsing fails.
    """
    require(method in {'GET','HEAD'} and type(remaining_bytes) is int and
            0<=remaining_bytes<=LIMITS['bytes'],'broker_reader_arguments')
    reader=_Reader(stream,deadline_ns);status_line=reader.line(8192)
    match=re.fullmatch(rb'HTTP/1\.[01] ([2-5][0-9]{2})(?: [\x20-\x7e]*)?',status_line)
    require(match,'broker_http_status_line');status=int(match[1]);headers=[];size=len(status_line)+2
    while True:
        line=reader.line(min(8192,LIMITS['header_bytes']-size));size+=len(line)+2
        if not line:break
        require(len(headers)<64 and b':' in line and line[:1] not in b' \t','broker_http_header_line')
        name,value=line.split(b':',1)
        try:headers.append([name.decode('ascii'),value.strip(b' \t').decode('latin-1')])
        except UnicodeDecodeError as e:raise ValueError('broker_http_header_name') from e
    _,length,_=response_headers(headers)
    encodings=[v.lower() for k,v in headers if k.lower()=='transfer-encoding']
    require(not encodings or encodings==['chunked'] and length is None,'broker_http_framing')
    body=bytearray()
    if method=='HEAD' or status in {204,304}:
        require(not encodings,'broker_http_bodyless_transfer')
    elif encodings:
        while True:
            line=reader.line(16)
            require(re.fullmatch(rb'[0-9a-fA-F]{1,8}',line),'broker_http_chunk_size')
            count=int(line,16)
            require(len(body)+count<=remaining_bytes,'broker_response_budget')
            if not count:
                require(reader.line(2)==b'','broker_http_trailers');break
            body.extend(reader.exact(count))
            require(reader.exact(2)==b'\r\n','broker_http_chunk_end')
    elif length is not None:
        require(length<=remaining_bytes,'broker_response_budget');body.extend(reader.exact(length))
    else:
        body.extend(reader.buffer);reader.buffer.clear()
        require(len(body)<=remaining_bytes,'broker_response_budget')
        while True:
            chunk=reader.receive(min(32768,remaining_bytes-len(body)+1))
            if not chunk:break
            require(len(body)+len(chunk)<=remaining_bytes,'broker_response_budget');body.extend(chunk)
    return status,headers,bytes(body)


def exchange(ledger, plan):
    """One pinned numeric connection, fixed safe headers, verified broker TLS.

    Not an activation API: only a future independently confined trusted broker
    may call it. There is no DNS, proxy/environment configuration, retry, page
    header forwarding or redirect following. A failed exchange exhausts the
    session's remaining byte allowance because partial bytes may have arrived.
    It closes its socket; kernel-wide external stop is a separate runtime gate.
    """
    plan=ledger.lease(plan,time.monotonic_ns());stream=None
    try:
        stream=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        stream.settimeout((plan['expires_ns']-time.monotonic_ns())/10**9)
        stream.connect((plan['peer_ipv4'],plan['port']))
        require(stream.getpeername()[0]==plan['peer_ipv4'],'broker_connected_peer')
        if plan['scheme']=='https':
            # Do not use create_default_context(): SSL_CERT_FILE/SSL_CERT_DIR
            # and SSLKEYLOGFILE can otherwise select caller-controlled trust or
            # log keys. The future immutable runtime must bind this fixed CA
            # artifact's actual bytes as part of its scoped context.
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.verify_mode=ssl.CERT_REQUIRED;context.check_hostname=True
            context.load_verify_locations(cafile=TRUST_FILE)
            ledger.lease(plan,time.monotonic_ns())
            stream.settimeout((plan['expires_ns']-time.monotonic_ns())/10**9)
            stream=context.wrap_socket(stream,server_hostname=plan['host'])
        ledger.lease(plan,time.monotonic_ns())
        parsed=urllib.parse.urlsplit(plan['url'])
        target=plan['url'][len(parsed.scheme)+3+len(parsed.netloc):]
        if not target or target.startswith('?'):target='/'+target
        request=(plan['method']+' '+target+' HTTP/1.1\r\nHost: '+plan['host']+
                 '\r\nUser-Agent: PAW-Mediated-Observation/1\r\nAccept: */*\r\n'+
                 'Accept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii')
        stream.settimeout((plan['expires_ns']-time.monotonic_ns())/10**9);stream.sendall(request)
        status,headers,body=read_http_response(stream,plan['method'],
            LIMITS['bytes']-ledger.received,plan['expires_ns'])
        return ledger.complete(plan,status,headers,body,plan['peer_ipv4'],
                               plan['scheme']=='https',time.monotonic_ns())
    except (OSError,ValueError) as error:
        ledger.received=LIMITS['bytes'];ledger.closed=True
        # complete() may already have consumed the response slot.
        if ledger._pending is not None:
            ledger.fail(plan,'tls' if isinstance(error,ssl.SSLError) else 'io',time.monotonic_ns())
        raise
    finally:
        if stream is not None:stream.close()
