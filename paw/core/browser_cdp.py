"""Bounded CDP pipe decoding and deny-by-default Fetch translation.

No browser launch, socket, Root operation or grant. A future trusted guest loop
must use this only with inherited private Chrome pipes in a no-NIC disposable VM.
"""
import base64
import hashlib
import json
import re

MAX_CDP=384*1024
MAX_PIPE_TOTAL=8*1024**2
MAX_EVENTS=4096
MAX_BODY=4*1024**2
CHUNK=32768


def require(value,reason):
    if not value:raise ValueError(reason)


def identifier(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',value),'cdp_identifier')
    return value


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def strict_json(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            require(key not in value,'cdp_duplicate_json_key');value[key]=item
        return value
    def invalid(value):raise ValueError('cdp_nonfinite_json')
    require(type(raw) is bytes and len(raw)<=MAX_CDP,'cdp_json_budget')
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)
    require(type(value) is dict,'cdp_json_object');return value


class PipeDecoder:
    """Chrome remote-debugging-pipe uses NUL-delimited JSON, not TCP CDP."""
    def __init__(self):self.buffer=bytearray();self.total=0;self.events=0;self.closed=False
    def feed(self,chunk):
        require(not self.closed and type(chunk) is bytes and len(chunk)<=32768,'cdp_pipe_input')
        self.total+=len(chunk)
        if self.total>MAX_PIPE_TOTAL:self.closed=True;raise ValueError('cdp_pipe_total')
        self.buffer.extend(chunk);result=[]
        try:
            while True:
                end=self.buffer.find(0)
                if end<0:break
                require(0<end<=MAX_CDP and self.events<MAX_EVENTS,'cdp_pipe_frame_budget')
                raw=bytes(self.buffer[:end]);del self.buffer[:end+1]
                result.append(strict_json(raw));self.events+=1
            require(len(self.buffer)<=MAX_CDP,'cdp_pipe_partial_budget')
        except (ValueError,RecursionError):self.closed=True;raise
        return result
    def eof(self):
        self.closed=True;require(not self.buffer,'cdp_pipe_truncated')


def encode_command(value):
    require(type(value) is dict and type(value.get('id')) is int and value['id']>0 and
            type(value.get('method')) is str and type(value.get('params')) is dict,'cdp_command_shape')
    if 'sessionId' in value:identifier(value['sessionId'])
    raw=canonical(value);require(len(raw)<=MAX_BODY*2,'cdp_command_budget')
    return raw+b'\0'


def response_chunks(nonce,seq,body):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and
            type(seq) is int and 0<=seq<32 and type(body) is bytes and len(body)<=MAX_BODY,'rpc_response_input')
    # Never write a multi-megabyte body as a single guest-console line.
    result=[]
    for offset in range(0,len(body),CHUNK):
        result.append({'nonce':nonce,'seq':seq,'chunk':offset//CHUNK,
                       'data_b64':base64.b64encode(body[offset:offset+CHUNK]).decode('ascii')})
    result.append({'nonce':nonce,'seq':seq,'done':True,'chunks':len(result),
                   'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()})
    require(all(len(canonical(row))<60000 for row in result),'rpc_wire_line_budget')
    return result


class ResponseAssembler:
    """One typed bounded body transfer; nonce, order, length and digest bind it."""
    def __init__(self,nonce,seq,remaining):
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and
                type(seq) is int and 0<=seq<32 and type(remaining) is int and
                0<=remaining<=MAX_BODY,'rpc_assembler_identity')
        self.nonce=nonce;self.seq=seq;self.remaining=remaining;self.data=bytearray();self.chunks=0;self.closed=False
    def feed(self,row):
        require(not self.closed,'rpc_response_closed')
        try:
            require(type(row) is dict and row.get('nonce')==self.nonce and
                    type(row.get('seq')) is int and row['seq']==self.seq,'rpc_response_identity')
            if set(row)=={'nonce','seq','chunk','data_b64'}:
                require(type(row['chunk']) is int and row['chunk']==self.chunks and self.chunks<128 and
                        type(row['data_b64']) is str and len(row['data_b64'])<=4*((CHUNK+2)//3),'rpc_response_chunk')
                raw=base64.b64decode(row['data_b64'],validate=True)
                require(0<len(raw)<=CHUNK and base64.b64encode(raw).decode('ascii')==row['data_b64'] and
                        len(self.data)+len(raw)<=self.remaining,'rpc_response_bytes')
                self.data.extend(raw);self.chunks+=1;return None
            require(set(row)=={'nonce','seq','done','chunks','body_bytes','body_sha256'} and row['done'] is True and
                    type(row['chunks']) is int and row['chunks']==self.chunks and
                    type(row['body_bytes']) is int and row['body_bytes']==len(self.data) and
                    row['body_sha256']==hashlib.sha256(self.data).hexdigest(),'rpc_response_end')
            self.closed=True;return bytes(self.data)
        except (ValueError,TypeError):self.closed=True;self.data.clear();raise


class FetchTranslator:
    """Translate one paused request into data only; never continue live traffic.

    The enclosing controller must enable Fetch before any navigation, cancel auth,
    deny downloads/permissions and stop on unknown targets or CDP errors. This
    class alone does not create those conditions or prove a sandbox/packet gate.
    """
    def __init__(self,nonce,session):
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'rpc_nonce')
        self.nonce=nonce;self.session=identifier(session);self.seq=0;self.pending=None;self.command_id=0
    def command(self,method,params):
        require(method in {'Fetch.failRequest','Fetch.fulfillRequest','Fetch.continueWithAuth'},'cdp_forbidden_command')
        self.command_id+=1;require(self.command_id<=96,'cdp_command_count')
        return {'id':self.command_id,'method':method,'params':params,'sessionId':self.session}
    def auth(self,request_id):
        return self.command('Fetch.continueWithAuth',{'requestId':identifier(request_id),
            'authChallengeResponse':{'response':'CancelAuth'}})
    def paused(self,event):
        require(self.pending is None and self.seq<32,'rpc_pending_or_budget')
        require(type(event) is dict and event.get('method')=='Fetch.requestPaused' and
                event.get('sessionId')==self.session and type(event.get('params')) is dict,'cdp_paused_event')
        params=event['params'];request_id=identifier(params.get('requestId'));request=params.get('request')
        require('responseStatusCode' not in params and 'responseErrorReason' not in params and
                type(request) is dict and type(request.get('url')) is str and len(request['url'])<=2048 and
                type(request.get('method')) is str and len(request['method'])<=16 and
                type(params.get('resourceType')) is str and len(params['resourceType'])<=32,'cdp_paused_request')
        self.pending=(self.seq,request_id);self.seq+=1
        # Headers, postData, credentials and any page-supplied extra fields are
        # deliberately absent from the broker RPC frame.
        return {'nonce':self.nonce,'seq':self.seq-1,'url':request['url'],
                'method':request['method'],'resource':params['resourceType']}
    def refuse(self):
        require(self.pending is not None,'rpc_no_pending');_,request_id=self.pending;self.pending=None
        return self.command('Fetch.failRequest',{'requestId':request_id,'errorReason':'BlockedByClient'})
    def fulfill(self,response,body):
        require(self.pending is not None,'rpc_no_pending');seq,request_id=self.pending
        require(type(response) is dict and response.get('status')=='response' and
                type(response.get('slot')) is int and response['slot']==seq and
                type(response.get('http_status')) is int and 200<=response['http_status']<=599 and
                type(body) is bytes and len(body)<=MAX_BODY and type(response.get('body_bytes')) is int and
                response['body_bytes']==len(body) and
                response.get('body_sha256')==hashlib.sha256(body).hexdigest(),'rpc_fulfill_identity')
        headers=response.get('headers');require(type(headers) is list and len(headers)<=66,'rpc_fulfill_headers')
        for row in headers:
            require(type(row) is dict and set(row)=={'name','value'} and
                    type(row['name']) is str and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}",row['name']) and
                    type(row['value']) is str and len(row['value'])<=8192 and
                    not any(ord(c)<32 and c!='\t' or ord(c)==127 for c in row['value']),'rpc_fulfill_header')
        require(len(canonical(headers))<=65536,'rpc_fulfill_headers_budget')
        self.pending=None
        return self.command('Fetch.fulfillRequest',{'requestId':request_id,'responseCode':response['http_status'],
            'responseHeaders':headers,'body':base64.b64encode(body).decode('ascii')})


class GuestController:
    """Main-page controller; no process creation or network authority.

    send(frame) writes only to the private Chrome CDP pipe. request(frame) emits
    a bounded broker RPC, without doing network I/O in this controller. Callbacks
    must not execute a page-supplied command. Child targets are deliberately
    closed and reported as missing coverage, never resumed without interception.
    """
    def __init__(self,seed_url,nonce,send,request):
        require(type(seed_url) is str and len(seed_url)<=2048 and
                seed_url.startswith(('http://','https://')) and
                all(33<=ord(v)<127 for v in seed_url),'guest_seed_shape')
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'guest_nonce')
        self.seed=seed_url;self.nonce=nonce;self.send=send;self.request=request
        self.next_id=0;self.pending={};self.stage='new';self.session=None;self.target=None
        self.fetch=None;self.queue=[];self.events=0;self.closed_targets=set();self.missing=[];self.dom=None

    def _command(self,method,params,callback=None,session=None):
        require(self.stage not in {'failed','stopped'} and self.next_id<256 and len(self.pending)<16,'guest_command_budget')
        self.next_id+=1;ident=self.next_id
        frame={'id':ident,'method':method,'params':params}
        if session is not None:frame['sessionId']=session
        self.pending[ident]=(callback,session);self.send(frame)

    def start(self):
        require(self.stage=='new','guest_single_session');self.stage='configuring'
        def permissions(_):self._command('Browser.grantPermissions',{'permissions':[]},create)
        def create(_):self._command('Target.createTarget',{'url':'about:blank'},attach)
        def attach(result):
            self.target=identifier(result.get('targetId'))
            self._command('Target.attachToTarget',{'targetId':self.target,'flatten':True},enable)
        def enable(result):
            self.session=identifier(result.get('sessionId'));self.fetch=FetchTranslator(self.nonce,self.session)
            self._command('Fetch.enable',{'patterns':[{'urlPattern':'*','requestStage':'Request'}],
                'handleAuthRequests':True},children,self.session)
        def children(_):
            self._command('Target.setAutoAttach',{'autoAttach':True,'waitForDebuggerOnStart':True,
                'flatten':True},discover,self.session)
        def discover(_):self._command('Target.setDiscoverTargets',{'discover':True},page)
        def page(_):self._command('Page.enable',{},navigate,self.session)
        def navigate(_):
            self.stage='running'
            self._command('Page.navigate',{'url':self.seed},navigated,self.session)
        def navigated(result):require(not result.get('errorText'),'guest_navigation_failed')
        self._command('Browser.setDownloadBehavior',{'behavior':'deny','eventsEnabled':False},permissions)

    def _translated(self,frame):
        self._command(frame['method'],frame['params'],session=frame['sessionId'])

    def _pump(self):
        if self.queue and self.fetch.pending is None:
            frame=self.fetch.paused(self.queue.pop(0));self.request(frame)

    def accept(self,message):
        require(self.stage not in {'new','failed','stopped'} and type(message) is dict,'guest_session_not_running')
        self.events+=1;require(self.events<=MAX_EVENTS,'guest_event_budget')
        try:
            if 'id' in message:
                ident=message['id'];require(type(ident) is int and ident in self.pending,'guest_unknown_response')
                callback,session=self.pending.pop(ident)
                require('error' not in message and type(message.get('result')) is dict and
                        message.get('sessionId')==session,'guest_cdp_command_failed')
                if callback is not None:callback(message['result'])
                return
            method=message.get('method');params=message.get('params')
            require(type(method) is str and type(params) is dict,'guest_event_shape')
            if method=='Fetch.requestPaused':
                if self.stage in {'snapshot','snapshot_ready'}:
                    require(message.get('sessionId')==self.session,'guest_snapshot_fetch_session')
                    self._command('Fetch.failRequest',{'requestId':identifier(params.get('requestId')),
                        'errorReason':'BlockedByClient'},session=self.session)
                    if not any(x.get('kind')=='snapshot_network_cutoff' for x in self.missing):
                        self.missing.append({'kind':'snapshot_network_cutoff'})
                    return
                require(self.stage=='running' and message.get('sessionId')==self.session and
                        len(self.queue)+self.fetch.seq<32,'guest_request_queue_budget')
                self.queue.append(message);self._pump()
            elif method=='Fetch.authRequired':
                require(message.get('sessionId')==self.session,'guest_auth_session')
                self._translated(self.fetch.auth(params.get('requestId')))
            elif method in {'Target.targetCreated','Target.attachedToTarget'}:
                info=params.get('targetInfo');require(type(info) is dict,'guest_child_target_shape')
                target=identifier(info.get('targetId'))
                if info.get('type') not in {'browser','tab'} and target!=self.target and target not in self.closed_targets:
                    require(len(self.closed_targets)<16,'guest_target_budget');self.closed_targets.add(target)
                    self.missing.append({'kind':'child_target_blocked','target_type':str(info.get('type'))[:32]})
                    self._command('Target.closeTarget',{'targetId':target})
            elif method in {'Inspector.targetCrashed','Inspector.detached'}:
                raise ValueError('guest_browser_lost')
            # Unused events supply no commands, RPC or authority. Their count
            # and total pipe bytes are still bounded independently.
        except (ValueError,TypeError,KeyError):self.stage='failed';raise

    def response(self,metadata,body):
        require(self.stage=='running','guest_not_running')
        try:self._translated(self.fetch.fulfill(metadata,body));self._pump()
        except (ValueError,TypeError,KeyError):self.stage='failed';raise

    def refused(self):
        require(self.stage=='running','guest_not_running')
        self._translated(self.fetch.refuse());self._pump()

    def snapshot(self):
        require(self.stage=='running' and not self.queue and self.fetch.pending is None,'guest_snapshot_pending_network')
        self.stage='snapshot'
        def document(result):
            node=result.get('root',{}).get('nodeId')
            require(type(node) is int and node>0,'guest_dom_node')
            self._command('DOM.getOuterHTML',{'nodeId':node},html,self.session)
        def html(result):
            value=result.get('outerHTML');require(type(value) is str,'guest_dom_shape')
            raw=value.encode('utf-8');require(len(raw)<=256*1024,'guest_dom_budget')
            self.dom=raw;self.stage='snapshot_ready'
        self._command('DOM.getDocument',{'depth':0},document,self.session)

    def stop(self):
        # Data state only. The guest cgroup and external Root owner must still
        # kill/reconcile the whole Chrome/QEMU tree before any import.
        self.stage='stopped';self.pending.clear();self.queue.clear()
        return {'dom_available':self.dom is not None,'missing_coverage':list(self.missing),
                'writers_stopped':'not established by this controller'}
