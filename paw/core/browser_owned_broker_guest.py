"""Trusted owned-only asynchronous CDP guest, with no NIC or public config.

Reuse the fixed sandboxed launcher and synthetic seed. Responses arrive only
through strict nonce/sequence/phase-bound metadata and body transfers. Protocol
loss or parent EOF stops the renderer; no socket or live continuation is added.
"""
import base64
import hashlib
import re
import time
import os
import sys
import tty
from pathlib import Path

if __package__:
    from . import browser_owned_cdp_guest as fixed
    from . import browser_cdp as cdp
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import browser_owned_cdp_guest as fixed
    import browser_cdp as cdp

META_MAX=65536
META_TOTAL=1024**2


def require(value,reason):
    if not value:raise ValueError(reason)


class CaptureController(cdp.GuestController):
    def __init__(self,*args):
        super().__init__(*args);self.png=None;self.png_pending=False
    def accept(self,message):
        super().accept(message)
        if self.stage=='snapshot_ready'and self.png is None and not self.png_pending:
            self.stage='snapshot';self.png_pending=True
            def screenshot(result):
                value=result.get('data')
                cdp.require(type(value)is str and len(value)<=4*((256*1024+2)//3),'owned_png_encoded_budget')
                raw=base64.b64decode(value,validate=True)
                cdp.require(33<=len(raw)<=256*1024 and raw.startswith(b'\x89PNG\r\n\x1a\n')and
                    raw[12:16]==b'IHDR'and 0<int.from_bytes(raw[16:20],'big')<=2048 and
                    0<int.from_bytes(raw[20:24],'big')<=2048 and
                    base64.b64encode(raw).decode('ascii')==value,'owned_png_shape')
                self.png=raw;self.png_pending=False;self.stage='snapshot_ready'
            self._command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False},screenshot,self.session)


CAPS={'dom.html':256*1024,'screenshot.png':256*1024}
class Transfer:
 def __init__(self,nonce,artifacts,writers_stopped):
  cdp.require(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'owned_capture_nonce')
  cdp.require(writers_stopped is True and type(artifacts)is dict and set(artifacts)<=set(CAPS),'owned_capture_known_stop')
  self.manifest=[];self.streams=[];self.stream=0;self.chunk=0;self.closed=False
  for name,cap in CAPS.items():
   if name not in artifacts:continue
   raw=artifacts[name];cdp.require(type(raw)is bytes and 0<len(raw)<=cap,'owned_capture_byte_cap')
   seq=len(self.streams);self.streams.append((name,cdp.response_chunks(nonce,seq,raw)))
   self.manifest.append({'name':name,'stream':seq,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
  if not self.streams:self.closed=True
 def read(self,value):
  try:
   cdp.require(not self.closed and type(value)is dict and set(value)=={'name','chunk'}and
    type(value['chunk'])is int and value['chunk']==self.chunk,'owned_capture_order')
   name,rows=self.streams[self.stream];cdp.require(value['name']==name,'owned_capture_name')
   row=rows[self.chunk];reply={'name':name,'row':row}
   cdp.require(len(cdp.canonical(reply))<60000,'owned_capture_line_budget')
   if row.get('done')is True:
    self.stream+=1;self.chunk=0
    if self.stream==len(self.streams):self.closed=True
   else:self.chunk+=1
   return reply
  except (ValueError,TypeError,KeyError,IndexError):self.closed=True;raise ValueError('owned_capture_closed')from None


class Runtime(fixed.Runtime):
    def __init__(self):
        super().__init__();self.network_pending=None;self.transfer_failed=False
        self.network_bytes=0;self.metadata_bytes=0;self.capture_transfer=None

    def _make_controller(self):
        return CaptureController(fixed.SEED,self.nonce,self._send,self._request)

    def finish(self,status,error=None):
        result=super().finish(status,error)
        if self.capture_transfer is None:
            # The base finish has killed Chrome and proved its cgroup empty.
            artifacts={}
            if self.driver is not None:
                for name,raw in [('dom.html',self.driver.dom),('screenshot.png',self.driver.png)]:
                    if type(raw)is bytes and 0<len(raw)<=CAPS[name]:artifacts[name]=raw
            self.capture_transfer=Transfer(self.nonce,artifacts,result.get('writers_stopped'))
            result['capture_artifacts']=self.capture_transfer.manifest
            result['missing_coverage']=[name for name in CAPS if name not in artifacts]
        return result

    def artifact(self,value):
        require(self.done is not None and self.done.get('writers_stopped')is True and
            self.capture_transfer is not None,'owned_capture_not_stopped')
        return self.capture_transfer.read(value)

    def _request(self,frame):
        require(not self.transfer_failed and self.network_pending is None and
            type(frame) is dict and set(frame)=={'nonce','seq','url','method','resource'} and
            frame['nonce']==self.nonce and type(frame['seq']) is int and 0<=frame['seq']<32 and
            type(frame['url']) is str and len(frame['url'])<=2048 and
            type(frame['method']) is str and len(frame['method'])<=16 and
            type(frame['resource']) is str and len(frame['resource'])<=32,'owned_network_request')
        self.requests+=1
        self.network_pending={'request':dict(frame),'phase':'await_begin'}
        # Chrome remains paused. No fulfillment or live continue is performed.

    def network(self,value):
        try:
            require(not self.transfer_failed and self.network_pending is not None and
                self.driver is not None and self.driver.stage=='running' and
                self.started is not None and time.monotonic()-self.started<15 and
                type(value) is dict,'owned_network_not_pending_or_expired')
            pending=self.network_pending;request=pending['request'];slot=request['seq']
            require(value.get('nonce')==self.nonce and type(value.get('seq')) is int and
                    value['seq']==slot,'owned_network_identity')
            if value.get('kind')=='refusal':
                require(set(value)=={'kind','nonce','seq'} and pending['phase']=='await_begin',
                        'owned_network_refusal_phase')
                self.network_pending=None;self.refused+=1;self.driver.refused()
                return {'accepted':True,'refused_slot':slot}
            if value.get('kind')=='begin':
                require(set(value)=={'kind','nonce','seq','bytes','sha256'} and
                    pending['phase']=='await_begin' and type(value['bytes']) is int and
                    0<value['bytes']<=min(META_MAX,META_TOTAL-self.metadata_bytes) and
                    type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),
                    'owned_network_metadata_begin')
                pending.update(phase='metadata',expected_bytes=value['bytes'],expected_sha256=value['sha256'],
                    assembler=cdp.ResponseAssembler(self.nonce,slot,value['bytes']))
                return {'accepted':True,'phase':'metadata'}
            require(set(value)=={'kind','nonce','seq','section','row'} and value['kind']=='part' and
                    value['section']==pending['phase'] and pending['phase'] in {'metadata','body'},
                    'owned_network_transfer_phase')
            raw=pending['assembler'].feed(value['row'])
            if raw is None:return {'accepted':True,'phase':pending['phase']}
            if pending['phase']=='metadata':
                require(len(raw)==pending['expected_bytes'] and hashlib.sha256(raw).hexdigest()==pending['expected_sha256'],
                        'owned_network_metadata_binding')
                metadata=cdp.strict_json(raw)
                require(cdp.canonical(metadata)==raw and
                    set(metadata)=={'status','slot','http_status','headers','body_bytes','body_sha256'} and
                    metadata['status']=='response' and type(metadata['slot']) is int and metadata['slot']==slot and
                    type(metadata['http_status']) is int and 200<=metadata['http_status']<=599 and
                    type(metadata['headers']) is list and len(metadata['headers'])<=66 and
                    type(metadata['body_bytes']) is int and 0<=metadata['body_bytes']<=cdp.MAX_BODY-self.network_bytes and
                    type(metadata['body_sha256']) is str and re.fullmatch('[0-9a-f]{64}',metadata['body_sha256']),
                    'owned_network_metadata_shape')
                self.metadata_bytes+=len(raw)
                pending.update(phase='body',metadata=metadata,
                    assembler=cdp.ResponseAssembler(self.nonce,slot,metadata['body_bytes']))
                return {'accepted':True,'phase':'body'}
            metadata=pending['metadata']
            require(len(raw)==metadata['body_bytes'] and hashlib.sha256(raw).hexdigest()==metadata['body_sha256'],
                    'owned_network_response_binding')
            self.network_bytes+=len(raw);self.network_pending=None
            # Clear the old pending state first: response() may immediately
            # expose the next queued request through this Runtime callback.
            self.driver.response(metadata,raw)
            return {'accepted':True,'completed_slot':slot}
        except (ValueError,TypeError,KeyError,RecursionError):
            self.transfer_failed=True;self.network_pending=None
            if self.driver is not None:self.driver.stage='failed'
            raise ValueError('owned_network_protocol_closed')

    def tick(self):
        if self.transfer_failed:return self.finish('failed','owned_network_protocol_closed')
        result=super().tick()
        if not result.get('done') and self.network_pending is not None:
            result={**result,'network_request':dict(self.network_pending['request']),
                    'transfer_phase':self.network_pending['phase']}
        return result


class ConsoleSession:
    """Finite guest command state. No generic dispatch or arbitrary config."""
    def __init__(self,runtime):self.runtime=runtime;self.next=1;self.closed=False

    def command(self,raw):
        require(not self.closed,'owned_console_closed')
        try:
            require(type(raw)is bytes and 0<len(raw)<60000,'owned_console_input_budget')
            value=cdp.strict_json(raw)
            require(type(value)is dict and type(value.get('id'))is int and value['id']==self.next and
                self.next<=4096 and type(value.get('op'))is str and
                value['op']in {'inspect','start','poll','network','artifact','cancel'},'owned_console_command')
            op=value['op'];self.next+=1
            require(set(value)==({'id','op','value'}if op in {'network','artifact'}else{'id','op'})and
                (op=='network'or len(raw)<=4096),'owned_console_shape')
            require(type(self.runtime.done)is not dict or op in {'poll','artifact','cancel'},
                'owned_console_terminal_operation')
            if op=='inspect':data=self.runtime.inspect()
            elif op=='start':data=self.runtime.start()
            elif op=='poll':data=self.runtime.tick()
            elif op=='network':data=self.runtime.network(value['value'])
            elif op=='artifact':data=self.runtime.artifact(value['value'])
            else:
                require(self.runtime.process is not None,'owned_console_cancel_before_start')
                data=self.runtime.finish('cancelled')
            result={'id':value['id'],'ok':True,'data':data}
            require(len(cdp.canonical(result))<60000,'owned_console_reply_budget')
            return result
        except Exception:
            self.closed=True
            if self.runtime.process is not None:self.runtime.finish('failed','owned_console_protocol_lost')
            raise


def serve(runtime,input_stream,emit):
    """Bounded console loop; injected inert streams are unit-test seams only."""
    session=ConsoleSession(runtime)
    try:
        for _ in range(4096):
            line=input_stream.readline(60000)
            if not line:break
            require(line.endswith(b'\n') and len(line)<60000,'owned_console_unterminated_or_large')
            emit(session.command(line))
            if session.closed:break
    finally:
        if runtime.process is not None and runtime.done is None:
            runtime.finish('failed','owned_console_owner_lost')


def main():
    require(os.geteuid()==0 and Path('/etc/paw-owned-cdp.json').is_file(),
            'trusted_owned_brokered_guest_service_only')
    levels=Path('/proc/sys/kernel/printk').read_text().split()
    require(len(levels)==4 and all(v.isdecimal()for v in levels),'owned_console_levels')
    Path('/proc/sys/kernel/printk').write_text('0 '+' '.join(levels[1:])+'\n')
    os.chmod('/dev/ttyS0',0o600);tty.setraw(0)
    def emit(value):
        raw=cdp.canonical(value)
        require(len(raw)<60000,'owned_console_reply_budget')
        print('PAW14 '+raw.decode('ascii'),flush=True)
    emit({'ready':True,'network_interfaces':['lo']})
    serve(Runtime(),sys.stdin.buffer,emit)


if __name__=='__main__':main()
