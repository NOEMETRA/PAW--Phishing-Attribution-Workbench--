"""Trusted guest-only owned CDP probe; never email or public input.

The fixed owned URL is fulfilled from generated fixture bytes inside a no-NIC VM.
This exercises real sandboxed Chrome JS, not TLS, public routing or Root approval.
No caller can select a URL, executable, path, method or arbitrary response body.
"""
import base64
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import sys
import time
import tty

if __package__:
    from . import browser_cdp as cdp
else:
    import browser_cdp as cdp

GROUP=Path('/sys/fs/cgroup/paw-browser-job')
WORK=Path('/run/paw-owned-cdp')
MARKER=Path('/var/lib/paw-owned-cdp-used')
SEED='https://paw-owned.invalid/'
CHROME='/opt/google/chrome/chrome'


def require(value,reason):
    if not value:raise ValueError(reason)


def file_digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda:stream.read(65536),b''):value.update(raw)
    return value.hexdigest()


def fixed_arguments():
    return [CHROME,'--headless','--disable-gpu','--no-first-run','--no-default-browser-check',
        '--disable-background-networking','--disable-component-update','--disable-sync',
        '--disable-extensions','--disable-dev-shm-usage','--disable-quic','--password-store=basic',
        '--user-data-dir='+str(WORK/'profile'),'--log-net-log='+str(WORK/'netlog.json'),
        '--net-log-capture-mode=Default','--remote-debugging-pipe','about:blank']


def fixture(nonce,frame):
    """Only two fixed owned synthetic resources. Never opens a socket."""
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'owned_nonce')
    require(type(frame) is dict and set(frame)=={'nonce','seq','url','method','resource'} and
        frame['nonce']==nonce and type(frame['seq']) is int and 0<=frame['seq']<32 and
        type(frame['url']) is str and len(frame['url'])<=2048 and
        type(frame['method']) is str and len(frame['method'])<=16 and
        type(frame['resource']) is str and len(frame['resource'])<=32,'owned_frame')
    if frame['method']!='GET' or frame['url'] not in {SEED,SEED+'owned-data'}:return None,None
    if frame['url']==SEED:
        body=("<!doctype html><title>waiting</title><script>fetch('/owned-data')"
              ".then(x=>x.text()).then(x=>{document.title=x;document.body.dataset.owned='done'})"
              "</script><body>PAW owned fixture only</body>").encode('ascii')
        content='text/html; charset=utf-8'
    else:body=('PAW-OWNED-'+nonce).encode('ascii');content='text/plain; charset=utf-8'
    metadata={'status':'response','slot':frame['seq'],'http_status':200,
        'headers':[{'name':'Content-Type','value':content},{'name':'Content-Length','value':str(len(body))},
                   {'name':'Content-Security-Policy','value':"form-action 'none'; object-src 'none'"}],
        'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()}
    return metadata,body


class Runtime:
    def __init__(self):
        self.process=None;self.started=None;self.driver=None;self.used=False;self.done=None
        self.decoder=cdp.PipeDecoder();self.selector=selectors.DefaultSelector();self.write=bytearray()
        self.stderr=bytearray();self.witness=None;self.requests=0;self.refused=0;self.cdp_frames=0
    def inspect(self):
        require(os.geteuid()==0 and sorted(os.listdir('/sys/class/net'))==['lo'],'owned_guest_no_nic')
        require(not self.used and not MARKER.exists(),'owned_fresh_vm')
        info=json.loads(Path('/etc/paw-browser-image.json').read_text())
        return {'network_interfaces':['lo'],'chrome_version':info['chrome_version'],
            'chrome_binary_sha256':file_digest(CHROME),
            'purpose':'owned CDP bytes only; no TLS/public-network acceptance'}
    def _send(self,frame):
        raw=cdp.encode_command(frame);require(len(self.write)+len(raw)<=8*1024**2,'owned_cdp_write_budget')
        self.write.extend(raw)
    def _request(self,frame):
        self.requests+=1;metadata,body=fixture(self.nonce,frame)
        if metadata is None:self.refused+=1;self.driver.refused()
        else:self.driver.response(metadata,body)
    def start(self):
        self.inspect()
        from browser_sandbox import RendererWitness
        self.witness=RendererWitness()
        self.used=True;MARKER.write_text('used\n');MARKER.chmod(0o600)
        config=json.loads(Path('/etc/paw-owned-cdp.json').read_text())
        require(type(config) is dict and set(config)=={'kind','nonce'} and
            config['kind']=='owned-cdp-probe-v1' and type(config['nonce']) is str and
            re.fullmatch('[0-9a-f]{32}',config['nonce']),'owned_fixed_config')
        self.nonce=config['nonce'];WORK.mkdir(mode=0o700);os.chown(WORK,65534,65534)
        Path('/sys/fs/cgroup/cgroup.subtree_control').write_text('+cpu +memory +pids');GROUP.mkdir()
        for name,value in {'memory.max':str(512*1024**2),'memory.swap.max':'0','pids.max':'256','memory.oom.group':'1'}.items():
            (GROUP/name).write_text(value)
        browser_read,coordinator_write=os.pipe();coordinator_read,browser_write=os.pipe()
        read_keep=fcntl.fcntl(browser_read,fcntl.F_DUPFD_CLOEXEC,10)
        write_keep=fcntl.fcntl(browser_write,fcntl.F_DUPFD_CLOEXEC,10)
        parent=os.getpid()
        def admission():
            (GROUP/'cgroup.procs').write_text(str(os.getpid()))
            for key,limit in [(resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,32*1024**2),(resource.RLIMIT_NOFILE,512)]:
                resource.setrlimit(key,(limit,limit))
            os.dup2(read_keep,3);os.dup2(write_keep,4);os.close(read_keep);os.close(write_keep)
            os.setgroups([]);os.setgid(65534);os.setuid(65534)
            libc=ctypes.CDLL(None)
            if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:os._exit(125)
        try:
            self.process=subprocess.Popen(fixed_arguments(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,start_new_session=True,preexec_fn=admission,
                pass_fds=tuple(sorted({3,4,read_keep,write_keep})),
                env={'PATH':'/usr/bin:/bin','HOME':str(WORK),'LANG':'C.UTF-8',
                     'XDG_CONFIG_HOME':str(WORK),'XDG_CACHE_HOME':str(WORK)})
        finally:
            for fd in [browser_read,browser_write,read_keep,write_keep]:os.close(fd)
        self.read_fd=coordinator_read;self.write_fd=coordinator_write
        for fd in [self.read_fd,self.write_fd,self.process.stderr.fileno()]:os.set_blocking(fd,False)
        self.selector.register(self.read_fd,selectors.EVENT_READ,'cdp')
        self.selector.register(self.process.stderr.fileno(),selectors.EVENT_READ,'stderr')
        self.driver=cdp.GuestController(SEED,self.nonce,self._send,self._request)
        self.started=time.monotonic();self.driver.start()
        return {'started':True,'purpose':'owned CDP only','pid':self.process.pid,'network_interfaces':['lo']}
    def tick(self):
        require(self.process is not None,'owned_not_started')
        if self.done is not None:return self.done
        try:
            require(sorted(os.listdir('/sys/class/net'))==['lo'],'owned_network_changed')
            self.witness.observe(GROUP)
            if self.write:
                try:count=os.write(self.write_fd,self.write);del self.write[:count]
                except BlockingIOError:pass
            for key,_ in self.selector.select(timeout=0):
                try:raw=os.read(key.fd,32768)
                except BlockingIOError:continue
                if not raw:
                    self.selector.unregister(key.fd)
                    if key.data=='cdp':
                        self.decoder.eof()
                        raise ValueError('owned_cdp_pipe_eof')
                    continue
                if key.data=='stderr':
                    require(len(self.stderr)+len(raw)<=8192,'owned_stderr_budget');self.stderr.extend(raw)
                else:
                    for message in self.decoder.feed(raw):self.driver.accept(message);self.cdp_frames+=1
            netlog=WORK/'netlog.json'
            require(not netlog.exists() or netlog.stat().st_size<=1024**2,'owned_netlog_budget')
            require(time.monotonic()-self.started<15,'owned_whole_deadline')
            require(self.process.poll() is None,'owned_chrome_exited')
            if self.driver.stage=='running' and self.requests>=2 and self.driver.fetch.pending is None and not self.driver.queue and time.monotonic()-self.started>=3:
                self.driver.snapshot()
            if self.driver.stage=='snapshot_ready':return self.finish('completed')
            return {'done':False,'requests':self.requests,'stage':self.driver.stage}
        except Exception as error:return self.finish('failed',type(error).__name__+':'+str(error)[:256])
    def finish(self,status,error=None):
        if self.done is not None:return self.done
        (GROUP/'cgroup.kill').write_text('1');self.process.wait(timeout=3)
        end=time.monotonic()+3
        while (GROUP/'pids.current').read_text().strip()!='0' and time.monotonic()<end:time.sleep(.02)
        require((GROUP/'pids.current').read_text().strip()=='0','owned_guest_writers_alive')
        if status=='completed':
            dom=self.driver.dom or b''
            require(('PAW-OWNED-'+self.nonce).encode() in dom and b'data-owned="done"' in dom and
                all(self.witness.flags().values()),'owned_actual_js_or_sandbox_missing')
        self.driver.stop()
        self.done={'done':True,'status':status,'error':error,'writers_stopped':True,
            'sandbox':self.witness.flags(),'network_interfaces':['lo'],'requests':self.requests,'refused':self.refused,
            'dom_sha256':hashlib.sha256(self.driver.dom or b'').hexdigest(),'cdp_frames':self.cdp_frames,
            'scope':'actual owned browser JS/Fetch/DOM only; no TLS/public egress acceptance'}
        return self.done


def main():
    require(os.geteuid()==0 and Path('/etc/paw-owned-cdp.json').is_file(),'trusted_guest_service_only')
    levels=Path('/proc/sys/kernel/printk').read_text().split()
    require(len(levels)==4 and all(v.isdecimal() for v in levels),'owned_console_levels')
    Path('/proc/sys/kernel/printk').write_text('0 '+' '.join(levels[1:])+'\n')
    os.chmod('/dev/ttyS0',0o600);tty.setraw(0);runtime=Runtime()
    def emit(value):
        raw=json.dumps(value,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        require(len(raw)<60000,'owned_console_budget');print('PAW14 '+raw,flush=True)
    emit({'ready':True,'network_interfaces':['lo']})
    try:
        for _ in range(4096):
            line=sys.stdin.buffer.readline(4097)
            if not line:break
            require(len(line)<=4096,'owned_console_input_budget');value=cdp.strict_json(line)
            require(set(value)=={'id','op'} and type(value['id']) is int and
                value['op'] in {'inspect','start','poll','cancel'},'owned_finite_command')
            op=value['op']
            result=(runtime.inspect() if op=='inspect' else runtime.start() if op=='start' else
                    runtime.tick() if op=='poll' else runtime.finish('cancelled'))
            emit({'id':value['id'],'ok':True,'data':result})
    finally:
        if runtime.process is not None:
            try:(GROUP/'cgroup.kill').write_text('1')
            except FileNotFoundError:pass


if __name__=='__main__':main()
