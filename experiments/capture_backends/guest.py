"""Finite harmless benchmark in a disposable no-NIC guest; no production grant.

Upstream engines are loaded only by the nonroot worker. No real email/URL input,
browser/CDP/HTTP client implementation, host mount, account data or installer.
"""
import argparse, asyncio, base64, hashlib, http.server, io, json, os, re
import shutil, ssl, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path

MEDIA=Path('/mnt/bench/payload');WORK=Path('/run/capture-benchmark')
MODES=('playwrightcapture','lacus-api')
CASES=('http-js','https-invalid','redirect')
def require(v,r):
    if not v:raise ValueError(r)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def stop_unit(unit,group):
    stopped=subprocess.run(['systemctl','stop',unit],capture_output=True,text=True,timeout=2)
    shown=subprocess.run(['systemctl','show',unit,'-p','LoadState','-p','MainPID','-p','ActiveState'],
        capture_output=True,text=True,timeout=2)
    props=dict(r.split('=',1)for r in shown.stdout.splitlines()if '='in r)
    require(shown.returncode in {0,1}and props.get('MainPID')=='0'and
        props.get('ActiveState')in {'inactive','failed'}and props.get('LoadState')in {'loaded','not-found'},
        'guest terminal unit unknown')
    if shown.returncode or stopped.returncode:require(props['LoadState']=='not-found','guest stop/readback failed')
    if group.exists():require(not(group/'cgroup.procs').read_text().strip(),'guest cgroup not empty')
    return props
def emit(v):
    raw=canonical(v);require(len(raw)<60000,'console budget');print('CAPTUREBENCH '+raw.decode(),flush=True)
def fixture(nonce,path):
    require(re.fullmatch('[0-9a-f]{32}',nonce),'nonce')
    if path=='/':return 200,{'Content-Type':'text/html'},("<!doctype html><title>waiting</title><script>fetch('/owned-data')"
        ".then(x=>x.text()).then(x=>{document.title=x;document.body.dataset.owned='done'})"
        "</script><body>PAW owned fixture only</body>").encode()
    if path=='/owned-data':return 200,{'Content-Type':'text/plain'},('PAW-OWNED-'+nonce).encode()
    if path=='/redirect':return 302,{'Location':'/'},b''
    return 404,{},b''
def url(case):
    require(case in CASES,'fixed case')
    return 'https://127.0.0.1:8443/'if case=='https-invalid'else'http://127.0.0.1:8080/'+('redirect'if case=='redirect'else'')
def settings(case):return {'url':url(case),'browser':'chromium','depth':0,'headless':True,
    'general_timeout_in_sec':15,'with_screenshot':True,'with_favicon':False,'with_video':False,
    'with_trusted_timestamps':False,'allow_tracking':False,'final_wait':0,
    'viewport':{'width':1280,'height':720},'locale':'en-US','timezone_id':'UTC'}
def configure_home(folder):
    home=folder/'lacus-home';(home/'config').mkdir(parents=True);(home/'cache').mkdir();(home/'logs').mkdir()
    shutil.copytree(MEDIA/'lacus-source/config',home/'config',dirs_exist_ok=True)
    generic=json.loads((home/'config/generic.json.sample').read_bytes())
    generic.update(concurrent_captures=1,max_capture_time=15,expire_results=300,max_retries=0,
        only_global_lookups=False,tor_proxy=None,i2p_proxy=None,allow_headed=False)
    (home/'config/generic.json').write_bytes(canonical(generic));os.environ['LACUS_HOME']=str(home)
    return home
async def capture(mode,case,folder):
    # False is an explicitly owned-loopback fixture setting. This benchmark
    # cannot establish the public-address/egress contract of production PAW.
    from playwrightcapture import Capture
    from lookyloo_models import CaptureSettings
    kwargs=settings(case)
    if mode=='playwrightcapture':
        async with Capture(capture_settings=CaptureSettings(**kwargs),only_global_lookup=False)as c:
            await c.initialize_context();result=await c.capture_page(max_depth_capture_time=15)
        return result
    require(mode=='lacus-api','fixed mode');home=configure_home(folder)
    env=dict(os.environ,LD_LIBRARY_PATH=str(MEDIA/'redis/usr/lib/x86_64-linux-gnu'))
    redis=subprocess.Popen([str(MEDIA/'redis/redis-server'),'--port','0','--unixsocket',str(home/'cache/cache.sock'),
        '--unixsocketperm','700','--save','','--appendonly','no'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
    server=None
    try:
        deadline=time.monotonic()+2
        while not(home/'cache/cache.sock').exists():
            require(redis.poll()is None and time.monotonic()<deadline,'redis readiness');await asyncio.sleep(.02)
        from website.web import app,lacus
        from wsgiref.simple_server import make_server
        server=make_server('127.0.0.1',7100,app)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        raw=await asyncio.to_thread(lambda:urllib.request.urlopen(urllib.request.Request(
            'http://127.0.0.1:7100/enqueue',data=canonical({**kwargs,'max_retries':0,'force':True}),
            headers={'Content-Type':'application/json'}),timeout=2).read(65536))
        ident=json.loads(raw);require(str(uuid.UUID(ident))==ident,'API UUID')
        tasks=[task async for task in lacus.core.consume_queue(1)];require(len(tasks)==1,'single queued capture')
        await asyncio.gather(*tasks)
        raw=await asyncio.to_thread(lambda:urllib.request.urlopen('http://127.0.0.1:7100/capture_result/'+ident,
            timeout=2).read(6*1024**2+1));require(len(raw)<=6*1024**2,'API response budget')
        result=json.loads(raw)
        if isinstance(result.get('png'),str):result['png']=base64.b64decode(result['png'],validate=True)
        result['benchmark_api_uuid']=ident;return result
    finally:
        if server is not None:server.shutdown();server.server_close()
        redis.terminate();redis.wait(timeout=2)
def worker(mode,case,nonce,folder):
    require(os.geteuid()==1000 and mode in MODES and case in CASES,'nonroot finite worker')
    folder=Path(folder);require(folder.parent==WORK,'worker output parent');began=time.monotonic()
    sys.path[:0]=[str(MEDIA/'site'),str(MEDIA/'lacus-source')]
    record={'mode':mode,'case':case,'nonce':nonce,'owned_loopback_only':True,'production_acceptance':False,
        'settings':settings(case),'only_global_lookup':False,'tls_verified':False}
    artifacts=[]
    try:
        result=asyncio.run(capture(mode,case,folder));total=0
        for name,value in [('har.json',result.get('har')),('dom.html',result.get('html')),('screenshot.png',result.get('png'))]:
            if value is None:continue
            raw=canonical(value)if name.endswith('.json')else value.encode()if isinstance(value,str)else value
            cap={'har.json':1024**2,'dom.html':256*1024,'screenshot.png':512*1024}[name]
            require(type(raw)is bytes and len(raw)<=cap,'artifact budget');total+=len(raw);require(total<=2*1024**2,'aggregate artifacts')
            (folder/name).write_bytes(raw);artifacts.append({'name':name,'bytes':len(raw),'sha256':sha(raw)})
        dom=result.get('html')or'';har=result.get('har')or{};entries=har.get('log',{}).get('entries',[])if isinstance(har,dict)else[]
        checks={'har_entries':bool(entries),'dom_nonempty':isinstance(dom,str)and bool(dom.strip()),
            'png_signature':isinstance(result.get('png'),bytes)and result['png'].startswith(b'\x89PNG\r\n\x1a\n')}
        complete={a['name']for a in artifacts}=={'har.json','dom.html','screenshot.png'}and all(checks.values())
        status='captured'if complete and not result.get('error')else'partial'if artifacts else'failed'
        record.update(status=status,html_nonce_seen=('PAW-OWNED-'+nonce)in dom,dom_js_marker='data-owned="done"'in dom,
            har_entries=len(entries),har_urls=[r.get('request',{}).get('url')for r in entries],final_url=result.get('last_redirected_url'),
            upstream_error=result.get('error'),capture_checks=checks,artifact_inventory=artifacts,upstream_keys=sorted(result))
    except Exception as error:record.update(status='partial'if artifacts else'failed',error=type(error).__name__+':'+str(error)[:2048])
    record['artifact_inventory']=artifacts
    record['worker_seconds']=time.monotonic()-began;(folder/'result.json').write_bytes(canonical(record))
def controller(nonce):
    require(os.geteuid()==0 and sorted(os.listdir('/sys/class/net'))==['lo'],'guest no NIC')
    WORK.mkdir(mode=0o755);servers=[];requests=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            requests.append({'path':self.path,'method':'GET'});require(len(requests)<=128,'fixture request budget')
            status,headers,body=fixture(nonce,self.path);self.send_response(status)
            for k,v in headers.items():self.send_header(k,v)
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def do_POST(self):self.send_error(405)
    subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=paw-owned.invalid',
        '-keyout',str(WORK/'key.pem'),'-out',str(WORK/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    for port in [8080,8443]:
        server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler)
        if port==8443:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(WORK/'cert.pem',WORK/'key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
    tls_error=None
    try:
        import socket
        context=ssl.create_default_context(cafile=str(WORK/'cert.pem'))
        with socket.create_connection(('127.0.0.1',8443),timeout=1)as stream:
            with context.wrap_socket(stream,server_hostname='127.0.0.1'):pass
    except ssl.SSLCertVerificationError as error:tls_error=str(error)
    require(tls_error is not None,'invalid certificate fixture did not fail independent verification')
    runs=[];seq=0
    sys.path.insert(0,str(MEDIA/'code'));from browser_cdp import response_chunks
    from browser_sandbox import RendererWitness
    for mode in MODES:
        for case in CASES:
            folder=WORK/(mode+'-'+case);folder.mkdir();os.chown(folder,1000,1000)
            unit='capturebench-'+uuid.uuid4().hex;witness=RendererWitness();began=time.monotonic();observed_peaks={}
            group=Path('/sys/fs/cgroup/system.slice')/(unit+'.service')
            cmd=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
                '-p','User=ubuntu','-p','NoNewPrivileges=yes','-p','MemoryMax=512M','-p','MemorySwapMax=0',
                '-p','TasksMax=256','-p','CPUQuota=100%','-p','RuntimeMaxSec=15','-p','TimeoutStopSec=500ms',
                '-p','KillMode=control-group','-p','LimitFSIZE=8M','-p','Environment=HOME='+str(folder),
                '-p','Environment=PLAYWRIGHT_BROWSERS_PATH='+str(MEDIA/'browsers'),
                '/usr/bin/python3','-I','-B',__file__,'worker',mode,case,nonce,str(folder)]
            with (folder/'stdout.log').open('wb')as out,(folder/'stderr.log').open('wb')as err:
                child=subprocess.Popen(cmd,stdout=out,stderr=err)
                try:
                    while child.poll()is None:
                        if time.monotonic()-began>20:raise TimeoutError('guest case external stop deadline')
                        if group.exists():
                            witness.observe(group)
                            for metric in ['memory.peak','pids.peak']:
                                try:observed_peaks[metric]=max(observed_peaks.get(metric,0),int((group/metric).read_text()))
                                except FileNotFoundError:pass
                        time.sleep(.03)
                finally:
                    props=stop_unit(unit,group)
                    child.wait(timeout=2)
            row={'mode':mode,'case':case,'returncode':child.returncode,'wall_seconds':time.monotonic()-began,
                'sandbox_flags':witness.flags(),'writers_stopped':True,'renderer_details':witness.details(),'terminal_unit':props}
            row['observed_peaks_before_collection']=observed_peaks
            if(folder/'result.json').exists():row['result']=json.loads((folder/'result.json').read_bytes())
            else:row['result']={'status':'failed_or_timeout','reason':'no completed bounded result'}
            runs.append(row)
            for name in ['result.json','har.json','dom.html','screenshot.png','stderr.log']:
                p=folder/name
                if not p.exists():continue
                raw=p.read_bytes();require(len(raw)<=2*1024**2,'export per-file budget')
                emit({'event':'file','nonce':nonce,'seq':seq,'name':mode+'-'+case+'/'+name,'bytes':len(raw),'sha256':sha(raw)})
                for chunk in response_chunks(nonce,seq,raw):emit({'event':'chunk','row':chunk})
                seq+=1
    for server in servers:server.shutdown();server.server_close()
    emit({'event':'done','nonce':nonce,'schema':'paw-capture-backend-experiment-v1','runs':runs,
        'network_interfaces':sorted(os.listdir('/sys/class/net')),'real_connections':0,
        'production_acceptance':False,'guest_writers_stopped':True,'fixture_requests':requests,
        'fixture_tls_verification_error':tls_error,
        'interpretation':'UID experimental capture benchmark; not Root PAW authorization, full egress/custody gate or classifier accuracy'})
if __name__=='__main__':
    if sys.argv[1]=='worker':worker(*sys.argv[2:])
    else:
        try:controller(sys.argv[2])
        except Exception as e:emit({'event':'failure','error':type(e).__name__+':'+str(e)[:2048]})
        finally:subprocess.run(['systemctl','poweroff','--no-block'],check=False)
