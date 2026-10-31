"""Ordinary-UID, no-NIC QEMU experiment. Not the privileged PAW operator.

Run inside one bounded user systemd unit. Only an owned synthetic guest is
booted. Existing Root images/code/privileges remain unchanged; output is an
experimental observation, never production authorization or acceptance.
"""
import base64, ctypes, hashlib, json, os, re, resource, selectors, signal, subprocess, sys, time, uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent;REPO=HERE.parents[1]
BASE=Path('/var/lib/libvirt/images/paw-s14/base/browser-v1.qcow2')
sys.path.insert(0,str(REPO/'paw/core'))
from browser_cdp import ResponseAssembler,strict_json

def require(v,r):
    if not v:raise ValueError(r)
def digest(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def command(overlay,iso):
    return ['/usr/bin/qemu-system-x86_64','-enable-kvm','-machine','q35,mem-merge=off,vmport=off',
        '-cpu','host,vmx=off,svm=off,pmu=off','-m','1024','-smp','1','-nodefaults','-nic','none',
        '-smbios','type=1,serial=ds=nocloud',
        '-display','none','-monitor','none','-serial','stdio','-no-reboot',
        '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
        '-drive','file='+str(overlay)+',if=virtio,format=qcow2,cache=none',
        '-drive','file='+str(iso)+',if=virtio,format=raw,readonly=on']

class Receiver:
    def __init__(self,nonce,folder):self.nonce=nonce;self.folder=folder;self.current=None;self.seq=0;self.total=0;self.files=[];self.done=None
    def feed(self,v):
        require(type(v)is dict,'frame object')
        if v.get('event')=='file':
            require(set(v)=={'event','nonce','seq','name','bytes','sha256'}and self.current is None and
                v.get('nonce')==self.nonce and type(v.get('seq'))is int and
                v['seq']==self.seq and self.seq<30 and type(v.get('name'))is str and
                re.fullmatch(r'(playwrightcapture|lacus-api)-(http-js|https-invalid|redirect)/(result\.json|har\.json|dom\.html|screenshot\.png|stderr\.log)',v['name'])and
                type(v.get('bytes'))is int and 0<=v['bytes']<=2*1024**2 and
                type(v.get('sha256'))is str and re.fullmatch('[0-9a-f]{64}',v['sha256']),'file header')
            self.total+=v['bytes'];require(self.total<=12*1024**2,'aggregate exports')
            self.current=(v,ResponseAssembler(self.nonce,self.seq,v['bytes']))
        elif v.get('event')=='chunk':
            require(set(v)=={'event','row'}and self.current is not None,'chunk without file');header,assembler=self.current;raw=assembler.feed(v['row'])
            if raw is not None:
                require(len(raw)==header['bytes']and hashlib.sha256(raw).hexdigest()==header['sha256'],'file binding')
                path=self.folder/header['name'];path.parent.mkdir(exist_ok=True);require(not path.exists(),'duplicate file')
                path.write_bytes(raw);path.chmod(0o400);self.files.append(header);self.seq+=1;self.current=None
        elif v.get('event')=='done':
            require(self.current is None and v.get('nonce')==self.nonce and self.done is None and
                v.get('network_interfaces')==['lo']and v.get('production_acceptance')is False and
                type(v.get('real_connections'))is int and v['real_connections']==0 and
                v.get('guest_writers_stopped')is True and v.get('schema')=='paw-capture-backend-experiment-v1'and
                type(v.get('runs'))is list and [(r.get('mode'),r.get('case'))for r in v['runs']]==
                [(m,c)for m in ['playwrightcapture','lacus-api']for c in ['http-js','https-invalid','redirect']],'terminal frame')
            self.done=v
        elif v.get('event')=='failure':raise ValueError('guest failure: '+str(v.get('error'))[:2048])
        else:raise ValueError('unknown frame')

def run(payload,output):
    require(os.getuid()==os.geteuid()==1000 and not output.exists(),'ordinary UID exclusive output')
    require(payload.is_dir()and(payload/'payload-manifest.json').is_file(),'prepared payload')
    cg=Path('/sys/fs/cgroup')/next(x.split('::',1)[1].lstrip('/')for x in Path('/proc/self/cgroup').read_text().splitlines()if x.startswith('0::'))
    limits={'memory.max':str(1536*1024**2),'memory.swap.max':'0','pids.max':'64','cpu.max':'50000 100000'}
    require({k:(cg/k).read_text().strip()for k in limits}==limits,'bounded user-unit required')
    require('NoNewPrivs:\t1'in Path('/proc/self/status').read_text(),'host no-new-privileges')
    require(not subprocess.check_output(['virsh','--readonly','-c','qemu:///system','list','--all','--name'],text=True).strip(),'no concurrent domain')
    require(subprocess.run(['pgrep','-f','^/usr/bin/qemu-system'],capture_output=True).returncode==1,'no concurrent QEMU')
    output.mkdir(mode=0o700);nonce=uuid.uuid4().hex;before=digest(BASE);payload_sha=digest(payload/'payload-manifest.json')
    cloud={'package_update':False,'package_upgrade':False,'ssh_pwauth':False,
        'write_files':[{'path':'/usr/local/lib/capture-benchmark.py','encoding':'b64','content':base64.b64encode((HERE/'guest.py').read_bytes()).decode(),'permissions':'0644'},
            {'path':'/etc/systemd/system/capture-benchmark.service','content':'[Unit]\nAfter=cloud-final.service\n[Service]\nExecStart=/usr/bin/python3 -I -B /usr/local/lib/capture-benchmark.py controller '+nonce+'\nStandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nMemoryMax=128M\nMemorySwapMax=0\nTasksMax=32\n'}],
        'runcmd':[['systemctl','mask','--now','ssh.service','ssh.socket','serial-getty@ttyS0.service','paw-browser.service'],
            ['mkdir','-p','/mnt/bench'],['mount','-o','ro','/dev/vdb','/mnt/bench'],['systemctl','daemon-reload'],['systemctl','--no-block','start','capture-benchmark.service']]}
    (output/'user-data').write_text('#cloud-config\n'+json.dumps(cloud));(output/'meta-data').write_bytes(canonical({'instance-id':nonce,'local-hostname':'capture-benchmark'}))
    (output/'network-config').write_bytes(canonical({'version':2,'ethernets':{}}))
    iso=output/'payload.iso';overlay=output/'overlay.qcow2'
    subprocess.run(['/usr/bin/genisoimage','-quiet','-o',str(iso),'-V','cidata','-J','-r','-graft-points',
        'user-data='+str(output/'user-data'),'meta-data='+str(output/'meta-data'),'network-config='+str(output/'network-config'),
        'payload='+str(payload)],check=True,timeout=45);iso.chmod(0o400);iso_sha=digest(iso)
    subprocess.run(['/usr/bin/qemu-img','create','-q','-f','qcow2','-F','qcow2','-b',str(BASE),str(overlay)],check=True,timeout=10)
    receiver=Receiver(nonce,output);process=None;began=time.monotonic();error=None;buffer=b'';serial_bytes=0
    try:
        with (output/'qemu.stderr.log').open('wb')as err,(output/'serial.log').open('wb')as serial:
            parent=os.getpid()
            def child_limits():
                resource.setrlimit(resource.RLIMIT_FSIZE,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                require(ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent,'parent death binding')
            process=subprocess.Popen(command(overlay,iso),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=err,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},preexec_fn=child_limits)
            os.set_blocking(process.stdout.fileno(),False);selected=selectors.DefaultSelector();selected.register(process.stdout,selectors.EVENT_READ)
            while process.poll()is None or selected.get_map():
                require(time.monotonic()-began<300,'VM experiment deadline')
                for key,_ in selected.select(.2):
                    raw=os.read(key.fileobj.fileno(),32768)
                    if not raw:selected.unregister(key.fileobj);continue
                    serial_bytes+=len(raw);require(serial_bytes<=16*1024**2,'serial budget');serial.write(raw);buffer+=raw
                    while b'\n'in buffer:
                        line,buffer=buffer.split(b'\n',1)
                        if line.startswith(b'CAPTUREBENCH '):receiver.feed(strict_json(line[len(b'CAPTUREBENCH '):]))
                    require(len(buffer)<=65536,'serial line budget')
            selected.close();require(process.returncode==0 and receiver.done is not None,'VM did not finish benchmark')
    except Exception as e:error=type(e).__name__+':'+str(e)
    finally:
        stopped=time.monotonic()
        if process is not None and process.poll()is None:process.terminate()
        if process is not None:
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
        stop_seconds=time.monotonic()-stopped
        restored=digest(BASE)==before and digest(iso)==iso_sha
        report={'schema':'paw-uid-capture-benchmark-v1','nonce':nonce,'result':'completed'if error is None else'failed',
            'error':error,'guest':receiver.done,'artifacts':receiver.files,'wall_seconds':time.monotonic()-began,
            'stop_seconds':stop_seconds,'base_sha256':before,'base_and_media_unchanged':restored,'iso_sha256':iso_sha,
            'payload_manifest_sha256':payload_sha,
            'host_limits':limits,'qemu_command':command(overlay,iso),'host_uid':os.geteuid(),'production_acceptance':False,
            'trust':'UID experiment only; no privileged PAW profile/AppArmor/Root receipt or production quota claim'}
        require(restored and stop_seconds<12,'unknown restore/stop');(output/'experiment.json').write_bytes(canonical(report))
    require(error is None,error or'benchmark failed')
    print(json.dumps({'result':report['result'],'report':str(output/'experiment.json')}))
if __name__=='__main__':
    require(len(sys.argv)==3,'prepared payload and new output required');run(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
