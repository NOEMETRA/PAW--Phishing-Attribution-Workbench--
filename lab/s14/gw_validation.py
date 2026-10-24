"""Fixed, root-supervised offline S14 gateway matrix; never accepts live targets.

Run as a bounded systemd service. It creates only transient AUTODESTROY domains,
two unnumbered private bridges and an owned synthetic WAN namespace. No NAT,
physical bridge port, Internet route, host filesystem mount or Docker is used.
"""
import argparse
import base64
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import queue
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from benign_guest_validation import BASE, Serial, digest, process_identity, guard_fingerprint
from gw_quarantine import publish

TABLES=[('inet','paw_s14_guard'),('inet','paw_s14_gateway'),('bridge','paw_s14_roles')]
BRIDGES=['pawbr-int','pawbr-wan']
HOSTS=[v+'.fixture.invalid' for v in ['allow','private','rebind','loopback','metadata','mixed','badwire','badcert']]

def canonical(value):
    if isinstance(value,list):return [canonical(v) for v in value if not isinstance(v,dict) or 'metainfo' not in v]
    if isinstance(value,dict):
        if set(value)=={'counter'}:return {'counter':{}}
        return {k:canonical(v) for k,v in value.items() if k not in {'handle','metainfo'}}
    return value

def fingerprints():
    result=[]
    for family,table in TABLES:
        value=subprocess.run(['/usr/sbin/nft','-j','list','table',family,table],capture_output=True,timeout=3)
        if value.returncode:return None
        result.append(hashlib.sha256(json.dumps(canonical(json.loads(value.stdout)),sort_keys=True).encode()).hexdigest())
    return result

def atomic(path,value):
    path=Path(path);temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value));temp.replace(path)

def owner(path):
    import libvirt
    config=json.loads(path.read_text())
    ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)
    if os.getppid()!=config['parent_pid']:return
    stopped=False;reason='owner_error'
    def stop(*_):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGTERM,stop)
    connection=libvirt.open('qemu:///system');domains=[]
    try:
        if fingerprints()!=config['filters'] or guard_fingerprint() is None:raise RuntimeError('effective_filter_admission')
        if any(v['identity'] is None or process_identity(v['pid'])!=v['identity'] for v in config['processes']):raise RuntimeError('health_process_admission')
        ready=[]
        for xml in config['xml']:
            domain=connection.createXML(Path(xml).read_text(),libvirt.VIR_DOMAIN_START_PAUSED|libvirt.VIR_DOMAIN_START_AUTODESTROY)
            domains.append(domain)
            pid=int(Path('/run/libvirt/qemu',domain.name()+'.pid').read_text())
            cg=Path('/proc',str(pid),'cgroup').read_text().split('0::',1)[1].strip()
            unit=next(p for p in Path(cg).parts if p.endswith('.scope'))
            subprocess.run(['/usr/bin/systemctl','set-property','--runtime',unit,'TasksMax=64','MemoryMax=768M','MemorySwapMax=0','CPUQuota=50%'],check=True)
            scope=Path('/sys/fs/cgroup/machine.slice/machine-paws14.slice')/unit
            assert 'machine-paws14.slice' in cg and (scope/'pids.max').read_text().strip()=='64'
            assert (scope/'memory.max').read_text().strip()==str(768*1024**2)
            assert (scope/'memory.swap.max').read_text().strip()=='0'
            label=Path('/proc',str(pid),'attr/current').read_text().strip()
            assert label.startswith('libvirt-') and '(enforce)' in label
            uid=next(v for v in Path('/proc',str(pid),'status').read_text().splitlines() if v.startswith('Uid:'))
            assert all(int(v)!=0 for v in uid.split()[1:])
            ready.append({'uuid':domain.UUIDString(),'name':domain.name(),'pid':pid,'identity':process_identity(pid),
                          'scope':str(scope),'apparmor':label,'uid':uid,
                          'limits':{p:(scope/p).read_text().strip() for p in ['pids.max','memory.max','memory.swap.max','cpu.max']}})
        atomic(config['ready'],ready)
        start=time.monotonic();clock_offset=time.time()-start;resumed=False
        while not stopped:
            control=json.loads(Path(config['control']).read_text())
            if fingerprints()!=config['filters']:reason='host_filter_changed';break
            if any(process_identity(v['pid'])!=v['identity'] for v in ready):reason='domain_process_lost';break
            if any(process_identity(v['pid'])!=v['identity'] for v in config['processes']):reason='capture_or_fixture_lost';break
            if abs((time.time()-time.monotonic())-clock_offset)>3:reason='host_clock_changed';break
            if time.monotonic()-start>300 or time.monotonic()>control.get('expiry',float('inf')):reason='deadline';break
            if control.get('abort'):reason=control['abort'];break
            if control.get('heartbeat',0)<time.monotonic()-3:reason='management_heartbeat_lost';break
            if control.get('resume') and not resumed:
                for domain in domains:domain.resume()
                resumed=True
            # Unexpected ports or host addresses invalidate the frozen topology.
            for bridge in BRIDGES:
                allowed={'pgw-worker','pgw-lan'} if bridge=='pawbr-int' else {'pgw-wan','pgw-fixture'}
                ports={p.name for p in Path('/sys/class/net',bridge,'brif').iterdir()}
                if not ports<=allowed:reason='unexpected_bridge_port';stopped=True
                addresses=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show',bridge]))
                if addresses[0]['addr_info']:reason='numbered_private_bridge';stopped=True
            time.sleep(.25)
        if reason=='owner_error' and stopped:reason='requested_stop'
    finally:
        connection.close()
        atomic(config['result'],{'reason':reason,'connection_closed':True})

class Channel:
    def __init__(self,path,log):
        self.serial=Serial(path,log);self.responses=queue.Queue();self.health=None;self.health_at=None
        self.failure=None;self.lock=threading.Lock();self.done=False
        self.thread=threading.Thread(target=self.read,daemon=True);self.thread.start()
    def read(self):
        while not self.done:
            try:value=self.serial.message(1)
            except TimeoutError:continue
            except Exception as error:self.failure=str(error);return
            if value.get('health'):self.health=value;self.health_at=time.monotonic()
            else:self.responses.put(value)
    def ready(self,seconds=180):
        value=self.responses.get(timeout=seconds);assert value.get('ready'),value;return value
    def call(self,op,seconds=15,**values):
        with self.lock:
            self.serial.sequence+=1;ident=self.serial.sequence
            os.write(self.serial.fd,json.dumps({'id':ident,'op':op,**values}).encode()+b'\n')
            value=self.responses.get(timeout=seconds)
            assert value.get('id')==ident and value.get('ok'),value
            return value['data']
    def close(self):
        self.done=True;self.thread.join(timeout=2);self.serial.close()

class Matrix:
    def __init__(self,args):
        import libvirt
        self.args=args;self.output=args.output;self.output.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.libvirt=libvirt;libvirt.registerErrorHandler(lambda *_:None,None)
        self.connection=libvirt.open('qemu:///system')
        self.report={'result':'FAIL','scope':'offline-fixture; live transport unavailable','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commands':[],'jobs':[]}
        self.processes=[];self.active=None;self.network_created=False;self.namespace=False;self.link=False
        self.root_image_sha=digest(BASE)
        assert self.root_image_sha=='b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658'
        assert BASE.stat().st_uid==0 and BASE.stat().st_mode&0o777==0o444
        sources=[p for p in HERE.iterdir() if p.suffix in {'.py','.nft','.xml','.service','.conf','.slice'}]
        self.source_hashes={p.name:digest(p) for p in sources}
        (self.output/'sources').mkdir()
        for path in sources:shutil.copyfile(path,self.output/'sources'/path.name)
        self.report['source_hashes']=self.source_hashes
    def run(self,argv,required=True):
        value=subprocess.run(argv,capture_output=True,text=True,timeout=45)
        self.report['commands'].append({'argv':argv,'code':value.returncode,'stdout':value.stdout,'stderr':value.stderr})
        if required and value.returncode:raise RuntimeError(str(argv)+': '+value.stderr)
        return value
    def spawn(self,argv,name):
        with (self.output/(name+'.log')).open('wb') as log:process=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True)
        self.processes.append(process);return process
    def wait_file(self,path,seconds=15):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if path.exists() and path.stat().st_size:return json.loads(path.read_text())
            time.sleep(.1)
        raise TimeoutError(str(path))
    def filters(self):
        for file in ['gateway-host.nft','gateway-bridge.nft']:self.run(['/usr/sbin/nft','-f',str(HERE/file)])
        assert guard_fingerprint() is not None and fingerprints() is not None
        self.expected=fingerprints()
    def prepare(self):
        assert Path('/proc/self/attr/current').read_text().strip()=='unconfined','Use PID1 systemd service, not desktop scope'
        assert not self.connection.listAllDomains(0),'Existing domains require review'
        for bridge in ['pawbr-int']:
            info=json.loads(self.run(['/usr/sbin/ip','-j','address','show',bridge]).stdout)[0]
            assert not info['addr_info'] and not list(Path('/sys/class/net',bridge,'brif').iterdir())
        assert not Path('/sys/class/net/pawbr-wan').exists() and not Path('/run/netns/pawgwan').exists()
        self.filters()
        self.wan=self.connection.networkDefineXML((HERE/'gateway-wan.xml').read_text());self.network_created=True
        self.wan.setAutostart(0);self.wan.create()
        for bridge in BRIDGES:self.run(['/usr/sbin/sysctl','-w','net.ipv6.conf.'+bridge+'.disable_ipv6=1'])
        routes=json.loads(self.run(['/usr/sbin/ip','-j','route']).stdout)
        default=next(v for v in routes if v.get('dst')=='default')
        addresses=json.loads(self.run(['/usr/sbin/ip','-j','address','show',default['dev']]).stdout)[0]
        self.host_ip=next(v['local'] for v in addresses['addr_info'] if v['family']=='inet')
        self.report['host_inventory']={'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'routes':routes,'management':addresses,
            'versions':{v:self.run(cmd).stdout for v,cmd in [('qemu',['/usr/bin/qemu-system-x86_64','--version']),('nft',['/usr/sbin/nft','--version']),('kernel',['/usr/bin/uname','-a'])]},
            'slice':self.run(['/usr/bin/systemctl','show','machine-paws14.slice','-p','MemoryMax','-p','MemorySwapMax','-p','TasksMax','-p','CPUQuotaPerSecUSec']).stdout}
        self.run(['/usr/sbin/ip','netns','add','pawgwan']);self.namespace=True
        self.run(['/usr/sbin/ip','link','add','pgw-fixture','type','veth','peer','name','pgw-fixturep']);self.link=True
        self.run(['/usr/sbin/ip','link','set','pgw-fixturep','netns','pawgwan'])
        self.run(['/usr/sbin/ip','-n','pawgwan','link','set','pgw-fixturep','name','eth0'])
        self.run(['/usr/sbin/ip','-n','pawgwan','link','set','eth0','address','52:54:00:14:40:10'])
        for address in ['198.18.40.10/24','198.18.40.11/24']:self.run(['/usr/sbin/ip','-n','pawgwan','address','add',address,'dev','eth0'])
        for device in ['eth0','lo']:self.run(['/usr/sbin/ip','-n','pawgwan','link','set',device,'up'])
        self.run(['/usr/sbin/ip','netns','exec','pawgwan','/usr/sbin/sysctl','-w','net.ipv4.ip_forward=0','net.ipv6.conf.all.disable_ipv6=1'])
        self.run(['/usr/sbin/ip','link','set','pgw-fixture','master','pawbr-wan'])
        self.run(['/usr/sbin/sysctl','-w','net.ipv6.conf.pgw-fixture.disable_ipv6=1'])
        self.run(['/usr/sbin/ip','link','set','pgw-fixture','up'])
        (self.output/'fixture.json').write_text(json.dumps({'host_ip':self.host_ip}))
        self.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=PAW offline fixture CA','-keyout',str(self.output/'ca.key'),'-out',str(self.output/'ca.pem')])
        self.run(['/usr/bin/openssl','req','-newkey','rsa:2048','-nodes','-subj','/CN=allow.fixture.invalid','-keyout',str(self.output/'server.key'),'-out',str(self.output/'server.csr')])
        (self.output/'server.ext').write_text('subjectAltName=DNS:allow.fixture.invalid\nextendedKeyUsage=serverAuth\n')
        self.run(['/usr/bin/openssl','x509','-req','-in',str(self.output/'server.csr'),'-CA',str(self.output/'ca.pem'),'-CAkey',str(self.output/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(self.output/'server.ext'),'-out',str(self.output/'server.pem')])
        self.fixture=self.spawn(['/usr/sbin/ip','netns','exec','pawgwan','/usr/bin/python3','-I',str(HERE/'gw_fixture.py'),'--directory',str(self.output)],'wan-process')
        self.wait_file(self.output/'wan-ready.json')
        # Positive controls contact only local addresses in their own namespace.
        self.run(['/usr/sbin/ip','netns','exec','pawgwan','/usr/bin/python3','-I','-c',"import socket; s=socket.create_connection(('198.18.40.11',18080)); s.sendall(b'GET /positive HTTP/1.0\\r\\n\\r\\n'); assert b'200' in s.recv(512);s.close()"])
        canary="import http.server,json,pathlib,sys,time; p=pathlib.Path(sys.argv[2]);\nclass H(http.server.BaseHTTPRequestHandler):\n def log_message(self,*a):pass\n def do_GET(self):\n  with p.open('a') as f:f.write(json.dumps({'peer':self.client_address[0],'path':self.path})+'\\n')\n  self.send_response(200);self.end_headers();self.wfile.write(b'OWNED HOST')\nhttp.server.HTTPServer((sys.argv[1],18080),H).serve_forever()"
        self.canary=self.spawn(['/usr/bin/python3','-I','-c',canary,self.host_ip,str(self.output/'host-canary.jsonl')],'host-canary')
        time.sleep(.3)
        with socket.create_connection((self.host_ip,18080),timeout=2) as client:
            client.sendall(b'GET /positive HTTP/1.0\r\n\r\n');assert b'200' in client.recv(512)
        self.report['positive_controls']='owned host + forbidden WAN listener confirmed'
        self.report['runtime_provenance']=json.loads((self.args.assets/'nft-runtime-provenance.json').read_text())
        for item in self.report['runtime_provenance']['files']:
            assert digest(self.args.assets/item['bundle_name'])==item['sha256']
        for name,target in self.report['runtime_provenance']['aliases'].items():
            assert (self.args.assets/name).is_symlink() and os.readlink(self.args.assets/name)==target

    def seed(self,folder,role,job_id,token):
        files=[('/usr/local/lib/paw-s14/'+name,(HERE/name).read_bytes()) for name in ['gw_node.py','gw_broker.py','gw_admission.py']]
        cfg={'role':role,'job_id':job_id,'token':token,'host_ip':self.host_ip}
        files += [('/etc/paw-node.json',json.dumps(cfg).encode()),('/etc/paw-gateway.json',json.dumps({**cfg,'mode':'offline-fixture','hosts':HOSTS}).encode()),
                  ('/etc/paw-gateway.nft',(HERE/'gateway-guest.nft').read_bytes()),('/etc/paw-fixture-ca.pem',(self.output/'ca.pem').read_bytes())]
        service='[Unit]\nAfter=cloud-final.service\n[Service]\nExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/gw_node.py\nStandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTasksMax=32\nMemoryMax=128M\nCPUQuota=50%\nStateDirectory=paw-s14\n'
        files.append(('/etc/systemd/system/paw-s14-node.service',service.encode()))
        cloud={'package_update':False,'package_upgrade':False,'ssh_pwauth':False,'ssh_genkeytypes':[],
               'write_files':[{'path':p,'encoding':'b64','content':base64.b64encode(v).decode(),'permissions':'0600' if p.endswith('.json') else '0644'} for p,v in files],
               'runcmd':[['mkdir','-p','/mnt/paw-seed','/opt/paw-nft'],['mount','-o','ro','/dev/vdb','/mnt/paw-seed'],
                         ['cp','-a','/mnt/paw-seed/nft-runtime/.','/opt/paw-nft/'],['umount','/mnt/paw-seed'],
                         ['systemctl','mask','--now','ssh.service','ssh.socket','serial-getty@ttyS0.service'],
                         ['systemctl','daemon-reload'],['systemctl','--no-block','start','paw-s14-node.service']]}
        interfaces={}
        if role in {'worker','gateway'}:
            interfaces['lan0']={'match':{'macaddress':'52:54:00:14:00:20' if role=='worker' else '52:54:00:14:00:01'},'set-name':'lan0','dhcp4':False,'dhcp6':False,'accept-ra':False,'link-local':[],
                                'addresses':['192.0.2.20/24' if role=='worker' else '192.0.2.1/24']}
            if role=='worker':interfaces['lan0']['routes']=[{'to':value,'via':'192.0.2.1','on-link':True} for value in [self.host_ip+'/32','198.18.40.0/24']]
        if role=='gateway':interfaces['wan0']={'match':{'macaddress':'52:54:00:14:40:02'},'set-name':'wan0','dhcp4':False,'dhcp6':False,'accept-ra':False,'link-local':[],'addresses':['198.18.40.2/24']}
        (folder/'user-data').write_text('#cloud-config\n'+json.dumps(cloud));(folder/'meta-data').write_text(json.dumps({'instance-id':job_id+'-'+role,'local-hostname':'paw-'+role}))
        (folder/'network-config').write_text(json.dumps({'version':2,'ethernets':interfaces}))
        shutil.copytree(self.args.assets,folder/'nft-runtime',symlinks=True)
        self.run(['/usr/bin/genisoimage','-quiet','-output',str(folder/'seed.iso'),'-volid','cidata','-joliet','-rock','-graft-points',str(folder/'user-data'),str(folder/'meta-data'),str(folder/'network-config'),'nft-runtime='+str(folder/'nft-runtime')])
        (folder/'seed.iso').chmod(0o444)

    def descriptor(self,role,case,job_id,token,source=None):
        identifier=str(uuid.uuid4());folder=Path('/var/lib/libvirt/images/paw-s14/runs')/identifier
        folder.mkdir(mode=0o755,parents=True);overlay=folder/'overlay.qcow2';qemu=pwd.getpwnam('libvirt-qemu')
        self.run(['/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2','-b',str(BASE),str(overlay)])
        os.chown(overlay,qemu.pw_uid,qemu.pw_gid);overlay.chmod(0o600);self.seed(folder,role,job_id,token)
        root=ET.fromstring((HERE/'paused-probe.xml').read_text());root.find('name').text='pawgw-'+case+'-'+role
        ET.SubElement(root,'uuid').text=identifier
        for tag in ['memory','currentMemory']:root.find(tag).text='512'
        root.find('memtune/hard_limit').text='768';root.find('memtune/swap_hard_limit').text='768'
        dac=ET.SubElement(root,'seclabel',{'type':'static','model':'dac','relabel':'no'});ET.SubElement(dac,'label').text=f'+{qemu.pw_uid}:+{qemu.pw_gid}'
        ET.SubElement(ET.SubElement(root,'resource'),'partition').text='/machine/paws14'
        ET.SubElement(root.find('os'),'smbios',{'mode':'sysinfo'})
        ET.SubElement(ET.SubElement(ET.SubElement(root,'sysinfo',{'type':'smbios'}),'system'),'entry',{'name':'serial'}).text='ds=nocloud'
        devices=root.find('devices');devices.remove(devices.find('interface'))
        for network,mac,tap in ([('paw-s14-internal','52:54:00:14:00:20','pgw-worker')] if role=='worker' else
                                [('paw-s14-internal','52:54:00:14:00:01','pgw-lan'),('paw-s14-wan','52:54:00:14:40:02','pgw-wan')] if role=='gateway' else []):
            nic=ET.SubElement(devices,'interface',{'type':'network'});ET.SubElement(nic,'source',{'network':network});ET.SubElement(nic,'model',{'type':'virtio'});ET.SubElement(nic,'mac',{'address':mac});ET.SubElement(nic,'target',{'dev':tap})
        # Attach an evidence disk only after the extractor has mounted its own
        # root/boot partitions: clones share UUIDs, and early discovery can make
        # fstab select the read-only evidence disk for /boot.
        for path,target,kind,readonly in [(overlay,'vda','qcow2',False),(folder/'seed.iso','vdb','raw',True)]:
            disk=ET.SubElement(devices,'disk',{'type':'file','device':'disk'});ET.SubElement(disk,'driver',{'name':'qemu','type':kind});ET.SubElement(disk,'source',{'file':str(path)});ET.SubElement(disk,'target',{'dev':target,'bus':'virtio'})
            if readonly:ET.SubElement(disk,'readonly')
        serial=ET.SubElement(devices,'serial',{'type':'pty'});ET.SubElement(serial,'target',{'type':'isa-serial','port':'0'});ET.SubElement(devices,'console',{'type':'pty'})
        xml=self.output/(case+'-'+role+'.xml');xml.write_bytes(ET.tostring(root))
        return {'xml':xml,'folder':folder,'overlay':overlay,'uuid':identifier,'role':role}

    def job(self,case,source=None):
        print('Starting offline gateway case: '+case,flush=True)
        self.filters();job_id=str(uuid.uuid4());token=uuid.uuid4().hex
        nodes=[self.descriptor(role,case,job_id,token,source) for role in (['extractor'] if source else ['gateway','worker'])]
        captures=[]
        for bridge in BRIDGES:
            with (self.output/(case+'-'+bridge+'.pcap')).open('wb') as data,(self.output/(case+'-'+bridge+'-capture.log')).open('wb') as log:
                process=subprocess.Popen(['/usr/bin/prlimit','--fsize=8388608:8388608','--','/usr/bin/tcpdump','-i',bridge,'-nn','-s','256','-U','-Z','tcpdump','-w','-'],stdout=data,stderr=log)
            self.processes.append(process);captures.append(process)
            deadline=time.monotonic()+3
            while (self.output/(case+'-'+bridge+'.pcap')).stat().st_size<24 and time.monotonic()<deadline and process.poll() is None:time.sleep(.05)
            assert process.poll() is None and process_identity(process.pid) is not None and (self.output/(case+'-'+bridge+'.pcap')).stat().st_size>=24,'capture_not_ready'
        control=self.output/(case+'-control.json');ready=self.output/(case+'-ready.json')
        config={'parent_pid':os.getpid(),'filters':self.expected,'xml':[str(v['xml']) for v in nodes],
                'processes':[{'pid':p.pid,'identity':process_identity(p.pid)} for p in captures+[self.fixture,self.canary]],
                'ready':str(ready),'control':str(control),'result':str(self.output/(case+'-owner-result.json'))}
        atomic(control,{'heartbeat':time.monotonic()});path=self.output/(case+'-owner.json');atomic(path,config)
        process=self.spawn(['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--owner',str(path)],case+'-owner')
        active={'case':case,'nodes':nodes,'captures':captures,'owner':process,'control':control,'state':{'resume':False},'channels':{},'ready':[],
                'monitor_done':False,'health_required':False,'filter_hash':None,'health_reason':None}
        self.active=active
        def monitor():
            while not active['monitor_done']:
                state={**active['state'],'heartbeat':time.monotonic()}
                gateway=active['channels'].get('gateway')
                if active['health_required'] and gateway:
                    health=gateway.health
                    if not health or time.monotonic()-(gateway.health_at or 0)>3:state['abort']='gateway_heartbeat_lost'
                    elif not all(health['children'].values()):state['abort']='broker_or_dns_lost'
                    elif health['filter']!=active['filter_hash']:state['abort']='guest_filter_changed'
                    elif abs((health['utc']-health['monotonic'])-active['clock_offset'])>2:state['abort']='guest_clock_changed'
                if 'abort' in state and active['health_reason'] is None:active['health_reason']=state['abort']
                slice_path=Path('/sys/fs/cgroup/machine.slice/machine-paws14.slice')
                for key,file in [('memory_bytes','memory.current'),('tasks','pids.current')]:
                    value=int((slice_path/file).read_text());active.setdefault('peak',{})[key]=max(value,active.get('peak',{}).get(key,0))
                atomic(control,state);time.sleep(.2)
        active['monitor']=threading.Thread(target=monitor,daemon=True);active['monitor'].start()
        try:active['ready']=self.wait_file(ready,30)
        except Exception:
            print((self.output/(case+'-owner.log')).read_text()[-4000:],flush=True);raise
        for node,actual in zip(nodes,active['ready']):
            domain=self.connection.lookupByUUIDString(node['uuid']);xml=ET.fromstring(domain.XMLDesc(0))
            node['actual']=actual;node['channel']=Channel(xml.find('devices/serial/source').get('path'),self.output/(case+'-'+node['role']+'-serial.log'))
            active['channels'][node['role']]=node['channel']
        active['state']['resume']=True
        try:
            for node in nodes:node['channel'].ready(240 if source else 180)
        except Exception:
            for node in nodes:print((self.output/(case+'-'+node['role']+'-serial.log')).read_text(errors='replace')[-5000:],flush=True)
            raise
        if source:
            disk=ET.Element('disk',{'type':'file','device':'disk'})
            ET.SubElement(disk,'driver',{'name':'qemu','type':'qcow2'});ET.SubElement(disk,'source',{'file':str(source)})
            ET.SubElement(disk,'target',{'dev':'vdc','bus':'virtio'});ET.SubElement(disk,'readonly')
            domain=self.connection.lookupByUUIDString(nodes[0]['uuid'])
            domain.attachDeviceFlags(ET.tostring(disk,encoding='unicode'),self.libvirt.VIR_DOMAIN_AFFECT_LIVE)
            (self.output/'extractor-attached.xml').write_text(domain.XMLDesc(0));time.sleep(1)
        if 'gateway' in active['channels']:
            gateway=active['channels']['gateway'];deadline=time.monotonic()+5
            while gateway.health is None and time.monotonic()<deadline:time.sleep(.1)
            assert gateway.health and gateway.health['filter']
            active['filter_hash']=gateway.health['filter'];active['clock_offset']=gateway.health['utc']-gateway.health['monotonic'];active['health_required']=True
            gateway.call('activate',ttl=120)
        record={'case':case,'nodes':[{k:str(v) if isinstance(v,Path) else v for k,v in node.items() if k!='channel'} for node in nodes],
                'states':{role:ch.call('state') for role,ch in active['channels'].items()},'status':'running'}
        if 'gateway' in active['channels']:
            health=active['channels']['gateway'].health
            record['clock_observation']={'guest_utc':health['utc'],'host_receipt_utc':time.time(),
                 'absolute_offset_upper_bound_seconds':abs(health['utc']-time.time()),'guest_utc_minus_monotonic':active['clock_offset'],
                 'health_timeout_seconds':3,'clock_step_tolerance_seconds':2}
        self.report['jobs'].append(record);active['record']=record
        if 'worker' in active['channels']:assert not active['channels']['worker'].call('marker')['previous']
        print('Trusted nodes ready: '+case,flush=True)
        return active['channels']

    def stopped(self,seconds=12):
        active=self.active;end=time.monotonic()+seconds
        while time.monotonic()<end:
            stopped=True
            for node in active['nodes']:
                try:self.connection.lookupByUUIDString(node['uuid']);stopped=False
                except self.libvirt.libvirtError:pass
                actual=node.get('actual')
                if actual and process_identity(actual['pid'])==actual['identity']:stopped=False
                pattern=b'-uuid\0'+node['uuid'].encode()+b'\0'
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():continue
                    try:
                        if pattern in (proc/'cmdline').read_bytes():stopped=False
                    except (FileNotFoundError,PermissionError,ProcessLookupError):pass
            if any(Path('/sys/class/net',p).exists() for p in ['pgw-worker','pgw-lan','pgw-wan']):stopped=False
            if stopped:return True
            time.sleep(.1)
        return False

    def logs(self):
        channel=self.active['channels'].get('gateway')
        if not channel:return
        for name in ['broker.jsonl','dns.jsonl']:
            data=bytearray();total=1
            while len(data)<total:
                value=channel.call('log',name=name,offset=len(data));total=value['total'];chunk=bytes.fromhex(value['hex'])
                if not chunk and len(data)<total:raise ValueError('incomplete_gateway_log')
                data.extend(chunk)
            (self.output/(self.active['case']+'-'+name)).write_bytes(data)

    def events(self):
        return [json.loads(line) for line in (self.output/'wan.jsonl').read_text().splitlines()]

    def counter_snapshot(self):
        state=json.loads(self.run(['/usr/sbin/nft','-j','list','table','bridge','paw_s14_roles']).stdout)
        return [sum(e['counter']['packets'] for e in v['rule']['expr'] if 'counter' in e) for v in state['nftables']
                if 'rule' in v and any('drop' in e for e in v['rule']['expr'])]

    def traffic(self,channels):
        worker=channels['worker'];observations={}
        def fetch(name,url,status,reason=None,**kwargs):
            value=worker.call('fetch',url=url,**kwargs);body=value['body'];observations[name]=value
            assert body['status']==status,(name,value)
            if reason:assert reason in body.get('reason',''),(name,value)
            return body
        fetch('tls_verified','https://allow.fixture.invalid:8443/ok','completed')
        redirect=fetch('redirect_allowed','http://allow.fixture.invalid:18080/redirect-ok','completed');assert len(redirect['hops'])==2
        fetch('redirect_private','http://allow.fixture.invalid:18080/redirect-private','refused','dns_forbidden_address')
        fetch('rebinding','http://rebind.fixture.invalid:18080/rebind','refused','dns_forbidden_address')
        for name in ['loopback','metadata','mixed']:
            fetch(name,'http://'+name+'.fixture.invalid:18080/forbidden','refused','dns_forbidden_address')
        fetch('bad_dns_wire','http://badwire.fixture.invalid:18080/forbidden','refused','dns_reply_identity')
        fetch('bad_tls_name','https://badcert.fixture.invalid:8443/forbidden','unavailable','SSLCertVerificationError')
        fetch('response_budget','http://allow.fixture.invalid:18080/oversize','refused','response_bytes')
        fetch('redirect_budget','http://allow.fixture.invalid:18080/loop','refused','redirect_limit')
        fetch('wrong_job_token','http://allow.fixture.invalid:18080/forbidden','refused','job_token',token='wrong-owned-token')
        method=worker.call('fetch',url='http://allow.fixture.invalid:18080/forbidden',method='CONNECT');observations['connect_refused']=method;assert method['http_status']==405
        for number,url in enumerate(['http://127.1:18080/','http://2130706433:18080/','http://[::ffff:127.0.0.1]:18080/',
                                     'http://unknown.fixture.invalid:18080/','http://allow.fixture.invalid:80/']):
            fetch('bad_url_'+str(number),url,'refused')
        observations['dns_allowed']=worker.call('dns',name='allow.fixture.invalid');assert observations['dns_allowed']['rcode']==0
        observations['dns_forbidden']=worker.call('dns',name='private.fixture.invalid');assert observations['dns_forbidden']['rcode']!=0
        observations['probes']=worker.call('probes');assert all(not item.get('connected') and not item.get('udp_response') for item in observations['probes'])
        # Every L2 mutation uses the otherwise permitted DNS query. Verify the
        # positive control first, then a drop counter AND no WAN DNS transaction.
        before=len(self.events());worker.call('raw',case='valid-dns');time.sleep(.3)
        assert len([v for v in self.events()[before:] if v['event']=='dns'])==1
        raw={}
        for case in ['direct-wan','spoof-ip','spoof-mac','fragment','ip-in-ip','ipv6-tunnel','gre','vlan','qinq','mpls','ipv6','arp-poison']:
            counts=self.counter_snapshot();events=len(self.events());value=worker.call('raw',case=case);time.sleep(.2);after=self.counter_snapshot()
            assert any(b>a for a,b in zip(counts,after)),(case,'no filter counter')
            assert not [v for v in self.events()[events:] if v['event'] in {'dns','http'}],case
            raw[case]={'sent':value,'counter_deltas':[b-a for a,b in zip(counts,after)],'no_fixture_request':True}
        observations['l2']=raw
        observations['storage_full']=worker.call('storage_full');assert observations['storage_full']['enospc']
        observations['output']=worker.call('output');assert observations['output']['created']==7
        # Exhaust the finite request count without a real destination.
        for number in range(33):
            value=worker.call('fetch',url='http://allow.fixture.invalid:18080/ok')
            if value['body'].get('reason')=='budget':break
        else:raise AssertionError('request count did not close')
        observations['request_budget']={'additional_requests':number+1,'last':value}
        events=self.events()
        assert not [v for v in events if v['event']=='http' and v['path'] in {'/forbidden','/second'}]
        assert len([v for v in events if v['event']=='http' and v['local']=='198.18.40.11'])==1,'Only namespace positive control may reach denied WAN IP'
        canary=[json.loads(line) for line in (self.output/'host-canary.jsonl').read_text().splitlines()]
        assert len(canary)==1 and canary[0]['path']=='/positive',canary
        observations['host_and_forbidden_wan_canaries_unchanged']=True
        self.report['jobs'][-1]['traffic']=observations
        self.logs()

    def failures(self):
        for case in ['proxy-loss','dns-loss','host-inet-loss','host-l2-loss','guest-filter-loss','clock-back','capture-loss','supervisor-loss','management-loss','expiry']:
            channels=self.job(case);worker=channels['worker'];gateway=channels['gateway'];events=len(self.events())
            worker.call('async_fetch');time.sleep(.4)
            assert any(v['event']=='stream_start' for v in self.events()[events:]),'Established benign stream required'
            self.logs();triggered=time.monotonic()
            if case=='proxy-loss':gateway.call('kill',component='broker')
            elif case=='dns-loss':gateway.call('kill',component='dns')
            elif case=='host-inet-loss':self.run(['/usr/sbin/nft','flush','table','inet','paw_s14_gateway'])
            elif case=='host-l2-loss':self.run(['/usr/sbin/nft','flush','table','bridge','paw_s14_roles'])
            elif case=='guest-filter-loss':gateway.call('remove_filter')
            elif case=='clock-back':gateway.call('clock_back')
            elif case=='capture-loss':self.active['captures'][0].terminate();self.active['captures'][0].wait(timeout=4)
            elif case=='supervisor-loss':self.active['owner'].kill()
            elif case=='management-loss':self.active['monitor_done']=True;self.active['monitor'].join(timeout=2)
            elif case=='expiry':self.active['state']['expiry']=time.monotonic()+1
            assert self.stopped(),case
            latency=time.monotonic()-triggered;assert latency<12
            self.report['jobs'][-1]['stop_latency_seconds']=latency
            self.finish(case)
            # Closed owner connection and absent QEMU/TAP are the external
            # established-flow cessation oracle, independent of the guest.
            print('Failure closed and writers stopped: '+case,flush=True)

    def extract(self,source):
        before=digest(source);channels=self.job('extractor',source=source)
        result=channels['extractor'].call('extract',seconds=30)
        assert result['network_interfaces']==1 and len(result['accepted'])==3 and len(result['refused'])==4,result
        self.report['jobs'][-1]['extraction']=result
        self.finish('normal');assert digest(source)==before,'Read-only source changed'
        manifest=publish(self.output/'quarantine',result['accepted'],stopped=True)
        (self.output/'quarantine-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        self.report['quarantine']={'source_sha256_unchanged':before,'accepted':manifest,'refused':result['refused'],
                                  'only_loopback_in_extractor':True,'host_guest_filesystem_mount':False}

    def admission_faults(self):
        assert not self.connection.listAllDomains(0)
        previous=json.loads((self.output/'traffic-owner.json').read_text());evidence=[]
        for family,table in TABLES:
            for state in ['empty','absent']:
                try:
                    self.run(['/usr/sbin/nft','flush' if state=='empty' else 'delete','table',family,table])
                    config={**previous,'parent_pid':os.getpid(),'ready':str(self.output/(table+'-'+state+'-ready.json')),
                            'result':str(self.output/(table+'-'+state+'-result.json'))}
                    path=self.output/(table+'-'+state+'-reject.json');atomic(path,config)
                    result=self.run(['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--owner',str(path)],required=False)
                    assert result.returncode!=0 and not Path(config['ready']).exists()
                    assert not self.connection.listAllDomains(0)
                    evidence.append({'family':family,'table':table,'state':state,'rejected_before_creation':True})
                finally:
                    self.run(['/usr/sbin/nft','-f',str(HERE/'host-guard.nft')]);self.filters()
        # A dead capture cannot be represented by a missing PID identity and
        # admitted as healthy merely because both observations equal None.
        config={**previous,'parent_pid':os.getpid(),'processes':[{'pid':2147483647,'identity':None}],
                'ready':str(self.output/'dead-capture-ready.json'),'result':str(self.output/'dead-capture-result.json')}
        path=self.output/'dead-capture-reject.json';atomic(path,config)
        value=self.run(['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--owner',str(path)],required=False)
        assert value.returncode!=0 and not Path(config['ready']).exists() and not self.connection.listAllDomains(0)
        evidence.append({'process':'dead-capture','rejected_before_creation':True})
        self.report['admission_faults']=evidence

    def startup(self):
        assert not self.connection.listAllDomains(0)
        self.connection.close()
        root=Path('/etc/paw-s14');root.mkdir(mode=0o755,exist_ok=True)
        for file in ['host-guard.nft','gateway-host.nft','gateway-bridge.nft']:
            shutil.copyfile(HERE/file,root/file);(root/file).chmod(0o644)
        shutil.copyfile(HERE/'all-guards.nft',root/'all-guards.nft')
        unit=Path('/etc/systemd/system/paw-s14-guard.service')
        shutil.copyfile(HERE/'paw-s14-guard.service',unit)
        override=Path('/run/systemd/system/paw-s14-guard.service.d/99-paw-s14-negative-test.conf')
        assert not override.exists()
        sockets=['libvirtd.socket','libvirtd-ro.socket','libvirtd-admin.socket']
        try:
            self.run(['/usr/bin/systemctl','stop',*sockets,'libvirtd.service'])
            self.run(['/usr/bin/systemctl','stop','paw-s14-guard.service'])
            override.parent.mkdir(parents=True,exist_ok=True)
            override.write_text('[Service]\nExecStart=\nExecStart=/bin/false\n')
            self.run(['/usr/bin/systemctl','daemon-reload'])
            value=self.run(['/usr/bin/systemctl','start','libvirtd.service'],required=False)
            guard=self.run(['/usr/bin/systemctl','is-failed','paw-s14-guard.service'],required=False)
            daemon=self.run(['/usr/bin/systemctl','is-active','libvirtd.service'],required=False)
            assert value.returncode!=0 and guard.stdout.strip()=='failed' and daemon.stdout.strip()!='active'
            self.report['startup_failure']={'guard_failed':True,'libvirt_start_rejected':True,'no_guest_autostart':True,'whole_host_reboot':'not_measured'}
        finally:
            override.unlink(missing_ok=True)
            self.run(['/usr/bin/systemctl','daemon-reload'])
            self.run(['/usr/bin/systemctl','reset-failed','paw-s14-guard.service','libvirtd.service'],required=False)
            self.run(['/usr/bin/systemctl','start','paw-s14-guard.service'])
            self.run(['/usr/bin/systemctl','start',*sockets,'libvirtd.service'])
            self.connection=self.libvirt.open('qemu:///system')
            # Network handles are tied to the pre-restart libvirt connection.
            # Reacquire this owned network before the final cleanup.
            if self.network_created:self.wan=self.connection.networkLookupByName('paw-s14-wan')
        assert fingerprints()==self.expected and not self.connection.listAllDomains(0)
        self.report['persistent_guard']={'unit_sha256':digest(unit),'all_rules_sha256':{p.name:digest(p) for p in root.glob('*.nft')},
                                        'dependencies':self.run(['/usr/bin/systemctl','show','libvirtd.service','-p','Requires','-p','After']).stdout}

    def finish(self,reason):
        active=self.active
        if active['owner'].poll() is None:active['owner'].terminate()
        try:active['owner'].wait(timeout=10)
        except subprocess.TimeoutExpired:active['owner'].kill();active['owner'].wait(timeout=5)
        stopped=self.stopped();active['monitor_done']=True;active['monitor'].join(timeout=2)
        record=active.get('record',{'case':active['case']});record.update({'tree_stopped':stopped,'reason':reason,'owner_exit':active['owner'].returncode,'health_reason':active['health_reason'],'aggregate_peak_sampled':active.get('peak'),'status':'completed' if reason=='normal' else 'interrupted'})
        if not stopped:
            for node in active['nodes']:
                try:self.connection.lookupByUUIDString(node['uuid']).destroy()
                except self.libvirt.libvirtError:pass
            raise RuntimeError('Independent stop oracle failed; no stable publication')
        for channel in active['channels'].values():channel.close()
        for capture in active['captures']:
            if capture.poll() is None:capture.send_signal(signal.SIGINT)
            capture.wait(timeout=5)
        for node in active['nodes']:node['sha256_after_stop']=digest(node['overlay'])
        record['stopped_overlays']=[{'role':v['role'],'path':str(v['overlay']),'sha256':v['sha256_after_stop']} for v in active['nodes']]
        assert digest(BASE)==self.root_image_sha and BASE.stat().st_uid==0 and BASE.stat().st_mode&0o777==0o444
        self.active=None;return active

    def cleanup(self):
        if self.active:self.finish('validation_error')
        for process in reversed(self.processes):
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=4)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)
        if self.link:self.run(['/usr/sbin/ip','link','del','pgw-fixture'])
        if self.namespace:self.run(['/usr/sbin/ip','netns','del','pawgwan'])
        if self.network_created:
            if self.wan.isActive():self.wan.destroy()
            self.wan.undefine()
        # Keep the restrictive filters installed; no lab link or guest survives.
        self.filters();assert not self.connection.listAllDomains(0)
        self.report['final_domains']=[];self.report['final_bridges']={b:[p.name for p in Path('/sys/class/net',b,'brif').iterdir()] for b in ['pawbr-int']}
        self.report['final_filter_fingerprints']=fingerprints();self.connection.close()
        self.report['source_freeze_unchanged']=all(digest(HERE/name)==sha for name,sha in self.source_hashes.items())
        if not self.report['source_freeze_unchanged']:raise RuntimeError('Sources changed during measured run')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);parser.add_argument('--assets',type=Path);parser.add_argument('--owner',type=Path);parser.add_argument('--export',type=Path);parser.add_argument('--phase',choices=['smoke','matrix'],default='smoke')
    args=parser.parse_args()
    if args.owner:owner(args.owner);return
    assert os.geteuid()==0 and args.output and args.assets
    validation=Matrix(args)
    try:
        validation.prepare();channels=validation.job('traffic')
        worker=channels['worker'];gateway=channels['gateway']
        observation=worker.call('fetch',url='http://allow.fixture.invalid:18080/ok');assert observation['body']['status']=='completed',observation
        validation.report['jobs'][-1]['initial_fetch']=observation
        if args.phase=='matrix':validation.traffic(channels)
        validation.logs();finished=validation.finish('normal')
        if args.phase=='matrix':
            source=next(v['overlay'] for v in finished['nodes'] if v['role']=='worker')
            validation.admission_faults();validation.extract(source);validation.failures();validation.startup()
        validation.report['result']='PASS'
    except Exception as error:
        validation.report['error']=type(error).__name__+': '+str(error);validation.report['traceback']=traceback.format_exc();print(validation.report['traceback'],flush=True)
    finally:
        try:validation.cleanup()
        except Exception as error:validation.report['cleanup_error']=str(error);validation.report['cleanup_traceback']=traceback.format_exc();validation.report['result']='FAIL'
        validation.report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        (args.output/'results.json').write_text(json.dumps(validation.report,indent=2)+'\n')
        if args.export:
            args.export.mkdir(mode=0o700,parents=True,exist_ok=False)
            # Deliberately exclude fixture private keys, CSRs and ephemeral
            # job-token configs. Evidence is data; no report is rendered here.
            for path in args.output.iterdir():
                if path.is_file() and (path.suffix in {'.pcap','.log','.xml'} or path.name in {'results.json','wan.jsonl','host-canary.jsonl','quarantine-manifest.json'} or path.name.endswith('-result.json') or path.name.endswith('-broker.jsonl') or path.name.endswith('-dns.jsonl')):
                    shutil.copyfile(path,args.export/path.name);os.chown(args.export/path.name,1000,1000)
            shutil.copytree(args.output/'sources',args.export/'sources')
            for path in (args.export/'sources').iterdir():os.chown(path,1000,1000)
            os.chown(args.export/'sources',1000,1000);os.chown(args.export,1000,1000)
            if (args.output/'quarantine').exists():
                shutil.copytree(args.output/'quarantine',args.export/'quarantine')
                for path in (args.export/'quarantine').iterdir():os.chown(path,1000,1000)
                os.chown(args.export/'quarantine',1000,1000)
        print('Gateway validation: '+validation.report['result'],flush=True)
    if validation.report['result']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
