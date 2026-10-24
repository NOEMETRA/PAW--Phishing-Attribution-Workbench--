"""Run only fixed, owned, offline S14 guest fixtures with stopped-tree evidence.

Requires root, python3-libvirt, genisoimage and the verified base preparation.
No user URL, domain, attachment, arbitrary command or Internet target is accepted.
"""
import argparse
import base64
import ctypes
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import subprocess
import sys
import termios
import time
import tty
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
BASE = Path('/var/lib/libvirt/images/paw-s14/base/ubuntu-24.04-minimal-cloudimg-amd64.img')
MAC = '52:54:00:14:00:20'
PEER_MAC = '52:54:00:14:00:10'
TAP = 'paw14vm0'
BRIDGE = 'pawbr-int'

def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(data)
    return result.hexdigest()

def canonical(value):
    if isinstance(value, list): return [canonical(v) for v in value if 'metainfo' not in v]
    if isinstance(value, dict):
        if set(value) == {'counter'}: return {'counter': {}}
        return {k: canonical(v) for k, v in value.items() if k not in {'handle', 'metainfo'}}
    return value

def guard_fingerprint():
    result = subprocess.run(['/usr/sbin/nft', '--json', 'list', 'table', 'inet', 'paw_s14_guard'],
                            capture_output=True, text=True, timeout=3)
    if result.returncode: return None
    state=json.loads(result.stdout)
    objects=[obj for obj in state['nftables'] if 'metainfo' not in obj]
    tables=[obj['table'] for obj in objects if 'table' in obj]
    chains=[obj['chain'] for obj in objects if 'chain' in obj]
    rules=[obj['rule'] for obj in objects if 'rule' in obj]
    if len(tables)!=1 or len(chains)!=3 or len(rules)!=4 or len(objects)!=8:return None
    expected={'host_input':('input',['iifname']),'host_output':('output',['oifname']),
              'transit':('forward',['iifname','oifname'])}
    if {chain['name'] for chain in chains}!=set(expected):return None
    for chain in chains:
        if (chain.get('type'),chain.get('hook'),chain.get('prio'),chain.get('policy')) != ('filter',expected[chain['name']][0],-310,'accept'):return None
        actual=[r['expr'] for r in rules if r['chain']==chain['name']]
        desired=[[{'match':{'op':'==','left':{'meta':{'key':key}},'right':BRIDGE}},
                  {'counter':{}},{'drop':None}] for key in expected[chain['name']][1]]
        if canonical(actual)!=desired:return None
    return hashlib.sha256(json.dumps(canonical(state), sort_keys=True).encode()).hexdigest()

def process_identity(pid):
    try:
        data = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        return None if data[0] == 'Z' else data[19]
    except FileNotFoundError:
        return None

def supervisor_child(config_path):
    import libvirt
    config = json.loads(config_path.read_text())
    parent = config['parent_pid']
    ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)
    if os.getppid() != parent: return
    reason = 'supervisor_error'
    connection = libvirt.open('qemu:///system')
    stop = False
    def requested(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, requested)
    try:
        if guard_fingerprint() != config['guard_fingerprint']:
            raise RuntimeError('Effective guard differs before creation')
        domain = connection.createXML(Path(config['xml']).read_text(),
            libvirt.VIR_DOMAIN_START_PAUSED | libvirt.VIR_DOMAIN_START_AUTODESTROY)
        pid = int(Path('/run/libvirt/qemu', domain.name() + '.pid').read_text())
        cg = next(line.split('::', 1)[1] for line in Path('/proc', str(pid), 'cgroup').read_text().splitlines() if line.startswith('0::'))
        unit = next(part for part in Path(cg).parts if part.endswith('.scope'))
        subprocess.run(['/usr/bin/systemctl', 'set-property', '--runtime', unit,
                        'TasksMax=64', 'MemoryMax=768M', 'MemorySwapMax=0', 'CPUQuota=75%'], check=True)
        scope = Path('/sys/fs/cgroup/machine.slice/machine-paws14.slice') / unit
        assert (scope / 'pids.max').read_text().strip() == '64'
        assert (scope / 'memory.max').read_text().strip() == str(768 * 1024**2)
        assert (scope / 'memory.swap.max').read_text().strip() == '0'
        assert 'machine-paws14.slice' in cg
        label = Path('/proc', str(pid), 'attr/current').read_text().strip()
        assert label.startswith('libvirt-') and '(enforce)' in label
        status = Path('/proc', str(pid), 'status').read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith('Uid:'))
        assert all(int(v) != 0 for v in uid_line.split()[1:])
        ready = {'uuid': domain.UUIDString(), 'name': domain.name(), 'pid': pid,
                 'pid_identity': process_identity(pid), 'scope': str(scope), 'apparmor': label,
                 'limits': {name: (scope / name).read_text().strip() for name in
                            ['pids.max', 'memory.max', 'memory.swap.max', 'cpu.max']}}
        Path(config['ready']).write_text(json.dumps(ready))
        limit = time.monotonic() + 300
        resumed = False
        while not stop:
            if time.monotonic() >= limit:
                reason = 'deadline'; break
            if guard_fingerprint() != config['guard_fingerprint']:
                reason = 'guard_changed'; break
            if any(process_identity(item['pid']) != item['identity'] for item in config['health']):
                reason = 'health_process_lost'; break
            control = Path(config['control'])
            if control.exists():
                command = json.loads(control.read_text())
                if command.get('resume') and not resumed:
                    domain.resume(); resumed = True
                expiry = command.get('expiry')
                if expiry is not None:
                    if type(expiry) not in (int, float) or not math.isfinite(expiry):
                        raise ValueError('Invalid expiry')
                    limit = min(limit, expiry)
            time.sleep(.25)
        if stop: reason = 'requested_stop'
    finally:
        connection.close()  # Independent libvirtd AUTODESTROY owns teardown.
        Path(config['result']).write_text(json.dumps({'reason': reason, 'connection_closed': True}))

class Serial:
    def __init__(self, path, logfile):
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        tty.setraw(self.fd)
        self.buffer = bytearray()
        self.log = logfile.open('ab')
        self.sequence = 0
        self.total = 0
    def message(self, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            while b'\n' in self.buffer:
                line, _, remainder = self.buffer.partition(b'\n'); self.buffer[:] = remainder
                if line.startswith(b'PAW14 '): return json.loads(line[6:])
            if select.select([self.fd], [], [], min(1, max(0, end-time.monotonic())))[0]:
                try: data = os.read(self.fd, 8192)
                except BlockingIOError: continue
                self.total += len(data)
                if self.total > 2 * 1024**2: raise RuntimeError('Serial byte budget exceeded')
                self.log.write(data); self.log.flush(); self.buffer.extend(data)
                if len(self.buffer) > 65536: raise RuntimeError('Serial line exceeds budget')
        raise TimeoutError('Guest control deadline')
    def call(self, operation, timeout=12, **values):
        self.sequence += 1
        data = json.dumps({'id': self.sequence, 'op': operation, **values}).encode() + b'\n'
        os.write(self.fd, data)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = self.message(max(.01, end-time.monotonic()))
            if result.get('id') == self.sequence: return result
        raise TimeoutError('Guest operation deadline')
    def close(self):
        self.log.close(); os.close(self.fd)

class Validation:
    def __init__(self, output):
        import libvirt
        self.libvirt = libvirt
        libvirt.registerErrorHandler(lambda *_: None, None)
        self.output = output
        self.connection = libvirt.open('qemu:///system')
        self.report = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'result': 'FAIL', 'scope': 'Fixed owned offline fixtures only', 'commands': [], 'jobs': []}
        self.processes = []
        self.fixture_identities = {}
        self.namespace_names = []
        self.links = []
        self.host_addresses = []
        self.active = None
    def run(self, argv, required=True, **kw):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45, **kw)
        self.report['commands'].append({'argv': argv, 'exit_code': result.returncode,
                                       'stdout': result.stdout, 'stderr': result.stderr})
        if required and result.returncode: raise RuntimeError(f'{argv}: {result.stderr.strip()}')
        return result
    def wait_file(self, path, seconds=20):
        end = time.monotonic()+seconds
        while time.monotonic()<end:
            if path.exists() and path.stat().st_size: return json.loads(path.read_text())
            time.sleep(.1)
        raise TimeoutError(str(path))
    def spawn(self, argv, name):
        log = (self.output / (name+'.log')).open('wb')
        process = subprocess.Popen(argv, stdout=log, stderr=log, start_new_session=True)
        log.close(); self.processes.append(process)
        return process
    def fixtures(self):
        addresses = json.loads(self.run(['/usr/sbin/ip','-j','address']).stdout)
        assert not any(a['local'].startswith(('198.18.','fd42:14:')) for i in addresses for a in i['addr_info'])
        assert not self.connection.listAllDomains(0), 'Review existing domains first'
        bridge = json.loads(self.run(['/usr/sbin/ip','-j','addr','show','dev',BRIDGE]).stdout)[0]
        assert not bridge['addr_info'] and not list(Path('/sys/class/net',BRIDGE,'brif').iterdir())
        assert guard_fingerprint() is not None
        assert Path('/sys/fs/cgroup/machine.slice/machine-paws14.slice/pids.max').read_text().strip()=='128'
        for address in ['198.18.0.1/32', 'fd42:14:1::1/128']:
            argv=['/usr/sbin/ip']+(['-6'] if ':' in address else [])+['addr','add',address,'dev','lo']
            self.run(argv); self.host_addresses.append(address)
        for namespace in ['paw14peer','paw14lan']:
            self.run(['/usr/sbin/ip','netns','add',namespace]); self.namespace_names.append(namespace)
        for host, namespace, guest in [('paw14peerh','paw14peer','eth0'),('paw14lanh','paw14lan','eth0')]:
            self.run(['/usr/sbin/ip','link','add',host,'type','veth','peer','name',host+'p'])
            self.links.append(host)
            self.run(['/usr/sbin/ip','link','set',host+'p','netns',namespace])
            self.run(['/usr/sbin/ip','-n',namespace,'link','set',host+'p','name',guest])
            self.run(['/usr/sbin/ip','-n',namespace,'link','set','lo','up'])
        self.run(['/usr/sbin/ip','link','set','paw14peerh','master',BRIDGE])
        self.run(['/usr/sbin/sysctl','-w','net.ipv6.conf.paw14peerh.disable_ipv6=1'])
        self.run(['/usr/sbin/ip','link','set','paw14peerh','up'])
        self.run(['/usr/sbin/ip','-n','paw14peer','link','set','eth0','address',PEER_MAC])
        self.run(['/usr/sbin/ip','-n','paw14peer','addr','add','192.0.2.10/24','dev','eth0'])
        self.run(['/usr/sbin/ip','-n','paw14peer','-6','addr','add','fd42:14::10/64','dev','eth0','nodad'])
        self.run(['/usr/sbin/ip','-n','paw14peer','link','set','eth0','up'])
        self.run(['/usr/sbin/ip','netns','exec','paw14peer','/usr/sbin/sysctl','-w','net.ipv4.ip_forward=0','net.ipv6.conf.all.forwarding=0'])
        for ns, dev, addr in [('', 'paw14lanh','198.18.1.1/30'),('paw14lan','eth0','198.18.1.2/30')]:
            prefix=['/usr/sbin/ip']+(['-n',ns] if ns else [])
            self.run(prefix+['addr','add',addr,'dev',dev]); self.run(prefix+['link','set',dev,'up'])
        self.run(['/usr/sbin/ip','-6','addr','add','fd42:14:2::1/64','dev','paw14lanh','nodad'])
        self.run(['/usr/sbin/ip','-n','paw14lan','-6','addr','add','fd42:14:2::2/64','dev','eth0','nodad'])
        self.fixture_pids={}
        for role,namespace in [('peer','paw14peer'),('host',None),('lan','paw14lan')]:
            argv=['/usr/bin/systemd-run','--scope','--quiet','--collect','--unit=paw14-'+role+'-'+self.output.name[-8:],
                  '--slice=machine-paws14.slice','--property=TasksMax=32','--property=MemoryMax=128M']
            if namespace: argv+=['/usr/sbin/ip','netns','exec',namespace]
            argv+=['/usr/bin/python3','-I',str(HERE/'fixture_server.py'),'--role',role,'--output',str(self.output)]
            self.spawn(argv,role+'-server')
            self.fixture_pids[role]=self.wait_file(self.output/(role+'-ready.json'))['pid']
            self.fixture_identities[self.fixture_pids[role]]=process_identity(self.fixture_pids[role])
        for address,port in [('198.18.0.1',18081),('198.18.1.2',18082)]:
            with socket.create_connection((address,port),timeout=2) as client:
                client.sendall(b'GET /host-positive-control HTTP/1.0\r\n\r\n')
                assert b'200 OK' in client.recv(512)
        self.report['fixture_positive_controls']='PASS'
    def seed(self, folder, job_id):
        service='''[Unit]\nAfter=cloud-final.service\n[Service]\nExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/guest_agent.py\nStandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTasksMax=32\nMemoryMax=128M\nCPUQuota=50%\nStateDirectory=paw-s14-probe\n'''
        files=[('/usr/local/lib/paw-s14/guest_agent.py',(HERE/'guest_agent.py').read_bytes()),
               ('/etc/systemd/system/paw-s14-probe.service',service.encode()),
               ('/etc/paw-s14-fixture.json',json.dumps({'bridge_mac':Path('/sys/class/net',BRIDGE,'address').read_text().strip()}).encode())]
        cloud={'package_update':False,'package_upgrade':False,'ssh_pwauth':False,
               'ssh_genkeytypes':[], 'write_files':[{'path':path,'encoding':'b64','content':base64.b64encode(data).decode(),'permissions':'0644'} for path,data in files],
               'runcmd':[['ip','neigh','replace','192.0.2.1','lladdr',json.loads(files[2][1])['bridge_mac'],'nud','permanent','dev','lab0'],
                         ['ip','-6','neigh','replace','fd42:14::1','lladdr',json.loads(files[2][1])['bridge_mac'],'nud','permanent','dev','lab0'],
                         ['systemctl','mask','--now','ssh.service','ssh.socket','serial-getty@ttyS0.service'],
                         ['systemctl','daemon-reload'],['systemctl','--no-block','start','paw-s14-probe.service']]}
        # No DHCP/default route, no resolver. Only owned canaries have routes.
        routes=[{'to':ip,'via':'192.0.2.1','on-link':True} for ip in ['198.18.0.1/32','198.18.1.2/32']]
        routes += [{'to':ip,'via':'fd42:14::1','on-link':True} for ip in ['fd42:14:1::1/128','fd42:14:2::2/128']]
        network={'version':2,'ethernets':{'lab0':{'match':{'macaddress':MAC},'set-name':'lab0','dhcp4':False,'dhcp6':False,'accept-ra':False,'addresses':['192.0.2.20/24','fd42:14::20/64'],'routes':routes}}}
        (folder/'user-data').write_text('#cloud-config\n'+json.dumps(cloud))
        (folder/'meta-data').write_text(json.dumps({'instance-id':job_id,'local-hostname':'paw-s14-fixture'}))
        (folder/'network-config').write_text(json.dumps(network))
        self.run(['/usr/bin/genisoimage','-quiet','-output',str(folder/'seed.iso'),'-volid','cidata','-joliet','-rock',
                  str(folder/'user-data'),str(folder/'meta-data'),str(folder/'network-config')])
        (folder/'seed.iso').chmod(0o444)
    def job(self, name):
        print('Starting fixed guest fixture: '+name,flush=True)
        identifier=str(uuid.uuid4()); folder=Path('/var/lib/libvirt/images/paw-s14/runs')/identifier
        folder.mkdir(parents=True,mode=0o755)
        qemu=pwd.getpwnam('libvirt-qemu')
        overlay=folder/'overlay.qcow2'
        self.run(['/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2','-b',str(BASE),str(overlay)])
        os.chown(overlay,qemu.pw_uid,qemu.pw_gid); overlay.chmod(0o600)
        self.seed(folder,identifier)
        descriptor=ET.fromstring((HERE/'paused-probe.xml').read_bytes())
        dac=ET.SubElement(descriptor,'seclabel',{'type':'static','model':'dac','relabel':'no'})
        ET.SubElement(dac,'label').text=f'+{qemu.pw_uid}:+{qemu.pw_gid}'
        descriptor.find('name').text='paw14-'+name
        ET.SubElement(descriptor,'uuid').text=identifier
        for tag in ['memory','currentMemory']:descriptor.find(tag).text='512'
        descriptor.find('memtune/hard_limit').text='768'
        descriptor.find('memtune/swap_hard_limit').text='768'
        descriptor.find('cputune/global_quota').text='75000'
        resource=ET.SubElement(descriptor,'resource');ET.SubElement(resource,'partition').text='/machine/paws14'
        devices=descriptor.find('devices')
        nic=devices.find('interface');ET.SubElement(nic,'mac',{'address':MAC});ET.SubElement(nic,'target',{'dev':TAP})
        os_node=descriptor.find('os')
        ET.SubElement(os_node,'smbios',{'mode':'sysinfo'})
        info=ET.SubElement(descriptor,'sysinfo',{'type':'smbios'})
        system=ET.SubElement(info,'system');ET.SubElement(system,'entry',{'name':'serial'}).text='ds=nocloud'
        for disk_type,path,target,bus in [('disk',overlay,'vda','virtio'),('disk',folder/'seed.iso','vdb','virtio')]:
            disk=ET.SubElement(devices,'disk',{'type':'file','device':disk_type})
            ET.SubElement(disk,'driver',{'name':'qemu','type':'qcow2' if target=='vda' else 'raw'})
            ET.SubElement(disk,'source',{'file':str(path)});ET.SubElement(disk,'target',{'dev':target,'bus':bus})
            if target=='vdb':ET.SubElement(disk,'readonly')
        serial=ET.SubElement(devices,'serial',{'type':'pty'});ET.SubElement(serial,'target',{'type':'isa-serial','port':'0'})
        ET.SubElement(devices,'console',{'type':'pty'})
        xml=self.output/(name+'.xml');xml.write_bytes(ET.tostring(descriptor))
        control=self.output/(name+'-control.json');ready=self.output/(name+'-ready.json')
        capture_log=(self.output/(name+'-capture.log')).open('wb')
        capture_data=(self.output/(name+'.pcap')).open('wb')
        capture=subprocess.Popen(['/usr/bin/prlimit','--fsize=8388608:8388608','--',
                                  '/usr/bin/tcpdump','-Z','tcpdump','-i',BRIDGE,'-nn','-U','-s','192','-w','-'],
                                 stdout=capture_data,stderr=capture_log)
        capture_data.close();capture_log.close();self.processes.append(capture)
        time.sleep(.3);assert capture.poll() is None
        health=[{'pid':pid,'identity':process_identity(pid)} for pid in [capture.pid,self.fixture_pids['peer']]]
        config={'xml':str(xml),'ready':str(ready),'control':str(control),'result':str(self.output/(name+'-owner-result.json')),
                'parent_pid':os.getpid(),'guard_fingerprint':guard_fingerprint(),'health':health}
        config_path=self.output/(name+'-owner.json');config_path.write_text(json.dumps(config))
        child=self.spawn(['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--supervisor-child',str(config_path)],name+'-owner')
        self.active={'name':name,'uuid':identifier,'child':child,'capture':capture,'folder':folder}
        self.report['jobs'].append({'name':name,'uuid':identifier,'requested':config,
                                    'overlay':str(overlay),'status':'starting'})
        actual=self.wait_file(ready)
        if not self.report.get('exclusive_image_lock'):
            writer=self.run(['/usr/bin/qemu-img','check','-r','all',str(overlay)],required=False)
            assert writer.returncode!=0 and 'lock' in writer.stderr.lower(),writer.stderr
            self.report['exclusive_image_lock']={'second_writer_denied':True,'stderr':writer.stderr,
                                                   'first_guest_still_paused':True}
        domain=self.connection.lookupByUUIDString(identifier)
        dumped=ET.fromstring(domain.XMLDesc(0));path=dumped.find('./devices/serial/source').get('path')
        channel=Serial(path,self.output/(name+'-serial.log'))
        self.active.update({'channel':channel,'pid':actual['pid'],'actual':actual,'control':control})
        self.report['jobs'][-1].update({'admission':actual,'status':'running'})
        control.write_text(json.dumps({'resume':True}))
        print('Confined KVM guest resumed; awaiting fixed serial agent: '+name,flush=True)
        channel.message(180)
        snapshot=channel.call('snapshot');assert snapshot['ok'],snapshot
        assert not snapshot['data']['marker_exists'],snapshot
        assert snapshot['data']['pids_max']=='32' and snapshot['data']['memory_max']==str(128*1024**2)
        self.report['jobs'][-1]['guest_snapshot']=snapshot
        print('Fixed guest agent ready, fresh overlay and guest task budget verified: '+name,flush=True)
        return channel
    def stopped(self, seconds=12):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            try:self.connection.lookupByUUIDString(self.active['uuid']);present=True
            except self.libvirt.libvirtError:present=False
            pid=self.active.get('pid')
            pid_gone=pid is None or process_identity(pid)!=self.active['actual']['pid_identity']
            owned_qemu=False
            if not present and pid_gone and not Path('/sys/class/net',TAP).exists():
                pattern=b'-uuid\0'+self.active['uuid'].encode()+b'\0'
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():continue
                    try:
                        if pattern in (proc/'cmdline').read_bytes():owned_qemu=True;break
                    except (FileNotFoundError,PermissionError,ProcessLookupError):pass
                if not owned_qemu:return True
            time.sleep(.1)
        return False
    def finish_job(self, reason):
        job=self.active
        if job['child'].poll() is None:job['child'].terminate()
        try:job['child'].wait(timeout=8)
        except subprocess.TimeoutExpired:job['child'].kill();job['child'].wait(timeout=5)
        stopped=self.stopped()
        self.report['jobs'][-1].update({'status':'interrupted' if reason!='normal' else 'completed',
                                      'reason':reason,'tree_stopped':stopped,'owner_exit':job['child'].returncode})
        if not stopped:
            # Preserve the failed oracle, but still stop only this owned UUID.
            self.connection.lookupByUUIDString(job['uuid']).destroy()
            raise RuntimeError('AUTODESTROY did not confirm stop within budget')
        if 'channel' in job:job['channel'].close()
        if job['capture'].poll() is None:job['capture'].send_signal(signal.SIGINT)
        job['capture'].wait(timeout=5)
        self.report['jobs'][-1]['overlay_sha256_after_stop']=digest(job['folder']/'overlay.qcow2')
        assert BASE.stat().st_uid==0 and not BASE.stat().st_mode&0o222,'Vendor base ownership/mode changed'
        assert digest(BASE)==self.report['image_provenance']['sha256'],'Vendor base bytes changed'
        self.report['jobs'][-1]['vendor_base_unchanged']=True
        self.active=None
    def traffic(self, channel):
        def events(role):
            return [json.loads(line)['event'] for line in (self.output/(role+'.jsonl')).read_text().splitlines()]
        before={role:events(role) for role in ['host','lan']}
        observations={}
        for op,address,port,expected in [
            ('tcp','192.0.2.10',18080,True),('dns','192.0.2.10',5353,True),
            ('tcp','198.18.0.1',18081,False),('tcp','198.18.1.2',18082,False),
            ('dns','198.18.1.2',5353,False),('tcp','fd42:14:1::1',18081,False),
            ('tcp','fd42:14:2::2',18082,False)]:
            result=channel.call(op,address=address,port=port)
            observations[f'{op}:{address}:{port}']=result
            assert result['ok'] is expected,(address,result)
        observations['spoof']=channel.call('spoof');assert observations['spoof']['ok']
        observations['guest_process_budget']=channel.call('budget')
        assert observations['guest_process_budget']['data']['blocked'] and observations['guest_process_budget']['data']['children_stopped']
        observations['marker']=channel.call('marker');assert observations['marker']['ok']
        observations['unadmitted_target']=channel.call('tcp',address='unadmitted.fixture.invalid',port=18080)
        assert not observations['unadmitted_target']['ok'] and 'Only fixed owned' in observations['unadmitted_target']['error']
        time.sleep(.2)
        assert all(events(role)==before[role] for role in before),'Forbidden canary received guest traffic'
        assert 'tcp' in events('peer') and 'udp' in events('peer')
        observations['independent_forbidden_canaries_unchanged']=True
        self.report['jobs'][-1]['traffic']=observations
    def admission_faults(self):
        assert not self.connection.listAllDomains(0)
        previous=self.report['jobs'][-1]['requested']
        evidence=[]
        for fault in ['empty','absent']:
            try:
                self.run(['/usr/sbin/nft', 'flush' if fault=='empty' else 'delete','table','inet','paw_s14_guard'])
                assert guard_fingerprint() is None
                config={**previous,'ready':str(self.output/(fault+'-rejected-ready.json')),
                        'result':str(self.output/(fault+'-rejected-result.json'))}
                path=self.output/(fault+'-reject-owner.json');path.write_text(json.dumps(config))
                process=self.spawn(['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--supervisor-child',str(path)],fault+'-reject')
                assert process.wait(timeout=12)!=0 and not Path(config['ready']).exists()
                assert not self.connection.listAllDomains(0)
                evidence.append({'policy':fault,'creation_rejected':True,'no_domain_created':True})
            finally:
                self.run(['/usr/sbin/nft','--file','/etc/paw-s14/host-guard.nft'])
                assert guard_fingerprint() is not None
        self.report['guard_admission_faults']=evidence
    def cleanup(self):
        if self.active:
            try:self.finish_job('test_error')
            except Exception as error:self.report['cleanup_error']=str(error)
        for pid,identity in self.fixture_identities.items():
            if process_identity(pid)==identity:os.kill(pid,signal.SIGTERM)
        end=time.monotonic()+3
        while time.monotonic()<end and any(process_identity(pid)==identity for pid,identity in self.fixture_identities.items()):time.sleep(.1)
        for pid,identity in self.fixture_identities.items():
            if process_identity(pid)==identity:os.kill(pid,signal.SIGKILL)
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        for name in reversed(self.links):self.run(['/usr/sbin/ip','link','del',name],required=False)
        for name in reversed(self.namespace_names):self.run(['/usr/sbin/ip','netns','del',name],required=False)
        for address in self.host_addresses:
            self.run(['/usr/sbin/ip']+(['-6'] if ':' in address else [])+['addr','del',address,'dev','lo'],required=False)
        self.connection.close()
        self.report['fixture_writers_stopped']=all(process_identity(pid)!=identity for pid,identity in self.fixture_identities.items())

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--supervisor-child',type=Path)
    parser.add_argument('--only-traffic',action='store_true')
    parser.add_argument('--report-file',type=Path)
    parser.add_argument('--evidence-zip',type=Path)
    args=parser.parse_args()
    if args.supervisor_child:
        supervisor_child(args.supervisor_child);return
    if os.geteuid()!=0 or args.output is None:raise RuntimeError('Explicit root output directory required')
    if Path('/proc/self/attr/current').read_text().strip() != 'unconfined':
        raise RuntimeError('Launch this trusted validation supervisor as a bounded systemd service; do not alter app/capture confinement')
    args.output.mkdir(parents=True,mode=0o700,exist_ok=False)
    validation=Validation(args.output)
    try:
        provenance=json.loads((BASE.parent/'provenance.json').read_text())
        if (digest(BASE)==provenance['sha256'] and BASE.stat().st_uid==pwd.getpwnam('libvirt-qemu').pw_uid
                and not BASE.stat().st_mode&0o222 and not validation.connection.listAllDomains(0)):
            os.chown(BASE,0,0)
            validation.report['repaired_prior_preparation_owner_drift']=True
        assert digest(BASE)==provenance['sha256'] and BASE.stat().st_uid==0 and not BASE.stat().st_mode&0o222
        validation.report['image_provenance']=provenance
        validation.report['source_hashes']={p.name:digest(p) for p in HERE.glob('*.py')}
        validation.fixtures()
        channel=validation.job('traffic')
        validation.traffic(channel)
        validation.finish_job('normal')
        if not args.only_traffic:validation.admission_faults()
        for case in ([] if args.only_traffic else ['capture-loss','supervisor-kill','expiry','fixture-loss']):
            channel=validation.job(case)
            assert channel.call('stream')['data']['stream_started']
            triggered=time.monotonic()
            if case=='capture-loss':validation.active['capture'].terminate();validation.active['capture'].wait(timeout=5)
            elif case=='supervisor-kill':validation.active['child'].kill()
            elif case=='expiry':validation.active['control'].write_text(json.dumps({'resume':True,'expiry':time.monotonic()+1}))
            else:os.kill(validation.fixture_pids['peer'],signal.SIGTERM)
            assert validation.stopped(),case
            validation.report['jobs'][-1]['stop_latency_seconds']=time.monotonic()-triggered
            validation.finish_job(case)
        validation.report['result']='PASS'
        validation.report['gate']='Bounded traffic and lifecycle fixtures only; complete S14 isolation gate remains open'
    except Exception as error:
        validation.report['error']=type(error).__name__+': '+str(error)
        validation.report['traceback']=traceback.format_exc()
    finally:
        try:validation.cleanup()
        except Exception as error:
            validation.report['cleanup_error']=type(error).__name__+': '+str(error)
            validation.report['cleanup_traceback']=traceback.format_exc()
            validation.report['result']='FAIL'
        validation.report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        (args.output/'results.json').write_text(json.dumps(validation.report,indent=2)+'\n')
        # Hash only after all known writers have stopped; no PAW case is modified.
        if (validation.report.get('fixture_writers_stopped') is True and 'cleanup_error' not in validation.report
                and all(job.get('tree_stopped') is True for job in validation.report['jobs'])):
            inventory={str(p.relative_to(args.output)):digest(p) for p in args.output.iterdir() if p.is_file() and p.name!='inventory.json'}
            (args.output/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
    diagnostics={str(p.name):p.read_text(errors='replace')[-5000:] for p in args.output.glob('*-owner.log')}
    if args.report_file:
        with args.report_file.open('x') as stream:json.dump(validation.report,stream,indent=2)
    if args.evidence_zip:
        import zipfile
        if not (args.output/'inventory.json').exists():raise RuntimeError('Evidence writers unconfirmed; archive refused')
        with zipfile.ZipFile(args.evidence_zip,'x',compression=zipfile.ZIP_DEFLATED) as archive:
            for path in args.output.iterdir():
                if path.is_symlink():raise RuntimeError('Unexpected evidence symlink')
                if path.is_file():archive.write(path,path.name)
            for name in ['provenance.json','SHA256SUMS','SHA256SUMS.gpg']:archive.write(BASE.parent/name,'vendor/'+name)
    if validation.report['result']!='PASS':
        diagnostics.update({str(p.name):p.read_text(errors='replace')[-5000:] for p in args.output.glob('*-serial.log')})
        diagnostics.update({str(p.name):p.read_text(errors='replace')[-2000:] for p in args.output.glob('*-capture.log')})
    print(json.dumps({'result':validation.report['result'],'error':validation.report.get('error'),
                      'traceback':validation.report.get('traceback'),'diagnostics':diagnostics,'output':str(args.output)}),flush=True)
    raise SystemExit(0 if validation.report['result']=='PASS' else 1)

if __name__=='__main__':main()
