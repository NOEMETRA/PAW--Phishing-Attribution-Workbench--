"""Temporary KVM -> real host routing/NAT -> owned namespace fixture.

No packet is admitted to Wi-Fi. Scoped test guards/DOCKER-USER extensions and
benchmark-only routes are removed after the identified QEMU/TAP stop oracle.
The live prepared profile is never installed or activated.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from gw_validation import Matrix,Channel,canonical,atomic
from benign_guest_validation import supervisor_child,guard_fingerprint,process_identity,BASE,digest
from prepare_uplink import current_uplink
from uplink_policy import (validate,make_profile,match_uplink,guard_tables,bridge_table,nat_table,
                            interop_commands,admit,lease_transaction)
from validate_uplink_namespace import Validation as NamespaceValidation

TABLES=[('inet','paw_s14_guard'),('inet','paw_s14_gateway'),('bridge','paw_s14_roles'),
        ('inet','paw_s14_up_floor'),('inet','paw_s14_up_lease'),('bridge','paw_s14_up_link'),('ip','paw_s14_up_nat')]

def policy_fingerprint():
    values=[]
    for family,table in TABLES:
        value=subprocess.run(['/usr/sbin/nft','-j','list','table',family,table],capture_output=True,timeout=3)
        if value.returncode:return None
        data=json.loads(value.stdout)
        for item in data['nftables']:
            if 'set' in item and item['set']['name']=='targets4':item['set'].pop('elem',None)
        values.append(canonical(data))
    return hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()

class VMValidation(Matrix):
    snapshot_host=NamespaceValidation.snapshot_host
    def __init__(self,args):
        super().__init__(args);self.root=self.output
        self.report['scope']='KVM routed/NAT components with owned benchmark upstream; no Wi-Fi egress'
        self.report['tests']=[];self.bridge=False;self.veth=False;self.namespace=False;self.rules=False;self.interop=[]
        self.ns_name='pu-vm-'+uuid.uuid4().hex[:8];self.vm=None;self.child=None;self.channel=None;self.monitor_done=False
        self.profile=make_profile('pu-up-out','02:00:00:00:42:01','198.18.42.1','198.18.42.2',emulation=True)
        self.profile['gateway'].update({'interface':'pawbr-up','tap':'pu-gw'});validate(self.profile)
    def ns(self,argv):return self.run(['/usr/sbin/ip','netns','exec',self.ns_name,*argv])
    def nft(self,text):return subprocess.run(['/usr/sbin/nft','-f','-'],input=text,text=True,capture_output=True,check=True,timeout=10)
    def record(self,name,**values):self.report['tests'].append({'name':name,'result':'PASS',**values});print('PASS: '+name,flush=True)
    def prepare(self):
        assert Path('/proc/self/attr/current').read_text().strip()=='unconfined'
        assert not self.connection.listAllDomains(0) and guard_fingerprint() is not None
        assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='1'
        assert not Path('/sys/class/net/pawbr-up').exists() and not Path('/sys/class/net/pu-up-out').exists()
        for family,table in TABLES[3:]:assert self.run(['/usr/sbin/nft','list','table',family,table],required=False).returncode!=0
        assert 'paw-s14-uplink-prepared' not in self.run(['/usr/sbin/iptables','-S','DOCKER-USER']).stdout
        self.prepared_profile=validate(json.loads((self.args.prepared/'profile.json').read_text()));match_uplink(self.prepared_profile,current_uplink())
        self.before=self.snapshot_host();self.nft(guard_tables(self.profile)+bridge_table(self.profile)+nat_table(self.profile));self.rules=True
        self.run(['/usr/sbin/ip','link','add','pawbr-up','type','bridge']);self.bridge=True
        self.run(['/usr/sbin/ip','link','set','pawbr-up','address','52:54:00:14:41:01'])
        self.run(['/usr/sbin/sysctl','-w','net.ipv6.conf.pawbr-up.disable_ipv6=1'])
        self.run(['/usr/sbin/ip','address','add','198.18.41.1/30','dev','pawbr-up']);self.run(['/usr/sbin/ip','link','set','pawbr-up','up'])
        self.run(['/usr/sbin/ip','netns','add',self.ns_name]);self.namespace=True
        self.ns(['/usr/sbin/ip','link','set','lo','up'])
        self.ns(['/usr/sbin/sysctl','-w','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1'])
        self.run(['/usr/sbin/ip','link','add','pu-up-out','type','veth','peer','name','peer0','netns',self.ns_name]);self.veth=True
        self.run(['/usr/sbin/ip','link','set','pu-up-out','address','02:00:00:00:42:01'])
        self.run(['/usr/sbin/sysctl','-w','net.ipv6.conf.pu-up-out.disable_ipv6=1'])
        self.run(['/usr/sbin/ip','address','add','198.18.42.1/30','dev','pu-up-out']);self.run(['/usr/sbin/ip','link','set','pu-up-out','up'])
        self.ns(['/usr/sbin/ip','address','add','198.18.42.2/30','dev','peer0']);self.ns(['/usr/sbin/ip','link','set','peer0','up'])
        self.ns(['/usr/sbin/ip','address','add','198.18.43.10/32','dev','lo'])
        self.run(['/usr/sbin/ip','route','add','198.18.43.0/24','via','198.18.42.2','dev','pu-up-out'])
        for argv in interop_commands(self.profile):self.run(argv);self.interop.append(argv)
        self.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=PAW KVM uplink fixture',
                  '-addext','subjectAltName=DNS:allow.fixture.invalid','-keyout',str(self.output/'server.key'),'-out',str(self.output/'server.pem')])
        (self.output/'ca.pem').write_bytes((self.output/'server.pem').read_bytes())
        self.fixture=self.spawn(['/usr/sbin/ip','netns','exec',self.ns_name,'/usr/bin/python3','-I',str(HERE/'validate_uplink_namespace.py'),'--fixture',str(self.output)],'fixture')
        deadline=time.monotonic()+10
        while not (self.output/'fixture-ready').exists() and time.monotonic()<deadline:time.sleep(.1)
        assert (self.output/'fixture-ready').exists()
        with (self.output/'uplink-vm.pcap').open('wb') as data,(self.output/'capture.log').open('wb') as log:
            self.capture=subprocess.Popen(['/usr/bin/prlimit','--fsize=8388608:8388608','--','/usr/bin/tcpdump','-i','pu-up-out','-nn','-s','256','-U','-Z','tcpdump','-w','-'],stdout=data,stderr=log)
        self.processes.append(self.capture)
        self.expected=policy_fingerprint();assert self.expected
        self.report['profile']=self.profile
    def seed(self,folder,role,job_id,token):
        service='[Unit]\nAfter=cloud-final.service\n[Service]\nExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/uplink_guest_probe.py\nStandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTasksMax=32\nMemoryMax=128M\nCPUQuota=50%\n'
        files=[('/usr/local/lib/paw-s14/uplink_guest_probe.py',(HERE/'uplink_guest_probe.py').read_bytes()),('/etc/paw-uplink-ca.pem',(self.output/'ca.pem').read_bytes()),('/etc/systemd/system/paw-uplink-probe.service',service.encode())]
        cloud={'package_update':False,'package_upgrade':False,'ssh_pwauth':False,'ssh_genkeytypes':[],
               'write_files':[{'path':p,'encoding':'b64','content':base64.b64encode(data).decode(),'permissions':'0644'} for p,data in files],
               'runcmd':[['systemctl','mask','--now','ssh.service','ssh.socket','serial-getty@ttyS0.service'],['systemctl','daemon-reload'],['systemctl','--no-block','start','paw-uplink-probe.service']]}
        network={'version':2,'ethernets':{'wan0':{'match':{'macaddress':'52:54:00:14:41:02'},'set-name':'wan0','addresses':['198.18.41.2/30'],
                    'dhcp4':False,'dhcp6':False,'accept-ra':False,'link-local':[],'routes':[{'to':'default','via':'198.18.41.1'}]}}}
        (folder/'user-data').write_text('#cloud-config\n'+json.dumps(cloud));(folder/'meta-data').write_text(json.dumps({'instance-id':job_id,'local-hostname':'paw-uplink-probe'}));(folder/'network-config').write_text(json.dumps(network))
        self.run(['/usr/bin/genisoimage','-quiet','-output',str(folder/'seed.iso'),'-volid','cidata','-joliet','-rock',str(folder/'user-data'),str(folder/'meta-data'),str(folder/'network-config')]);(folder/'seed.iso').chmod(0o444)
    def start_vm(self):
        node=self.descriptor('worker','uplink',str(uuid.uuid4()),uuid.uuid4().hex)
        xml=ET.fromstring(node['xml'].read_text());nic=xml.find('devices/interface');nic.set('type','bridge');nic.find('source').attrib={'bridge':'pawbr-up'}
        nic.find('mac').set('address','52:54:00:14:41:02');nic.find('target').set('dev','pu-gw');node['xml'].write_bytes(ET.tostring(xml));self.vm=node
        self.control=self.output/'owner-control.json';atomic(self.control,{'resume':False,'expiry':time.monotonic()+240})
        ready=self.output/'owner-ready.json'
        config={'parent_pid':os.getpid(),'guard_fingerprint':guard_fingerprint(),'xml':str(node['xml']),'ready':str(ready),'control':str(self.control),
                'result':str(self.output/'owner-result.json'),'health':[{'pid':p.pid,'identity':process_identity(p.pid)} for p in [self.fixture,self.capture]]}
        path=self.output/'owner-config.json';atomic(path,config)
        self.child=self.spawn(['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--owner',str(path)],'owner')
        actual=self.wait_file(ready,30);self.actual=actual
        self.run(['/usr/bin/systemctl','set-property','--runtime',Path(actual['scope']).name,'CPUQuota=50%'])
        actual['limits_after_parent_tightening']={name:(Path(actual['scope'])/name).read_text().strip() for name in ['memory.max','memory.swap.max','pids.max','cpu.max']}
        domain=self.connection.lookupByUUIDString(node['uuid']);runtime_xml=ET.fromstring(domain.XMLDesc(0))
        (self.output/'actual-domain.xml').write_bytes(ET.tostring(runtime_xml))
        self.channel=Channel(runtime_xml.find('devices/serial/source').get('path'),self.output/'guest-serial.log')
        def monitor():
            while not self.monitor_done:
                try:
                    valid=policy_fingerprint()==self.expected and process_identity(actual['pid'])==actual['pid_identity']
                    ports={p.name for p in Path('/sys/class/net/pawbr-up/brif').iterdir()};valid=valid and ports<={'pu-gw'}
                    route=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','route','get','198.18.43.10']))[0]
                    valid=valid and route['dev']=='pu-up-out'
                    atomic(self.control,{'resume':True,'expiry':time.monotonic()+120 if valid else 0})
                except Exception:atomic(self.control,{'resume':False,'expiry':0});return
                time.sleep(.2)
        self.monitor=threading.Thread(target=monitor,daemon=True);self.monitor.start()
        try:self.channel.ready(180)
        except Exception:print((self.output/'guest-serial.log').read_text(errors='replace')[-4000:],flush=True);raise
        self.report['domain']={**actual,'uuid':node['uuid'],'overlay':str(node['overlay'])}
        self.report['guest_state']=self.channel.call('state');self.record('trusted_kvm_probe_ready_with_bounded_scope')
    def clear(self):self.nft('flush set inet paw_s14_up_floor targets4\nflush set inet paw_s14_up_lease targets4\n')
    def grant(self,seconds):
        assert policy_fingerprint()==self.expected;self.clear()
        plan=admit(self.profile,'owned-fixture',self.profile['targets'][0]['url'],['198.18.43.10'],0,30,seconds)
        self.nft(lease_transaction(self.profile,plan))
    def stream(self):
        self.channel.call('stop');self.channel.call('stream');deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            value=self.channel.call('state')
            if value['bytes']>0:return value
            time.sleep(.1)
        raise RuntimeError('No positive stream byte')
    def tests(self):
        assert self.channel.call('fetch')['status']=='unavailable';self.record('empty_kernel_lease_blocks_guest')
        self.grant(5);result=self.channel.call('fetch');assert result['status']=='completed' and result['tls_verified'] and result['http_status']==200
        events=[json.loads(v) for v in (self.output/'fixture.jsonl').read_text().splitlines()]
        assert any(e['event']=='request' and e['peer']=='198.18.42.1' and e['local']=='198.18.43.10' for e in events)
        self.record('kvm_through_actual_host_docker_user_nat_tls',observation=result)
        (self.output/'stream-enabled').write_text('owned benchmark stream')
        self.grant(2);self.stream();time.sleep(2.6);first=self.channel.call('state');time.sleep(.8);second=self.channel.call('state')
        assert first['bytes']>0 and first['bytes']==second['bytes'] and second['running'] and not second['eof']
        self.record('kvm_existing_tls_stops_on_kernel_expiry',observed=second)
        self.channel.call('stop');self.grant(5);self.stream();self.clear();time.sleep(.6);first=self.channel.call('state');time.sleep(.8);second=self.channel.call('state')
        assert first['bytes']>0 and first['bytes']==second['bytes'] and second['running'] and not second['eof']
        self.record('kvm_existing_tls_stops_on_revoke',observed=second)
        self.channel.call('stop');self.grant(5);self.stream();start=time.monotonic();self.child.kill();self.child.wait(timeout=4)
        assert self.stopped();self.record('owner_sigkill_autodestroys_kvm_and_tap',seconds=time.monotonic()-start)
    def stopped(self):
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            try:self.connection.lookupByUUIDString(self.vm['uuid']);present=True
            except self.libvirt.libvirtError:present=False
            if not present and process_identity(self.actual['pid'])!=self.actual['pid_identity'] and not Path('/sys/class/net/pu-gw').exists():
                pattern=b'-uuid\0'+self.vm['uuid'].encode()+b'\0';other=False
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():continue
                    try:
                        if pattern in (proc/'cmdline').read_bytes():other=True;break
                    except (FileNotFoundError,PermissionError,ProcessLookupError):pass
                if not other:return True
            time.sleep(.1)
        return False
    def cleanup(self):
        self.monitor_done=True
        if hasattr(self,'monitor'):self.monitor.join(timeout=3)
        if self.child:
            if self.child.poll() is None:self.child.terminate()
            try:self.child.wait(timeout=8)
            except subprocess.TimeoutExpired:self.child.kill();self.child.wait(timeout=3)
            assert self.stopped(),'Unknown VM stop; no stable publication'
        if self.channel:self.channel.close()
        for process in reversed(self.processes):
            if process.poll() is None:process.send_signal(signal.SIGINT if process is getattr(self,'capture',None) else signal.SIGTERM)
            try:process.wait(timeout=4)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        if self.rules:self.clear()
        for argv in reversed(self.interop):
            remove=argv.copy();remove[3]='-D';remove.pop(5);self.run(remove)
        if self.veth:self.run(['/usr/sbin/ip','link','del','pu-up-out'])
        if self.bridge:self.run(['/usr/sbin/ip','link','del','pawbr-up'])
        if self.namespace:self.run(['/usr/sbin/ip','netns','del',self.ns_name])
        if self.rules:
            for family,table in reversed(TABLES[3:]):self.run(['/usr/sbin/nft','delete','table',family,table])
        assert not self.connection.listAllDomains(0)
        after=self.snapshot_host();assert self.before==after,'Host networking not restored'
        self.report['host_before']=self.before;self.report['host_after']=after;self.report['host_network_restored']=True
        self.report['writers_stopped']=True;self.report['source_freeze_unchanged']=all(digest(HERE/name)==sha for name,sha in self.source_hashes.items())
        assert self.report['source_freeze_unchanged'] and digest(BASE)==self.root_image_sha
        self.report['base_unchanged']=True
        if self.vm:self.report['overlay_sha256_after_stop']=digest(self.vm['overlay'])
        self.connection.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--owner',type=Path);parser.add_argument('--prepared',type=Path);parser.add_argument('--output',type=Path);parser.add_argument('--export',type=Path);args=parser.parse_args()
    if args.owner:supervisor_child(args.owner);return
    assert os.geteuid()==0 and args.prepared and args.output and args.export
    validation=VMValidation(args)
    try:validation.prepare();validation.start_vm();validation.tests();validation.report['result']='PASS'
    except Exception as error:validation.report['error']=str(error);validation.report['traceback']=traceback.format_exc();print(validation.report['traceback'],flush=True)
    finally:
        try:validation.cleanup()
        except Exception as error:validation.report['cleanup_error']=str(error);validation.report['result']='FAIL';print(traceback.format_exc(),flush=True)
        (args.output/'results.json').write_text(json.dumps(validation.report,indent=2)+'\n')
        args.export.mkdir(mode=0o700,parents=True,exist_ok=False)
        for path in args.output.iterdir():
            if path.is_file() and path.suffix in {'.json','.jsonl','.xml','.log','.pcap','.pem'}:
                shutil.copyfile(path,args.export/path.name);os.chown(args.export/path.name,1000,1000)
        shutil.copytree(args.output/'sources',args.export/'sources')
        for path in (args.export/'sources').iterdir():os.chown(path,1000,1000)
        for path in [args.export/'sources',args.export]:os.chown(path,1000,1000)
        print('Uplink KVM validation: '+validation.report['result'],flush=True)
    if validation.report['result']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
