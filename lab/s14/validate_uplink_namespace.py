"""Measure routed/NAT/lease components in wholly disconnected namespaces.

No real IP/DNS request, physical attachment, Docker invocation or host firewall
mutation. Host nft --check is a dry run only. This is not KVM/live-uplink
activation acceptance; the measured gateway profile remains unchanged.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import uuid

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from uplink_policy import (make_profile,validate,admit,guard_tables,nat_table,
                           bridge_table,interop_commands,lease_transaction,match_uplink,FIXTURE,fingerprint)
from prepare_uplink import current_uplink
from gw_admission import strict_json
from gw_validation import canonical

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def fixture(directory):
    lock=threading.Lock()
    def log(event,**fields):
        with lock,(directory/'fixture.jsonl').open('a') as stream:stream.write(json.dumps({'event':event,'monotonic':time.monotonic(),**fields})+'\n')
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            log('request',path=self.path,peer=self.client_address[0],local=self.connection.getsockname()[0])
            self.send_response(200);self.end_headers()
            try:
                if (directory/'stream-enabled').exists():
                    for _ in range(120):self.wfile.write(b'OWNED-HEARTBEAT\n');self.wfile.flush();time.sleep(.1)
                else:self.wfile.write(b'OWNED-UPLINK-FIXTURE\n')
            except OSError:pass
    for port in [443,80]:
        server=http.server.ThreadingHTTPServer(('0.0.0.0',port),Handler);server.daemon_threads=True
        if port==443:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(directory/'server.pem',directory/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
    def udp():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
            server.bind(('0.0.0.0',53))
            while True:
                data,peer=server.recvfrom(512);log('udp',peer=peer[0]);server.sendto(b'OWNED-DNS-CANARY',peer)
    threading.Thread(target=udp,daemon=True).start()
    (directory/'fixture-ready').write_text(str(os.getpid()))
    while True:time.sleep(1)

def client(directory,address,port,operation):
    result={'connected':False,'bytes':0,'eof':False,'first_byte':None,'last_byte':None}
    def save():
        path=directory/'client-state.json';temp=path.with_suffix('.tmp');temp.write_text(json.dumps(result));temp.replace(path)
    if operation=='udp':
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(.4)
            try:sock.sendto(b'OWNED-UDP-PROBE',(address,port));result['bytes']=len(sock.recv(512));result['connected']=True
            except OSError:pass
        print(json.dumps(result));return
    try:
        raw=socket.create_connection((address,port),timeout=.5,source_address=('198.18.41.9',0) if operation=='spoof' else None);result['connected']=True
        if operation=='tcp':raw.close();print(json.dumps(result));return
        context=ssl.create_default_context(cafile=str(directory/'ca.pem'))
        connection=context.wrap_socket(raw,server_hostname='allow.fixture.invalid')
        connection.sendall(b'GET /get HTTP/1.0\r\nHost: allow.fixture.invalid\r\n\r\n')
        if operation=='tls':
            data=connection.recv(4096);result['bytes']=len(data);result['tls_verified']=True;connection.close();print(json.dumps(result));return
        connection.settimeout(.25);save();deadline=time.monotonic()+9
        while time.monotonic()<deadline:
            try:data=connection.recv(1024)
            except socket.timeout:continue
            if not data:result['eof']=True;save();break
            now=time.monotonic();result['first_byte']=result['first_byte'] or now;result['last_byte']=now;result['bytes']+=len(data);save()
        connection.close()
    except OSError as error:result['error']=type(error).__name__
    if operation=='stream':save()
    else:print(json.dumps(result))

class Validation:
    def __init__(self,args):
        self.args=args;self.root=args.output;self.root.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.report={'result':'FAIL','scope':'Disconnected kernel uplink components only; live and KVM integration not activated','commands':[],'tests':[]}
        self.names=[];self.processes=[]
        self.sources={p.name:sha(p) for p in HERE.glob('*') if p.suffix in {'.py','.nft','.xml','.service','.slice','.conf'}}
        (self.root/'sources').mkdir()
        for name in self.sources:(self.root/'sources'/name).write_bytes((HERE/name).read_bytes())
        suffix=uuid.uuid4().hex[:8];self.gw='pu-gw-'+suffix;self.router='pu-router-'+suffix;self.up='pu-up-'+suffix
        self.profile=make_profile('out0','02:00:00:00:42:01','198.18.42.1','198.18.42.2',emulation=True)
    def run(self,argv,required=True,input=None):
        value=subprocess.run(argv,capture_output=True,text=True,timeout=20,input=input)
        self.report['commands'].append({'argv':argv,'code':value.returncode,'stdout':value.stdout,'stderr':value.stderr})
        if required and value.returncode:raise RuntimeError(str(argv)+': '+value.stderr)
        return value
    def ns(self,name,argv,**kw):return self.run(['/usr/sbin/ip','netns','exec',name,*argv],**kw)
    def nft(self,text):return self.ns(self.router,['/usr/sbin/nft','-f','-'],input=text)
    def spawn(self,name,argv,filename):
        with (self.root/filename).open('wb') as log:
            process=subprocess.Popen(['/usr/sbin/ip','netns','exec',name,*argv],stdout=log,stderr=log)
        self.processes.append(process);return process
    def wait(self,path,seconds=10):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if path.exists() and path.stat().st_size:return
            time.sleep(.05)
        raise TimeoutError(str(path))
    def snapshot_host(self):
        data=json.loads(self.run(['/usr/sbin/nft','-j','list','ruleset']).stdout)
        return {'nft_sha256':hashlib.sha256(json.dumps(canonical(data),sort_keys=True).encode()).hexdigest(),
                'routes':json.loads(self.run(['/usr/sbin/ip','-j','route']).stdout),
                'interfaces':sorted(p.name for p in Path('/sys/class/net').iterdir())}
    def prepare(self):
        assert os.geteuid()==0 and Path('/proc/self/attr/current').read_text().strip()=='unconfined','Use bounded PID1 service'
        self.before=self.snapshot_host();profile=validate(strict_json((self.args.prepared/'profile.json').read_text()))
        match_uplink(profile,current_uplink());assert profile['mode']=='wifi-routed' and not profile['enabled']
        assert (self.args.prepared/'host-guards.nft').read_text()==guard_tables(profile)+bridge_table(profile)
        assert (self.args.prepared/'nat.nft').read_text()==nat_table(profile)
        assert json.loads((self.args.prepared/'docker-user-commands.json').read_text())==interop_commands(profile)
        self.report['prepared_profile_sha256']=fingerprint(profile)
        self.report['prepared_files_sha256']={p.name:sha(p) for p in self.args.prepared.iterdir() if p.is_file()}
        self.report['host_preflight']={'binding_matches':True,'live_targets_unpinned':all(not t['pinned_ipv4'] for t in profile['targets']),
            'forwarding':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
            'iptables_version':self.run(['/usr/sbin/iptables','-V']).stdout,
            'docker_user':self.run(['/usr/sbin/iptables','-w','5','-S','DOCKER-USER'],required=False).stdout,
            'forward_chain':self.run(['/usr/sbin/iptables','-w','5','-S','FORWARD'],required=False).stdout}
        assert 'nf_tables' in self.report['host_preflight']['iptables_version']
        assert self.report['host_preflight']['forwarding']=='1','Do not change host forwarding automatically'
        for file in ['host-guards.nft','nat.nft']:
            self.run(['/usr/sbin/nft','--check','--file',str(self.args.prepared/file)])
        for name in [self.gw,self.router,self.up]:
            self.run(['/usr/sbin/ip','netns','add',name]);self.names.append(name)
            self.ns(name,['/usr/sbin/ip','link','set','lo','up'])
            self.ns(name,['/usr/sbin/sysctl','-w','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1'])
        self.ns(self.gw,['/usr/sbin/ip','link','add','wan0','type','veth','peer','name','gw-tap','netns',self.router])
        self.ns(self.gw,['/usr/sbin/ip','link','set','wan0','address','52:54:00:14:41:02'])
        self.ns(self.gw,['/usr/sbin/ip','address','add','198.18.41.2/30','dev','wan0'])
        self.ns(self.gw,['/usr/sbin/ip','link','set','wan0','up'])
        self.ns(self.gw,['/usr/sbin/ip','route','add','default','via','198.18.41.1'])
        self.ns(self.router,['/usr/sbin/ip','link','add','up0','type','bridge'])
        self.ns(self.router,['/usr/sbin/ip','link','set','up0','address','52:54:00:14:41:01'])
        self.ns(self.router,['/usr/sbin/ip','address','add','198.18.41.1/30','dev','up0'])
        self.ns(self.router,['/usr/sbin/ip','link','set','gw-tap','master','up0'])
        for device in ['gw-tap','up0']:self.ns(self.router,['/usr/sbin/ip','link','set',device,'up'])
        for router_if,peer_if,prefix in [('out0','peer0','198.18.42'),('out1','peer1','198.18.44')]:
            self.ns(self.router,['/usr/sbin/ip','link','add',router_if,'type','veth','peer','name',peer_if,'netns',self.up])
            for name,device,address in [(self.router,router_if,prefix+'.1/30'),(self.up,peer_if,prefix+'.2/30')]:
                self.ns(name,['/usr/sbin/ip','address','add',address,'dev',device]);self.ns(name,['/usr/sbin/ip','link','set',device,'up'])
        for address in ['198.18.43.10/32','198.18.43.11/32','10.44.0.10/32']:self.ns(self.up,['/usr/sbin/ip','address','add',address,'dev','lo'])
        self.ns(self.router,['/usr/sbin/ip','route','add','198.18.43.0/24','via','198.18.42.2'])
        self.ns(self.router,['/usr/sbin/ip','route','add','10.44.0.10/32','via','198.18.42.2'])
        self.ns(self.router,['/usr/sbin/sysctl','-w','net.ipv4.ip_forward=1'])
        self.nft(guard_tables(self.profile)+bridge_table(self.profile)+nat_table(self.profile))
        # Reproduce Docker's documented FORWARD/DOCKER-USER policy without
        # starting Docker or copying/modifying any real Docker-managed chain.
        for argv in [['-N','DOCKER-USER'],['-P','FORWARD','DROP'],['-A','FORWARD','-j','DOCKER-USER']]:
            self.ns(self.router,['/usr/sbin/iptables','-w','5',*argv])
        self.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=PAW isolated uplink fixture',
                  '-addext','subjectAltName=DNS:allow.fixture.invalid','-keyout',str(self.root/'server.key'),'-out',str(self.root/'server.pem')])
        (self.root/'ca.pem').write_bytes((self.root/'server.pem').read_bytes())
        self.fixture=self.spawn(self.up,['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--fixture',str(self.root)],'fixture-process.log')
        self.wait(self.root/'fixture-ready')
        self.router_canary=self.spawn(self.router,['/usr/bin/python3','-I','-c',
            "import http.server;http.server.HTTPServer(('198.18.41.1',443),http.server.BaseHTTPRequestHandler).serve_forever()"],'router-canary.log')
        time.sleep(.2)
        self.report['topology']={name:json.loads(self.ns(name,['/usr/sbin/ip','-j','address']).stdout) for name in self.names}
        # Only veth/bridge/loopback devices exist in each temporary namespace.
        assert all(i['ifname'] in {'lo','wan0','gw-tap','up0','out0','out1','peer0','peer1'} for interfaces in self.report['topology'].values() for i in interfaces)
        with (self.root/'uplink.pcap').open('wb') as data,(self.root/'capture.log').open('wb') as log:
            self.capture=subprocess.Popen(['/usr/sbin/ip','netns','exec',self.router,'/usr/bin/prlimit','--fsize=8388608:8388608','--',
                '/usr/bin/tcpdump','-i','out0','-nn','-s','256','-U','-Z','tcpdump','-w','-'],stdout=data,stderr=log)
        self.processes.append(self.capture)
        self.wait(self.root/'uplink.pcap');assert self.capture.poll() is None

    def probe(self,address=FIXTURE,port=443,operation='tls',namespace=None):
        value=self.ns(namespace or self.gw,['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--client',str(self.root),
                                         '--address',address,'--port',str(port),'--operation',operation])
        return json.loads(value.stdout)
    def events(self):
        path=self.root/'fixture.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    def guards_present(self):
        for table in ['paw_s14_up_floor','paw_s14_up_lease']:
            value=self.ns(self.router,['/usr/sbin/nft','-j','list','table','inet',table],required=False)
            if value.returncode:return False
            data=json.loads(value.stdout)
            if not any('rule' in v for v in data['nftables']):return False
        return True
    def clear(self):
        self.nft('flush set inet paw_s14_up_floor targets4\nflush set inet paw_s14_up_lease targets4\n')
    def grant(self,seconds=5):
        if not self.guards_present():raise ValueError('effective_guard_missing_before_lease')
        self.clear();plan=admit(self.profile,'owned-fixture',self.profile['targets'][0]['url'],[FIXTURE],0,30,seconds)
        self.nft(lease_transaction(self.profile,plan));return plan
    def record(self,name,**values):
        self.report['tests'].append({'name':name,'result':'PASS',**values});print('PASS: '+name,flush=True)
    def stream(self):
        state=self.root/'client-state.json';state.unlink(missing_ok=True)
        process=self.spawn(self.gw,['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--client',str(self.root),
                                   '--address',FIXTURE,'--port','443','--operation','stream'],'stream-'+str(len(self.processes))+'.log')
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            if state.exists():
                value=json.loads(state.read_text())
                if value['bytes']>0:return process
            time.sleep(.05)
        raise RuntimeError('Stream did not receive a positive control byte')
    def cessation(self,process,started,reason):
        state=self.root/'client-state.json'
        time.sleep(2.7)
        first=json.loads(state.read_text());time.sleep(.8);second=json.loads(state.read_text())
        assert first['bytes']>0 and first['bytes']==second['bytes'] and not second['eof']
        assert process.poll() is None and self.fixture.poll() is None
        assert time.monotonic()-second['last_byte']>=1
        result={'reason':reason,'last_byte_after_trigger_seconds':second['last_byte']-started,'bytes_received':second['bytes'],
                'no_eof_or_peer_exit':True,'bytes_stable_for_seconds':.8}
        process.terminate();process.wait(timeout=3)
        return result
    def tests(self):
        assert self.probe('198.18.43.11',namespace=self.up)['tls_verified']
        assert self.probe('198.18.43.11',53,'udp',self.up)['connected']
        assert self.probe('198.18.41.1',443,'tcp',self.router)['connected']
        self.record('forbidden_owned_listener_positive_controls')
        self.grant()
        before=len(self.events());assert not self.probe()['connected'];assert len(self.events())==before
        self.record('docker_forward_drop_reproduced_without_interop')
        for argv in interop_commands(self.profile):self.ns(self.router,argv)
        self.clear();assert not self.probe()['connected']
        self.record('empty_lease_denies_even_with_scoped_docker_user_accept')
        self.grant();positive=self.probe();assert positive.get('tls_verified') and positive['bytes']>0
        assert any(v['event']=='request' and v['peer']=='198.18.42.1' and v['local']==FIXTURE for v in self.events())
        self.record('owned_tls_and_snat_positive',observation=positive,observed_snat_source='198.18.42.1')
        self.grant();before=len(self.events());denials=[]
        for addr,port,op in [('198.18.43.11',443,'tcp'),('10.44.0.10',443,'tcp'),(FIXTURE,80,'tcp'),(FIXTURE,22,'tcp'),
                             (FIXTURE,53,'udp'),(FIXTURE,443,'udp'),('198.18.41.1',443,'tcp')]:
            result=self.probe(addr,port,op);assert not result['connected'],(addr,port,result)
            denials.append({'address':addr,'port':port,'transport':op,'connected':False})
        assert len(self.events())==before
        self.record('other_addresses_ports_udp_dns_quic_router_denied',observations=denials)
        # A wrong controller cannot override the independent special-purpose floor.
        self.clear();self.nft('add element inet paw_s14_up_floor targets4 { 10.44.0.10 . 443 timeout 5s }\nadd element inet paw_s14_up_lease targets4 { 10.44.0.10 . 443 timeout 5s }\n')
        assert not self.probe('10.44.0.10',443,'tcp')['connected'];self.record('private_destination_denied_despite_forced_kernel_tuple')
        self.grant();self.ns(self.gw,['/usr/sbin/ip','address','add','198.18.41.9/32','dev','wan0'])
        assert not self.probe(operation='spoof')['connected'];self.record('gateway_source_spoof_denied')
        self.grant();self.ns(self.router,['/usr/sbin/ip','route','replace',FIXTURE+'/32','via','198.18.44.2','dev','out1'])
        assert not self.probe()['connected'];self.record('alternate_uplink_route_cannot_fallback')
        self.ns(self.router,['/usr/sbin/ip','route','del',FIXTURE+'/32'])
        for table in ['paw_s14_up_floor','paw_s14_up_lease']:
            for state in ['empty','absent']:
                self.clear();self.nft(('flush' if state=='empty' else 'delete')+' table inet '+table+'\n')
                try:self.grant();raise AssertionError('Missing guard admitted')
                except ValueError as error:assert str(error)=='effective_guard_missing_before_lease'
                assert not self.probe()['connected']
                self.nft(guard_tables(self.profile))
                self.record('guard_'+table+'_'+state+'_rejects_new_lease')
        (self.root/'stream-enabled').write_text('owned synthetic stream')
        self.grant(2);trigger=time.monotonic();process=self.stream()
        self.record('lease_expiry_stops_established_tls',**self.cessation(process,trigger,'kernel_timeout'))
        self.grant(5);process=self.stream();trigger=time.monotonic();self.clear()
        self.record('lease_revocation_stops_established_tls',**self.cessation(process,trigger,'explicit_revoke'))
        self.clear()
        # A separate issuer dies; timed kernel entries still close established traffic.
        plan=admit(self.profile,'owned-fixture',self.profile['targets'][0]['url'],[FIXTURE],0,30,2)
        lease=self.root/'issuer-lease.nft';lease.write_text(lease_transaction(self.profile,plan))
        issuer=self.spawn(self.router,['/usr/bin/python3','-I','-c',
            "import subprocess,sys,time; subprocess.run(['/usr/sbin/nft','-f',sys.argv[1]],check=True); print('issued',flush=True); time.sleep(15)",str(lease)],'issuer.log')
        self.wait(self.root/'issuer.log');assert 'issued' in (self.root/'issuer.log').read_text()
        process=self.stream();trigger=time.monotonic();issuer.kill();issuer.wait(timeout=3)
        self.record('issuer_death_cannot_keep_established_lease_alive',**self.cessation(process,trigger,'issuer_sigkill'))
        self.clear()
        self.report['effective_namespace_rules']=json.loads(self.ns(self.router,['/usr/sbin/nft','-j','list','ruleset']).stdout)
        # Complete HTTP requests from the routed side can only be for the owned fixture.
        events=self.events()
        assert not any(v['event']=='request' and v['peer']=='198.18.42.1' and v['local']!=FIXTURE for v in events)
        self.report['actual_requests']=events
        self.record('request_log_reconciliation_no_forbidden_routed_request')
    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT if process is getattr(self,'capture',None) else signal.SIGTERM)
            try:process.wait(timeout=4)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        # Namespace deletion after all identified children have exited removes
        # every temporary interface and policy, without touching host routing.
        for name in reversed(self.names):self.run(['/usr/sbin/ip','netns','del',name])
        self.report['children_stopped']=all(p.poll() is not None for p in self.processes)
        self.report['namespaces_removed']=all(not Path('/run/netns',name).exists() for name in self.names)
        after=self.snapshot_host();self.report['host_before']=self.before;self.report['host_after']=after
        assert self.before==after,'Host firewall/route/interface state changed'
        self.report['host_network_unchanged']=True
        self.report['source_hashes']=self.sources
        self.report['source_freeze_unchanged']=all(sha(HERE/name)==digest for name,digest in self.sources.items())
        assert self.report['source_freeze_unchanged']

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',type=Path);parser.add_argument('--client',type=Path)
    parser.add_argument('--address');parser.add_argument('--port',type=int);parser.add_argument('--operation',choices=['tcp','tls','udp','stream','spoof'])
    parser.add_argument('--output',type=Path);parser.add_argument('--prepared',type=Path);parser.add_argument('--export',type=Path)
    args=parser.parse_args()
    if args.fixture or args.client:
        assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Disconnected namespace required'
        assert not any(p.name.startswith(('wl','en')) for p in Path('/sys/class/net').iterdir()),'No physical interface permitted'
    if args.fixture:fixture(args.fixture);return
    if args.client:
        assert args.address in {FIXTURE,'198.18.43.11','10.44.0.10','198.18.41.1'} and args.port in {443,80,22,53},'Only fixed owned canaries'
        client(args.client,args.address,args.port,args.operation);return
    assert args.output and args.prepared and args.export
    validation=Validation(args)
    try:validation.prepare();validation.tests();validation.report['result']='PASS'
    except Exception as error:
        validation.report['error']=str(error);validation.report['traceback']=traceback.format_exc();print(validation.report['traceback'],flush=True)
    finally:
        try:validation.cleanup()
        except Exception as error:
            validation.report['cleanup_error']=str(error);validation.report['cleanup_traceback']=traceback.format_exc();validation.report['result']='FAIL';print(validation.report['cleanup_traceback'],flush=True)
        (args.output/'results.json').write_text(json.dumps(validation.report,indent=2)+'\n')
        args.export.mkdir(mode=0o700,parents=True,exist_ok=False)
        import shutil
        for path in args.output.iterdir():
            if path.is_file() and path.suffix not in {'.key'}:
                shutil.copyfile(path,args.export/path.name);os.chown(args.export/path.name,1000,1000)
        shutil.copytree(args.output/'sources',args.export/'sources')
        for path in (args.export/'sources').iterdir():os.chown(path,1000,1000)
        for path in [args.export/'sources',args.export]:os.chown(path,1000,1000)
        print('Uplink namespace validation: '+validation.report['result'],flush=True)
    if validation.report['result']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
