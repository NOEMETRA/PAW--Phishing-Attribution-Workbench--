"""Finite owned loopback kernel components for the fixed no-VM recipe.

Root entry refuses mutable workspace code. Network roles require fixed vacant
nonroot IDs and a Root-supplied minimal private filesystem. No real URL, source,
interface, route, NAT, shell, caller-selected host path or generic Root command.
"""
import hashlib
import base64
import ctypes
import json
import os
from pathlib import Path
import selectors
import queue
import signal
import socket
import stat
import subprocess
import sys
import time
import threading
import uuid

HERE=Path(__file__).resolve()
if __package__:
    from . import owned_kernel_policy as policy
else:
    sys.path.insert(0,str(HERE.parent))
    import owned_kernel_policy as policy


def require(value,reason):
    if not value:raise ValueError(reason)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def decode(raw,maximum=4096):
    require(type(maximum)is int and maximum in {4096,65536} and
            type(raw) is bytes and 0<len(raw)<=maximum,'owned_kernel_frame_budget')
    def pairs(rows):
        out={}
        for k,v in rows:require(k not in out,'owned_kernel_duplicate_key');out[k]=v
        return out
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('owned_kernel_nonfinite')))
    require(type(value) is dict,'owned_kernel_frame_shape');return value


def emit(value):
    raw=canonical(value);require(len(raw)<4096,'owned_kernel_output_budget')
    data=memoryview(raw+b'\n')
    while data:
        count=os.write(1,data);data=data[count:]


def private_json(path,maximum=4096):
    require(path.is_absolute()and'..'not in path.parts,'owned_kernel_absolute_config')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child;info=os.fstat(fd)
            require(info.st_uid==0 and not info.st_mode&0o022,'owned_kernel_protected_parent')
        child=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            info=os.fstat(child)
            require(info.st_uid==0 and stat.S_ISREG(info.st_mode) and not info.st_mode&0o022 and
                    info.st_size<=maximum,'owned_kernel_protected_config')
            raw=os.read(child,maximum+1);require(len(raw)==info.st_size,'owned_kernel_config_read')
        finally:os.close(child)
    finally:os.close(fd)
    return decode(raw,maximum)


def root_entry(job,epoch,release):
    ids=policy.identity(job,epoch,release)
    require(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/owned_kernel_runtime.py',
            'owned_kernel_immutable_root_only')
    value=private_json(Path(ids['directory'])/'config.json')
    require(value=={'schema':'paw-owned-kernel-config-v1','job':job,'epoch':epoch,'release':release},
            'owned_kernel_fixed_config')
    return ids


def status():
    fields=dict(row.split(':',1) for row in Path('/proc/self/status').read_text().splitlines() if ':' in row)
    return {'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),
        'groups':os.getgroups(),'nnp':fields['NoNewPrivs'].strip(),'seccomp':fields['Seccomp'].strip(),
        'cap_eff':fields['CapEff'].strip(),'cap_prm':fields['CapPrm'].strip(),
        'cap_inh':fields['CapInh'].strip(),'cap_amb':fields['CapAmb'].strip(),
        'namespace_inode':os.stat('/proc/self/ns/net').st_ino,
        'interfaces':sorted(os.listdir('/sys/class/net'))}


def capabilities(mask):
    require(type(mask)is int and mask in {0,1<<10},'owned_kernel_fixed_capabilities')
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    header=Header(0x20080522,0);data=(Data*2)(Data(mask,mask,0),Data(0,0,0))
    require(ctypes.CDLL(None,use_errno=True).capset(ctypes.byref(header),data)==0,'owned_kernel_capset_failed')


def drop_credentials(role):
    require(type(role)is str and role in {'fixture','probe'} and os.getresuid()==(0,0,0) and
        os.getresgid()==(0,0,0),'owned_kernel_credential_bootstrap')
    before=status();mask=(1<<6)|(1<<7)|((1<<10)if role=='fixture'else 0)
    checks={'interfaces':before['interfaces']==['lo'],'no_new_privileges':before['nnp']=='1',
        'seccomp':before['seccomp']=='2','groups':set(before['groups'])<={0},
        'capabilities':int(before['cap_eff'],16)==mask}
    if not all(checks.values()):
        # Fixed owned metadata only, never config/peer bytes, credentials or
        # arbitrary /proc reads. Diagnose the refusal without weakening it.
        observed={'interfaces':[v[:32]for v in before['interfaces'][:16]],'groups':before['groups'][:16],
            **{key:before[key]for key in ['nnp','seccomp','cap_eff','cap_prm','cap_inh','cap_amb','namespace_inode']
               if key in before}}
        raise ValueError('owned_kernel_bootstrap_confinement:'+canonical({'checks':checks,
            'observed':observed,'expected_cap_eff':mask}).decode('ascii'))
    libc=ctypes.CDLL(None,use_errno=True)
    if role=='fixture':require(libc.prctl(8,1,0,0,0)==0,'owned_kernel_keep_capabilities')
    uid=policy.FIXTURE_UID if role=='fixture'else policy.BROKER_UID
    os.setgroups([]);os.setresgid(uid,uid,uid);os.setresuid(uid,uid,uid)
    capabilities((1<<10)if role=='fixture'else 0)
    if role=='fixture':require(libc.prctl(8,0,0,0,0)==0,'owned_kernel_clear_keep_capabilities')
    require(os.getresuid()==(uid,uid,uid) and os.getresgid()==(uid,uid,uid) and not os.getgroups(),
            'owned_kernel_irreversible_identity_drop')


def role_entry(job,epoch,release,role):
    ids=policy.identity(job,epoch,release)
    require(type(role)is str and role in {'fixture','probe'} and os.geteuid()==0 and
            HERE==Path('/opt/paw-code/owned_kernel_runtime.py'),'owned_kernel_private_root_bootstrap_only')
    value=private_json(Path('/etc/paw-owned-kernel.json'))
    require(value=={'schema':'paw-owned-kernel-config-v1','job':job,'epoch':epoch,'release':release},
            'owned_kernel_private_root_config')
    drop_credentials(role)
    witness=status()
    require(witness['interfaces']==['lo'] and witness['nnp']=='1' and witness['seccomp']=='2' and
            int(witness['cap_eff'],16)==(1<<10 if role=='fixture' else 0),
            'owned_kernel_process_confinement')
    return ids,witness


class NftFailure(ValueError):
    """Keep the old failure reason, with bounded evidence for private diagnosis."""
    def __init__(self,result):
        super().__init__('owned_kernel_nft_failed')
        raw=result.stderr.encode('utf-8','backslashreplace')
        self.detail={'returncode':result.returncode,'stderr_bytes':len(raw),
            'stderr_sha256':hashlib.sha256(raw).hexdigest(),
            'stderr_prefix_b64':base64.b64encode(raw[:512]).decode('ascii')}


def nft(*args,text=None):
    value=subprocess.run(['/usr/sbin/nft',*args],input=text,capture_output=True,text=True,timeout=2)
    if value.returncode!=0:raise NftFailure(value)
    return value.stdout


def filter_identity():
    value=json.loads(nft('-j','list','ruleset'))
    def clean(v):
        if type(v)is list:return [clean(x) for x in v if not(type(x)is dict and 'metainfo'in x)]
        if type(v)is dict:
            if set(v)=={'counter'}:return {'counter':{}}
            return {k:clean(x) for k,x in v.items() if k!='handle' and
                not(k=='elem' and v.get('name') in {'targets4','dns4'})}
        return v
    return hashlib.sha256(canonical(clean(value))).hexdigest()


def keeper_action(value,epoch,sequence):
    require(type(value)is dict and value.get('epoch')==epoch and
        type(value.get('id'))is int and value['id']==sequence and 0<=sequence<128,
        'owned_kernel_control_identity')
    op=value.get('op')
    if op=='lease':
        require(set(value)=={'op','epoch','id','kind','milliseconds'},'owned_kernel_control_shape')
        return op,policy.lease(value['kind'],value['milliseconds'])
    require(set(value)=={'op','epoch','id'} and type(op)is str and
        op in {'revoke','delete_one','delete_both','stop'},'owned_kernel_control_shape')
    if op=='revoke':return op,policy.revoke()
    if op=='delete_one':return op,'delete table inet '+policy.TABLES[1]+'\n'
    if op=='delete_both':return op,''.join('delete table inet '+table+'\n'for table in policy.TABLES)
    return op,None


def keeper(job,epoch,release):
    ids=root_entry(job,epoch,release);folder=Path(ids['directory'])
    fd=os.open(folder/'keeper-used',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
    require(sorted(os.listdir('/sys/class/net'))==['lo'],'owned_kernel_private_network_only')
    for argv in [['link','set','lo','up'],['address','add',policy.FIXTURE+'/32','dev','lo'],
                 ['address','add',policy.RESOLVER+'/32','dev','lo']]:
        subprocess.run(['/usr/sbin/ip',*argv],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=2)
    routes=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','route'],timeout=2))
    require(not any(row.get('dst')=='default' for row in routes),'owned_kernel_no_default_route')
    nft('-f','-',text=policy.rules());expected=filter_identity();began=time.monotonic_ns()
    selected=selectors.DefaultSelector();selected.register(0,selectors.EVENT_READ)
    stopped=[];signal.signal(signal.SIGTERM,lambda *_:stopped.append('external_stop'))
    emit({'ready':True,'role':'keeper','witness':status(),'filter_sha256':expected})
    sequence=0;reason='unknown';removed=False
    try:
        while time.monotonic_ns()-began<8*10**9:
            if stopped:reason=stopped[0];break
            if filter_identity()!=expected:reason='guard_changed';break
            if not selected.select(.1):continue
            raw=sys.stdin.buffer.readline(4097)
            if not raw:reason='controller_lost';break
            value=decode(raw)
            op,script=keeper_action(value,epoch,sequence);sequence+=1
            if op in {'delete_one','delete_both'}:
                require(not removed,'owned_kernel_fault_once');removed=True
            if script is not None:nft('-f','-',text=script)
            if op=='stop':reason='requested_stop'
            emit({'id':value['id'],'accepted':True,'op':op})
            if op=='stop':break
        else:reason='deadline'
    finally:
        selected.close()
        value={'schema':'paw-owned-kernel-owner-v1','epoch':epoch,'reason':reason,
            'namespace_inode':os.stat('/proc/self/ns/net').st_ino,'elapsed_ns':time.monotonic_ns()-began}
        fd=os.open(folder/'owner-result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(canonical(value))


def fixture(job,epoch,release):
    _,witness=role_entry(job,epoch,release,'fixture');selector=selectors.DefaultSelector();streams={}
    tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    tcp.bind((policy.FIXTURE,80));tcp.listen(4);tcp.setblocking(False);selector.register(tcp,selectors.EVENT_READ,'listen')
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((policy.RESOLVER,53));udp.setblocking(False)
    selector.register(udp,selectors.EVENT_READ,'udp');selector.register(0,selectors.EVENT_READ,'control')
    # Both sockets were created with the fixed nonroot UID, preserving skuid
    # firewall checks. Low-port authority ends before readiness/peer processing.
    capabilities(0);witness=status()
    require(os.getresuid()==(policy.FIXTURE_UID,)*3 and os.getresgid()==(policy.FIXTURE_UID,)*3 and
            not os.getgroups() and all(int(witness[k],16)==0 for k in ['cap_eff','cap_prm','cap_inh','cap_amb']),
            'owned_kernel_fixture_capabilities_left')
    counts={'tcp':0,'udp':0,'stream_bytes':0};start=time.monotonic();emit({'ready':True,'role':'fixture','witness':witness})
    try:
        while time.monotonic()-start<10:
            for key,_ in selector.select(.05):
                if key.data=='listen':
                    stream,_=tcp.accept();stream.setblocking(False)
                    if len(streams)>=4:stream.close();continue
                    streams[stream]={'stream':False,'last':0};selector.register(stream,selectors.EVENT_READ,'peer')
                elif key.data=='udp':
                    raw,peer=udp.recvfrom(512)
                    if raw==('OWNED-UDP '+epoch).encode():
                        counts['udp']+=1;udp.sendto(('PAW-UDP-'+epoch).encode(),peer)
                elif key.data=='control':
                    raw=sys.stdin.buffer.readline(4097)
                    if not raw:return
                    value=decode(raw);require(set(value)=={'op'} and value['op']in{'counts','stop'},'owned_fixture_control')
                    emit({'counts':dict(counts)})
                    if value['op']=='stop':return
                else:
                    stream=key.fileobj
                    try:raw=stream.recv(512)
                    except BlockingIOError:continue
                    if not raw:selector.unregister(stream);streams.pop(stream);stream.close();continue
                    if raw==('OWNED-TCP '+epoch).encode():
                        counts['tcp']+=1;stream.sendall(('PAW-TCP-'+epoch).encode())
                    elif raw==('OWNED-STREAM '+epoch).encode():
                        counts['tcp']+=1;streams[stream]['stream']=True
            for stream,row in list(streams.items()):
                if row['stream'] and time.monotonic()-row['last']>=.1:
                    try:
                        count=stream.send(('PAW-STREAM-'+epoch).encode());counts['stream_bytes']+=count
                        require(counts['stream_bytes']<=65536,'owned_fixture_stream_budget');row['last']=time.monotonic()
                    except OSError:
                        selector.unregister(stream);streams.pop(stream);stream.close()
    finally:
        for stream in streams:stream.close()
        tcp.close();udp.close();selector.close()


def probe(job,epoch,release,*,stream_seconds=3):
    require(type(stream_seconds)is int and stream_seconds in {2,3},'owned_probe_stream_duration')
    _,witness=role_entry(job,epoch,release,'probe');emit({'ready':True,'role':'probe','witness':witness})
    value=decode(sys.stdin.buffer.readline(4097))
    require(set(value)=={'op'} and value['op']in{'udp','tcp','udp-other','tcp-other','private','stream'},'owned_probe_operation')
    op=value['op'];datagram=op.startswith('udp');address=policy.RESOLVER if datagram else policy.FIXTURE
    require(stream_seconds==3 or op=='stream','owned_probe_expiry_operation')
    port=(53 if op=='udp' else 54) if datagram else (81 if op=='tcp-other' else 80)
    if op=='private':address='127.0.0.1'
    result={'done':True,'connected':False,'bytes':0,'matched':False,'error':None}
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if datagram else socket.SOCK_STREAM)as stream:
        stream.settimeout(.35)
        try:
            stream.connect((address,port));result['connected']=True
            kind='UDP' if datagram else 'STREAM' if op=='stream' else 'TCP'
            stream.sendall(('OWNED-'+kind+' '+epoch).encode())
            if op=='stream':
                if stream_seconds==2:
                    result.update(observation_started_ns=time.monotonic_ns(),timeouts_after_data=0)
                end=time.monotonic()+stream_seconds
                while time.monotonic()<end:
                    try:raw=stream.recv(128)
                    except socket.timeout:
                        if stream_seconds==2 and result['bytes']:result['timeouts_after_data']+=1
                        continue
                    if not raw:break
                    result['bytes']+=len(raw);result['matched']=raw==('PAW-STREAM-'+epoch).encode()
                    emit({'progress':True,'bytes':result['bytes'],'last_byte_ns':time.monotonic_ns(),
                          'matched':result['matched']})
                if stream_seconds==2:result['observation_finished_ns']=time.monotonic_ns()
            else:
                raw=stream.recv(128);result['bytes']=len(raw);result['matched']=raw==('PAW-'+kind+'-'+epoch).encode()
        except OSError as error:result['error']=type(error).__name__
    emit(result)


class Managed:
    """Root coordinator's bounded private stdio; never a user-selected command."""
    def __init__(self,job,epoch,release,role,keeper_pid=None,registry=None,serial=0,*,protocol=False,defer_ready=False):
        require(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/owned_kernel_runtime.py',
                'owned_kernel_immutable_root_only')
        self.unit,props,command=self._service(job,epoch,release,role,keeper_pid,serial,protocol=protocol)
        require(type(defer_ready)is bool,'owned_kernel_readiness_mode')
        argv=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--unit='+self.unit]
        argv+=['--property='+k+'='+v for k,v in props.items()]
        self.threads=[];self.pidfd=None;self.ready=None;self._ready_received_at=None
        self.process=subprocess.Popen([*argv,*command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        self.output=queue.Queue(maxsize=128);self.errors=bytearray()
        self.pidfd=None
        if registry is not None:registry.append(self)
        def read():
            try:
                if protocol and role=='probe':
                    if __package__:
                        from . import browser_broker_wire as wire
                    else:
                        import browser_broker_wire as wire
                    value=decode(self.process.stdout.readline(4097))
                    self._ready_received_at=time.monotonic();self.output.put(value,timeout=1)
                    decoder=wire.Decoder(epoch)
                    while True:
                        raw=self.process.stdout.read1(32768)
                        if not raw:break
                        for header,body in decoder.feed(raw):
                            self.output.put({'wire':header,'body':body},timeout=1)
                    decoder.eof();self.output.put({'eof':True},timeout=1);return
                for index in range(128):
                    raw=self.process.stdout.readline(4097)
                    if not raw:break
                    value=decode(raw)
                    if value.get('ready')is True and self._ready_received_at is None:
                        self._ready_received_at=time.monotonic()
                    self.output.put(value,timeout=1)
                self.output.put({'eof':True},timeout=1)
            except Exception as error:
                try:self.output.put({'reader_error':type(error).__name__},timeout=1)
                except queue.Full:pass
        def errors():
            raw=self.process.stderr.read(8193);self.errors.extend(raw[:8193])
        self.threads=[threading.Thread(target=read,daemon=True),threading.Thread(target=errors,daemon=True)]
        for thread in self.threads:thread.start()
        # The keeper creates its namespace policy under10%CPU. Its observed
        # PID1/initialization time can exceed2s; the service's8s hard ceiling
        # and500ms stop limit stay unchanged. This is only an observer wait.
        seconds=4 if role=='keeper'else 2
        self._ready_deadline=time.monotonic()+seconds
        if not defer_ready:self._accept_ready(self.receive(seconds))
    def _service(self,job,epoch,release,role,keeper_pid,serial,*,protocol):
        # Trusted immutable subclasses may supply another finite profile. No
        # service property, command or callback arrives from an ordinary RPC.
        return policy.service(job,epoch,release,role,keeper_pid,serial,protocol=protocol)
    def _accept_ready(self,value):
        require(type(value)is dict and value.get('ready')is True,'owned_kernel_role_not_ready')
        self.ready=value;self.pid=value['witness']['pid']
    def poll_ready(self):
        """Same bounded readiness, advanced by the one serial coordinator.

        A later poll cannot accept a header that arrived after the existing
        observer deadline. PID1 hard lifetimes are never changed or restarted.
        """
        if self.ready is not None:return True
        try:value=self.output.get_nowait()
        except queue.Empty:
            require(time.monotonic()<self._ready_deadline,'owned_kernel_role_deadline');return False
        require(type(value)is dict and not value.get('reader_error')and not value.get('eof'),
                'owned_kernel_role_protocol_lost')
        require(self._ready_received_at is not None and self._ready_received_at<=self._ready_deadline,
                'owned_kernel_role_deadline')
        self._accept_ready(value);return True
    def receive(self,seconds=2):
        try:value=self.output.get(timeout=seconds)
        except queue.Empty:raise ValueError('owned_kernel_role_deadline') from None
        require(type(value)is dict and not value.get('reader_error') and not value.get('eof'),
                'owned_kernel_role_protocol_lost')
        return value
    def send(self,value):
        raw=canonical(value);require(len(raw)<4096,'owned_kernel_send_budget')
        self.process.stdin.write(raw+b'\n');self.process.stdin.flush()
    def stop(self):
        value=subprocess.run(['/usr/bin/systemctl','stop',self.unit],capture_output=True,timeout=3)
        if value.returncode!=0:
            # --collect may already have unloaded a terminated transient unit.
            # A launcher exit is never evidence for this independent state.
            state=unit_properties(self.unit)
            require(state['MainPID']=='0' and state['ActiveState']in {'inactive','failed'},
                    'owned_kernel_role_stop_failed')
        self.process.wait(timeout=3)
        for thread in self.threads:thread.join(timeout=1)
        require(all(not thread.is_alive()for thread in self.threads) and len(self.errors)<=8192,
                'owned_kernel_role_readers_or_errors')


def cleanup_actors(actors):
    """Attempt every known writer, even after an earlier stop/readback failure."""
    failures=[]
    for child in reversed(actors):
        try:
            # The launcher and its detached PID1 service have separate lives.
            child.stop()
        except Exception as error:failures.append(type(error).__name__+':stop')
    for child in actors:
        try:
            for thread in child.threads:thread.join(timeout=1)
            require(all(not thread.is_alive()for thread in child.threads) and len(child.errors)<=8192,
                    'owned_kernel_readers_or_errors')
            state=unit_properties(child.unit)
            require(state['MainPID']=='0'and state['ActiveState']in{'inactive','failed'},'owned_kernel_role_residual')
            if child.pidfd is not None:
                # PID reuse cannot make a different process satisfy this proof.
                with selectors.DefaultSelector()as selector:
                    selector.register(child.pidfd,selectors.EVENT_READ)
                    require(selector.select(0),'owned_kernel_pidfd_still_live')
        except Exception as error:failures.append(type(error).__name__+':readback')
        finally:
            if child.pidfd is not None:os.close(child.pidfd);child.pidfd=None
    require(not failures,'owned_kernel_cleanup_failed:'+','.join(failures))


def unit_properties(unit):
    raw=subprocess.check_output(['/usr/bin/systemctl','show',unit,
        '--property=ActiveState,MainPID,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ControlGroup'],text=True,timeout=2)
    return dict(row.split('=',1)for row in raw.splitlines())


def live_role(child,role,namespace=None):
    props=unit_properties(child.unit);witness=child.ready['witness']
    require(props['ActiveState']=='active' and props['MainPID']==str(child.pid),'owned_kernel_main_pid')
    require(int(props['MemoryMax'])==({'keeper':64,'fixture':64,'probe':128}[role])*1024**2 and
        props['MemorySwapMax']=='0' and props['TasksMax']==str({'keeper':8,'fixture':8,'probe':16}[role]),
        'owned_kernel_unit_budget')
    fields=dict(row.split(':',1)for row in Path('/proc/'+str(child.pid)+'/status').read_text().splitlines()if':'in row)
    uid=0 if role=='keeper' else policy.FIXTURE_UID if role=='fixture' else policy.BROKER_UID
    caps=(1<<12)if role=='keeper' else 0
    require(all(int(v)==uid for v in fields['Uid'].split()) and
        all(int(v)==uid for v in fields['Gid'].split()) and
        (set(map(int,fields['Groups'].split()))<={0}if role=='keeper'else not fields['Groups'].split()) and
        fields['NoNewPrivs'].strip()=='1' and
        fields['Seccomp'].strip()=='2' and int(fields['CapEff'],16)==caps and
        int(fields['CapPrm'],16)==caps and int(fields['CapInh'],16)==int(fields['CapAmb'],16)==0,
            'owned_kernel_observed_uid')
    inode=os.stat('/proc/'+str(child.pid)+'/ns/net').st_ino
    require(inode==witness['namespace_inode'] and (namespace is None or inode==namespace),
            'owned_kernel_observed_namespace')
    group=Path('/sys/fs/cgroup')/props['ControlGroup'].lstrip('/')
    require((group/'memory.max').read_text().strip()==props['MemoryMax'] and
        (group/'memory.swap.max').read_text().strip()=='0' and
        (group/'pids.max').read_text().strip()==props['TasksMax'],'owned_kernel_cgroup_budget')
    quota,period=(group/'cpu.max').read_text().split()
    require(quota.isdecimal()and period.isdecimal()and
        int(quota)*100==int(period)*{'keeper':10,'fixture':15,'probe':25}[role],
        'owned_kernel_cgroup_cpu')
    child.pidfd=os.pidfd_open(child.pid)
    require(unit_properties(child.unit)['MainPID']==str(child.pid) and
        os.stat('/proc/'+str(child.pid)+'/ns/net').st_ino==inode,'owned_kernel_pid_changed')
    child.observation={'role':role,'pid':child.pid,'unit':child.unit,'uid':uid,'namespace_inode':inode,
        'no_new_privileges':True,'seccomp':2,'effective_capabilities':caps,
        'supplementary_groups':list(map(int,fields['Groups'].split())),
        'memory_max':int(props['MemoryMax']),'swap_max':0,'tasks_max':int(props['TasksMax']),
        'cpu_max':[int(quota),int(period)]}
    return inode


def prepare_case(folder,job,epoch,release):
    folder.mkdir(mode=0o700,parents=False,exist_ok=False)
    config={'schema':'paw-owned-kernel-config-v1','job':job,'epoch':epoch,'release':release}
    (folder/'config.json').write_bytes(canonical(config));(folder/'config.json').chmod(0o600)
    code=folder/'code';code.mkdir(mode=0o555)
    for source in [HERE,HERE.with_name('owned_kernel_policy.py')]:
        info=source.stat();require(info.st_uid==0 and not info.st_mode&0o022,'owned_kernel_immutable_source')
        raw=source.read_bytes();require(len(raw)<=128*1024,'owned_kernel_source_budget')
        target=code/source.name;target.write_bytes(raw);target.chmod(0o444)
    for role in ['fixture','probe']:
        root=folder/(role+'-root');root.mkdir(mode=0o755)
        for name in ['usr','lib','lib64','etc','proc','sys','dev','tmp','var','opt','run']:(root/name).mkdir(mode=0o755)
        (root/'etc/paw-owned-kernel.json').write_bytes(canonical(config))
        (root/'etc/paw-owned-kernel.json').chmod(0o444);root.chmod(0o555)


def vacant_ids():
    import pwd,grp
    for uid in [policy.BROKER_UID,policy.FIXTURE_UID]:
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise ValueError('owned_kernel_uid_account_exists')
        try:grp.getgrgid(uid)
        except KeyError:pass
        else:raise ValueError('owned_kernel_gid_account_exists')
    count=0
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        count+=1;require(count<=65536,'owned_kernel_process_inventory')
        try:
            text=(path/'status').read_text();uid=next(row for row in text.splitlines()if row.startswith('Uid:'))
        except (FileNotFoundError,ProcessLookupError):continue
        require(not set(map(int,uid.split()[1:]))&{policy.BROKER_UID,policy.FIXTURE_UID},'owned_kernel_uid_busy')


def _owned_validation(job,release):
    """Fixed no-VM entry. Caller must hold the global operation lock."""
    require(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/owned_kernel_runtime.py',
            'owned_kernel_immutable_root_only')
    policy.identity(job,'0'*32,release);vacant_ids()
    parent='paw-vm-owned-'+job+'.service';before=unit_properties(parent)
    require(before['ActiveState']=='active' and before['MainPID']==str(os.getpid()) and
        before['MemoryMax']==str(512*1024**2) and before['MemorySwapMax']=='0' and before['TasksMax']=='64',
        'owned_kernel_parent_budget')
    base=Path('/var/lib/paw-vm/jobs')/job/'kernel-owned';base.mkdir(mode=0o700,exist_ok=False)
    roles=[];results=[];host_namespace=os.stat('/proc/self/ns/net').st_ino
    def limit(memory,tasks,cpu):
        subprocess.run(['/usr/bin/systemctl','set-property','--runtime',parent,
            'MemoryMax='+memory,'TasksMax='+tasks,'CPUQuota='+cpu],check=True,capture_output=True,timeout=2)
    try:
        limit('256M','32','50%')
        for case in ['closed','dns-only','http-expiry','owner-loss','guard-loss']:
            epoch=uuid.uuid4().hex;ids=policy.identity(job,epoch,release);folder=Path(ids['directory'])
            prepare_case(folder,job,epoch,release);case_roles=[];began=time.monotonic_ns();sequence=0;probe_serial=0
            row={'case':case,'result':'FAIL','epoch':epoch}
            try:
                owner=Managed(job,epoch,release,'keeper',registry=roles);case_roles.append(owner)
                inode=live_role(owner,'keeper');require(inode!=host_namespace,'owned_kernel_host_namespace_reused')
                server=Managed(job,epoch,release,'fixture',owner.pid,registry=roles);case_roles.append(server)
                live_role(server,'fixture',inode)
                def control(op,**fields):
                    nonlocal sequence
                    value={'id':sequence,'epoch':epoch,'op':op,**fields};owner.send(value);ack=owner.receive()
                    require(ack.get('id')==sequence and ack.get('accepted')is True,'owned_kernel_control_ack');sequence+=1
                def packet(operation):
                    nonlocal probe_serial
                    child=Managed(job,epoch,release,'probe',owner.pid,registry=roles,serial=probe_serial);case_roles.append(child)
                    probe_serial+=1
                    live_role(child,'probe',inode);child.send({'op':operation});value=child.receive()
                    require(value.get('done')is True,'owned_kernel_probe_not_done');child.process.wait(timeout=2)
                    return value
                if case=='closed':
                    a=packet('udp');b=packet('tcp');require(not a['matched']and not b['connected'],'owned_kernel_default_drop')
                    row['observations']=[a,b]
                elif case=='dns-only':
                    control('lease',kind='dns',milliseconds=1000)
                    a=packet('udp');require(a['matched'],'owned_kernel_dns_tuple')
                    b=packet('tcp');require(not b['connected'],'owned_kernel_tcp_during_dns');row['observations']=[a,b]
                elif case=='http-expiry':
                    control('lease',kind='http',milliseconds=1000)
                    a=packet('tcp');require(a['matched'],'owned_kernel_http_tuple')
                    time.sleep(1.1);b=packet('tcp');require(not b['connected'],'owned_kernel_expired_tuple')
                    row['observations']=[a,b]
                else:
                    control('lease',kind='http',milliseconds=5000)
                    child=Managed(job,epoch,release,'probe',owner.pid,registry=roles);case_roles.append(child)
                    live_role(child,'probe',inode);child.send({'op':'stream'});progress=child.receive()
                    require(progress.get('progress')is True and progress.get('matched')is True,'owned_kernel_live_stream')
                    fault_at=time.monotonic_ns()
                    if case=='owner-loss':signal.pidfd_send_signal(owner.pidfd,signal.SIGKILL)
                    else:control('delete_both')
                    for role in [child,server,owner]:role.process.wait(timeout=3)
                    elapsed=time.monotonic_ns()-fault_at;require(0<=elapsed<12*10**9,'owned_kernel_fault_stop_bound')
                    if case=='guard-loss':
                        result=private_json(folder/'owner-result.json')
                        require(result['reason']=='guard_changed','owned_kernel_guard_loss_disposition')
                    row.update(established_stream=progress,fault_stop_ns=elapsed)
                if case not in {'owner-loss','guard-loss'}:
                    server.send({'op':'stop'});server.receive();server.process.wait(timeout=2)
                    control('stop');owner.process.wait(timeout=2)
                    result=private_json(folder/'owner-result.json');require(result['reason']=='requested_stop','owned_kernel_owner_disposition')
                row.update(result='PASS',namespace_inode=inode,elapsed_ns=time.monotonic_ns()-began)
            finally:
                # Registry includes actors whose readiness constructor failed.
                case_roles=[child for child in roles if epoch[:12]in child.unit]
                cleanup_actors(case_roles)
                vacant_ids()
                row['role_observations']=[child.observation for child in case_roles if hasattr(child,'observation')]
                row['role_diagnostics']=[{'unit':child.unit,'launcher_returncode':child.process.poll(),
                    'stderr':bytes(child.errors).decode('utf-8','replace')}for child in case_roles]
                error=sys.exc_info()[1]
                if error is not None:row['error']=type(error).__name__+':'+str(error)[:256]
                report={'scope':'owned raw TCP/UDP kernel fixtures, not HTTP/TLS/DNS or full O3 acceptance',
                    'result':'FAIL'if error is not None else 'in progress','runs':[*results,row],
                    'real_connections':0,'real_samples_executed':0,'vm_started':False}
                (base/'progress.json').write_bytes(canonical(report))
            results.append(row)
        return {'result':'PASS','scope':'owned loopback kernel components only; not full broker/VM/public gate',
            'cases':results,'real_connections':0,'real_samples_executed':0,'vm_started':False,
            'root_partition_mib':[256,64,128,64],'root_partition_tasks':[32,8,16,8]}
    finally:
        try:cleanup_actors(roles)
        finally:limit('512M','64','100%')



def owned_validation(job,release):
    """Fixed owned-only no-VM entry with terminal-only diagnostic publication."""
    require(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/owned_kernel_runtime.py',
            'owned_kernel_immutable_root_only')
    policy.identity(job,'0'*32,release)
    # Import only from the verified immutable release, never the workspace.
    sys.path.insert(0,str(HERE.parents[2]/'lab/s14'))
    import one_use_authorization as fs
    from vm_runtime_revalidation import snapshot,network_state
    from reader_export import publish_reader_tree
    before=snapshot();network=network_state();record={'result':'FAIL','job':job,'release_sha':release,
        'scope':'owned raw TCP/UDP kernel components only, not HTTP/TLS/DNS/VM/public acceptance',
        'real_connections':0,'real_samples_executed':0,'vm_started':False,
        'i08_installed':False,'production_grants_enabled':False}
    folder=Path('/var/lib/paw-vm/jobs')/job/'kernel-owned'
    try:
        with fs.execution_lock():record.update(_owned_validation(job,release))
    except Exception as error:
        record.update(error_type=type(error).__name__,error=str(error)[:512])
        if(folder/'progress.json').exists():record['progress']=private_json(folder/'progress.json',65536)
    finally:
        # No analysis or diagnostic success is published for unknown writers.
        props=unit_properties('paw-vm-owned-'+job+'.service')
        require(props['MemoryMax']==str(512*1024**2) and props['TasksMax']=='64' and
                props['CPUQuotaPerSecUSec']=='1s','owned_kernel_parent_not_restored')
        active=subprocess.check_output(['/usr/bin/systemctl','list-units','--plain','--no-legend',
            '--state=active,activating,deactivating','paw-owned-kernel-'+job+'-*'],text=True,timeout=3)
        require(not active.strip(),'owned_kernel_units_still_active')
        vacant_ids();after=snapshot();network_after=network_state()
        require(before==after and network==network_after,'owned_kernel_host_not_restored')
        record.update(writers_stopped=True,host_restored=True,host_before=before,host_after=after,
            network_before=network,network_after=network_after,
            programs={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in [HERE,HERE.with_name('owned_kernel_policy.py')]})
        target=Path('/var/lib/paw-vm-exports')/('owned-kernel-'+job)
        with fs.root_directory(target.parent):pass
        target.mkdir(mode=0o700,exist_ok=False)
        with fs.root_directory(target)as fd:fs.exclusive(fd,'attestation.json',canonical(record))
        publish_reader_tree(target)
    require(record['result']=='PASS','owned_kernel_component_failed')
    return {'result':'PASS','scope':record['scope'],'vm_started':False,'real_samples_executed':0,
        'i08_installed':False,'production_grants_enabled':False,'export':str(target),
        'attestation_sha256':hashlib.sha256(canonical(record)).hexdigest()}


def main():
    require(len(sys.argv)==5 and sys.argv[1]in{'--keeper','--fixture','--probe'},'owned_kernel_fixed_arguments')
    role=sys.argv[1][2:];job,epoch,release=sys.argv[2:]
    {'keeper':keeper,'fixture':fixture,'probe':probe}[role](job,epoch,release)


if __name__=='__main__':main()
