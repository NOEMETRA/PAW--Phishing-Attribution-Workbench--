"""Finite policy for a PID1 loopback-only namespace; data, not authority."""
import re

BROKER_UID=65520
FIXTURE_UID=65521
TABLES=('paw_owned_floor','paw_owned_gate')
FIXTURE='93.184.216.34'
RESOLVER='9.9.9.9'
DENIED=('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
    '172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16',
    '198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4')


def require(value,reason):
    if not value:raise ValueError(reason)


def identity(job,epoch,release):
    require(all(type(v) is str and re.fullmatch('[0-9a-f]{32}',v) for v in [job,epoch]) and
        type(release) is str and re.fullmatch('[0-9a-f]{40}',release),'owned_kernel_identity')
    prefix='paw-owned-kernel-'+job+'-'+epoch[:12]
    return {'job':job,'epoch':epoch,'release':release,'parent':'paw-vm-owned-'+job+'.service',
        **{role:prefix+'-'+role+'.service' for role in ['keeper','fixture','probe']},
        'directory':'/var/lib/paw-vm/jobs/'+job+'/kernel-owned/'+epoch}


def rules():
    deny=', '.join(DENIED);out=[]
    for table,priority in zip(TABLES,[-150,-140]):
        out.append(f'''table inet {table} {{
 set targets4 {{ type ipv4_addr . inet_service; flags timeout; timeout 5s; size 1; }}
 set dns4 {{ type ipv4_addr . inet_service; flags timeout; timeout 5s; size 1; }}
 chain allowed {{
  meta nfproto ipv6 drop
  ip saddr {{ {deny} }} drop
  ip daddr {{ {deny} }} drop
  ip daddr . tcp dport @targets4 accept
  ip saddr . tcp sport @targets4 ct state established accept
  ip daddr . udp dport @dns4 accept
  ip saddr . udp sport @dns4 ct state established accept
  drop
 }}
 chain input_guard {{ type filter hook input priority {priority}; policy drop; jump allowed; }}
 chain output_guard {{ type filter hook output priority {priority}; policy drop;
  meta skuid {{ {BROKER_UID}, {FIXTURE_UID} }} jump allowed;
 }}
}}''')
    return '\n'.join(out)+'\n'


def revoke():return ''.join(f'flush set inet {table} {name}\n' for table in TABLES for name in ['targets4','dns4'])


def lease(kind,milliseconds):
    require(type(kind) is str and kind in {'dns','http','https'} and
        type(milliseconds) is int and 1<=milliseconds<=5000,'owned_kernel_lease')
    address,port,name=(RESOLVER,53,'dns4') if kind=='dns' else (FIXTURE,80 if kind=='http' else 443,'targets4')
    return revoke()+''.join(f'add element inet {table} {name} {{ {address} . {port} timeout {milliseconds}ms }}\n' for table in TABLES)


def service(job,epoch,release,role,keeper_pid=None,serial=0):
    ids=identity(job,epoch,release);require(type(role)is str and role in {'keeper','fixture','probe'},'owned_kernel_role')
    require(type(serial)is int and 0<=serial<8 and (role=='probe' or serial==0),'owned_kernel_role_serial')
    memory={'keeper':64,'fixture':64,'probe':128};tasks={'keeper':8,'fixture':8,'probe':16};cpu={'keeper':10,'fixture':15,'probe':25}
    props={'Type':'exec','Restart':'no','MemoryMax':str(memory[role])+'M','MemorySwapMax':'0',
        'TasksMax':str(tasks[role]),'CPUQuota':str(cpu[role])+'%','LimitCORE':'0','LimitFSIZE':'1048576',
        'NoNewPrivileges':'yes','UMask':'0077','KillMode':'control-group','TimeoutStopSec':'500ms',
        'RuntimeMaxSec':'8' if role=='keeper' else '10','RuntimeRandomizedExtraSec':'0','NotifyAccess':'none'}
    if role=='keeper':
        props.update(User='root',PrivateNetwork='yes',PrivateMounts='yes',
            BindsTo=ids['parent'],After=ids['parent'],IPAddressDeny='any',
            CapabilityBoundingSet='CAP_NET_ADMIN',RestrictAddressFamilies='AF_UNIX AF_NETLINK',
            ProtectSystem='strict',ProtectHome='yes',ReadWritePaths=ids['directory'],
            RestrictSUIDSGID='yes',ProtectKernelModules='yes',ProtectKernelTunables='yes')
        command=['/usr/bin/python3','-I','-S','-B','/opt/paw-vm/releases/'+release+
                 '/paw/core/owned_kernel_runtime.py','--keeper',job,epoch,release]
    else:
        require(type(keeper_pid) is int and keeper_pid>1,'owned_kernel_live_keeper_pid')
        # PID1 requires a static account even for a numeric User=. Start only
        # the immutable credential bootstrap; it drops all three UID/GID values
        # before any socket or peer input, without modifying the host user DB.
        props.update(User='root',Group='root',SupplementaryGroups='',
            RootDirectory=ids['directory']+'/'+role+'-root',WorkingDirectory='/',
            BindReadOnlyPaths='/usr /lib /lib64 '+ids['directory']+'/code:/opt/paw-code',
            NetworkNamespacePath='/proc/'+str(keeper_pid)+'/ns/net',
            BindsTo=ids['keeper'],After=ids['keeper'],PrivateMounts='yes',PrivateDevices='yes',
            PrivateTmp='yes',ProtectSystem='strict',ProtectHome='yes',ProtectProc='invisible',ProcSubset='pid',
            ProtectKernelTunables='yes',ProtectKernelModules='yes',ProtectKernelLogs='yes',
            ProtectControlGroups='yes',ProtectClock='yes',RestrictNamespaces='yes',
            RestrictSUIDSGID='yes',RestrictRealtime='yes',LockPersonality='yes',MemoryDenyWriteExecute='yes',
            RestrictAddressFamilies='AF_INET',SystemCallArchitectures='native',SystemCallFilter='@system-service',
            CapabilityBoundingSet='CAP_SETUID CAP_SETGID'+(' CAP_NET_BIND_SERVICE' if role=='fixture' else ''),
            AmbientCapabilities='',
            IPAddressDeny='any',IPAddressAllow=FIXTURE+'/32 '+RESOLVER+'/32')
        command=['/usr/bin/python3','-I','-S','-B','/opt/paw-code/owned_kernel_runtime.py',
                 '--'+role,job,epoch,release]
    unit=ids[role] if role!='probe' else ids[role][:-8]+'-'+str(serial)+'.service'
    return unit,props,command
