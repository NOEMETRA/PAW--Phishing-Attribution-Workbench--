"""Trusted fixture node for gateway, worker or networkless extraction roles."""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import tty

sys.path.insert(0,str(Path(__file__).resolve().parent))
from gw_admission import encode_name

CFG=json.loads(Path('/etc/paw-node.json').read_text())
ROLE=CFG['role']
STATE=Path('/var/lib/paw-s14')
CHILDREN={}
OUTPUT_LOCK=threading.Lock()

def emit(value):
    data=('PAW14 '+json.dumps(value)+'\n').encode()
    with OUTPUT_LOCK:
        offset=0
        while offset<len(data):offset+=os.write(1,data[offset:])

def filter_fingerprint():
    try:
        data=json.loads(nft('-j','list','table','inet','paw_gateway'))
        def clean(value):
            if isinstance(value,list):return [clean(v) for v in value if not isinstance(v,dict) or 'metainfo' not in v]
            if isinstance(value,dict):
                if set(value)=={'counter'}:return {'counter':{}}
                return {k:clean(v) for k,v in value.items() if k!='handle'}
            return value
        return hashlib.sha256(json.dumps(clean(data),sort_keys=True).encode()).hexdigest()
    except Exception:return None

def health():
    while True:
        time.sleep(.5)
        emit({'health':True,'utc':time.time(),'monotonic':time.monotonic(),
              'children':{name:p.poll() is None for name,p in CHILDREN.items()},
              'filter':filter_fingerprint()})

def nft(*args):
    return subprocess.check_output(['/opt/paw-nft/ld-linux-x86-64.so.2','--library-path','/opt/paw-nft',
                                    '/opt/paw-nft/nft',*args],timeout=3).decode()

def fetch(url, token=None, method='POST'):
    import http.client
    client=http.client.HTTPConnection('192.0.2.1',3128,timeout=12)
    value=json.dumps({'job_id':CFG['job_id'],'url':url})
    client.request(method,'/fetch',body=value,headers={'Authorization':'Bearer '+(token or CFG['token']),
                                                     'Content-Type':'application/json'})
    response=client.getresponse();data=response.read(32769)
    client.close()
    if len(data)>32768:raise ValueError('broker_response_budget')
    try:body=json.loads(data)
    except ValueError:body={'status':'http_error','code':response.status}
    return {'http_status':response.status,'body':body}

def dns(name):
    data=struct.pack('!6H',0x1414,0x100,1,0,0,0)+encode_name(name)+b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(1);client.sendto(data,('192.0.2.1',5353));answer,_=client.recvfrom(513)
    return {'response':answer.hex(),'rcode':answer[3]&15}

def packets(case):
    # Constructed source/MAC/VLAN/IPv6/fragment/tunnel frames. Every target is owned.
    def checksum(data):
        value=sum(struct.unpack('!%dH'%(len(data)//2),data));value=(value&65535)+(value>>16)
        return (~((value&65535)+(value>>16)))&65535
    results=[]
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as wire:
        wire.bind(('lan0',0))
        dst=bytes.fromhex('525400140001');valid_src=bytes.fromhex('525400140020')
        for name,source,mac,proto,frag,kind in [
            ('valid-dns','192.0.2.20',valid_src,17,0,0x0800),
            ('direct-wan','192.0.2.20',valid_src,6,0,0x0800),
            ('spoof-ip','192.0.2.1',valid_src,17,0,0x0800),
            ('spoof-mac','192.0.2.20',bytes.fromhex('525400abcdef'),17,0,0x0800),
            ('fragment','192.0.2.20',valid_src,17,0x2000,0x0800),
            ('ip-in-ip','192.0.2.20',valid_src,4,0,0x0800),
            ('ipv6-tunnel','192.0.2.20',valid_src,41,0,0x0800),
            ('gre','192.0.2.20',valid_src,47,0,0x0800),
            ('vlan','192.0.2.20',valid_src,17,0,0x8100),
            ('qinq','192.0.2.20',valid_src,17,0,0x88a8),
            ('mpls','192.0.2.20',valid_src,17,0,0x8847)]:
            if name!=case:continue
            query=struct.pack('!6H',0x1414,0x100,1,0,0,0)+encode_name('allow.fixture.invalid')+b'\x00\x01\x00\x01'
            payload=struct.pack('!HHHH',18100,5353,8+len(query),0)+query
            destination='198.18.40.10' if name=='direct-wan' else '192.0.2.1'
            header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),0x1414,frag,32,proto,0,
                               socket.inet_aton(source),socket.inet_aton(destination))
            header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
            frame=dst+mac+struct.pack('!H',kind)+(b'\0\1\x08\0' if kind in {0x8100,0x88a8} else b'')+header+payload
            wire.send(frame);results.append(name)
        ipv6=struct.pack('!IHBB',6<<28,16,17,32)+socket.inet_pton(socket.AF_INET6,'fd42:14::20')+socket.inet_pton(socket.AF_INET6,'fd42:14::1')+b'IPv6-owned-probe!'
        if case=='ipv6':wire.send(dst+valid_src+b'\x86\xdd'+ipv6);results.append('ipv6')
        arp=struct.pack('!HHBBH',1,0x800,6,4,2)+valid_src+socket.inet_aton('192.0.2.1')+dst+socket.inet_aton('192.0.2.20')
        if case=='arp-poison':wire.send(dst+valid_src+b'\x08\x06'+arp);results.append('arp-poison')
    if not results:raise ValueError('fixed_packet_case')
    return {'sent':results}

def probes():
    results=[]
    # Actual management address is this host's owned canary, never a LAN peer.
    for host,port in [(CFG['host_ip'],18080),('198.18.40.10',18080),
                      ('198.18.40.11',18080),('192.0.2.1',8443)]:
        try:
            with socket.create_connection((host,port),timeout=.4):connected=True
        except OSError:connected=False
        results.append({'address':host,'port':port,'connected':connected})
    for host,port in [('198.18.40.10',5353),('192.0.2.1',53),('198.18.40.10',443)]:
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(.4);client.sendto(b'owned-denial-probe',(host,port));client.recv(512)
            connected=True
        except OSError:connected=False
        results.append({'address':host,'port':port,'udp_response':connected})
    return results

def output_fixture():
    directory=STATE/'output';directory.mkdir(exist_ok=True)
    (directory/'observation.txt').write_bytes(b'owned result\n')
    (directory/'active.html').write_bytes(b'<script>inert fixture</script>')
    (directory/'oversized.bin').write_bytes(b'x'*2048)
    (directory/'shadow-link').symlink_to('/etc/shadow')
    os.mkfifo(directory/'pipe')
    (directory/'bad name').write_bytes(b'reject')
    (directory/'bundle.zip').write_bytes(b'opaque archive fixture, do not expand')
    subprocess.run(['/usr/bin/sync'],check=True,timeout=10)
    return {'created':7}

def extract():
    mount=Path('/mnt/paw-source');mount.mkdir(exist_ok=True)
    subprocess.run(['/usr/bin/mount','-o','ro,noload','/dev/vdc1',str(mount)],check=True,timeout=10)
    accepted=[];refused=[];total=0
    source=mount/'var/lib/paw-s14/output'
    import re
    for path in sorted(source.iterdir()):
        name=path.name;info=path.lstat()
        reason=None
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name):reason='name'
        elif not stat.S_ISREG(info.st_mode):reason='type'
        elif info.st_size>1024:reason='size'
        elif len(accepted)>=4 or total+info.st_size>4096:reason='aggregate'
        if reason:refused.append({'name':name,'reason':reason});continue
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            opened=os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size!=info.st_size:raise ValueError('changed_source')
            data=os.read(fd,1025)
            if len(data)!=info.st_size:raise ValueError('incomplete_source')
            accepted.append({'name':name,'bytes_hex':data.hex(),'sha256':hashlib.sha256(data).hexdigest(),
                             'scope':'opaque, never rendered or expanded'})
            total+=len(data)
        finally:os.close(fd)
    subprocess.run(['/usr/bin/umount',str(mount)],check=True,timeout=10)
    return {'accepted':accepted,'refused':refused,'total_bytes':total,'network_interfaces':list(Path('/sys/class/net').iterdir()).__len__()}

def dispatch(command):
    op=command['op']
    if op=='state':
        value={'role':ROLE,'utc':time.time(),'monotonic':time.monotonic(),
               'addresses':subprocess.check_output(['/usr/sbin/ip','-j','address']).decode(),
               'routes':subprocess.check_output(['/usr/sbin/ip','-j','route']).decode(),
               'children':{name:process.poll() is None for name,process in CHILDREN.items()}}
        if ROLE=='gateway':value['filter']=json.loads(nft('-j','list','ruleset'))
        return value
    if ROLE=='gateway':
        if op=='activate':
            target=Path('/run/paw-s14-active.json')
            if target.exists():raise ValueError('already_activated')
            ttl=command['ttl']
            if type(ttl)not in(int,float) or not 1<=ttl<=120:raise ValueError('ttl')
            target.write_text(json.dumps({'start':time.monotonic(),'expiry':time.monotonic()+ttl}));return {'activated':True}
        if op=='kill':
            name=command['component']
            if name not in CHILDREN:raise ValueError('component')
            CHILDREN[name].kill();CHILDREN[name].wait(timeout=3);return {'killed':name}
        if op=='clock_back':time.clock_settime(time.CLOCK_REALTIME,time.time()-3600);return {'changed':True}
        if op=='remove_filter':nft('flush','ruleset');return {'removed':True}
        if op=='log':
            name=command['name']
            if name not in {'broker.jsonl','dns.jsonl'}:raise ValueError('log_name')
            data=(STATE/name).read_bytes() if (STATE/name).exists() else b''
            offset=command['offset']
            if type(offset)is not int or offset<0 or offset>262144 or len(data)>262144:raise ValueError('log_budget')
            # Small frames let the independent health thread use the same UART
            # without blocking behind a multi-kilobyte hex-encoded response.
            return {'hex':data[offset:offset+256].hex(),'total':len(data)}
    if ROLE=='worker':
        if op=='fetch':return fetch(command['url'],command.get('token'),command.get('method','POST'))
        if op=='dns':return dns(command['name'])
        if op=='raw':return packets(command['case'])
        if op=='probes':return probes()
        if op=='async_fetch':
            threading.Thread(target=lambda:fetch('http://allow.fixture.invalid:18080/slow'),daemon=True).start();return {'started':True}
        if op=='output':return output_fixture()
        if op=='storage_full':
            target=Path('/run/paw-full');target.mkdir(exist_ok=True)
            subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=64k,nr_inodes=16','tmpfs',str(target)],check=True)
            failed=False
            try:
                with (target/'bounded-fixture').open('wb') as stream:stream.write(b'x'*131072);stream.flush();os.fsync(stream.fileno())
            except OSError as error:
                import errno
                failed=error.errno==errno.ENOSPC
            finally:subprocess.run(['/usr/bin/umount',str(target)],check=True)
            return {'enospc':failed,'stable_output_published':False}
        if op=='marker':
            file=STATE/'marker';present=file.exists();file.write_bytes(b'new marker');return {'previous':present}
    if ROLE=='extractor' and op=='extract':return extract()
    raise ValueError('fixed_operation_unavailable')

def main():
    STATE.mkdir(exist_ok=True)
    if ROLE=='gateway':
        subprocess.run(['/usr/sbin/sysctl','-w','net.ipv4.ip_forward=0','net.ipv6.conf.all.disable_ipv6=1'],check=True)
        nft('-f','/etc/paw-gateway.nft')
        for name,extra in [('broker',[]),('dns',['--dns'])]:
            stream=(STATE/(name+'-process.log')).open('wb')
            CHILDREN[name]=subprocess.Popen(['/usr/bin/python3','-I',str(Path(__file__).with_name('gw_broker.py')),*extra],stdout=stream,stderr=stream)
            stream.close()
        time.sleep(.5)
        if any(p.poll() is not None for p in CHILDREN.values()):raise RuntimeError('gateway_service_failed')
    tty.setraw(sys.stdin.fileno());emit({'ready':True,'role':ROLE})
    if ROLE=='gateway':threading.Thread(target=health,daemon=True).start()
    while True:
        data=sys.stdin.buffer.readline(8193)
        if not data:return
        if len(data)>8192:raise ValueError('frame_budget')
        value=json.loads(data)
        try:result={'id':value['id'],'ok':True,'data':dispatch(value)}
        except Exception as error:result={'id':value['id'],'ok':False,'error':type(error).__name__+': '+str(error)[:512]}
        emit(result)

if __name__=='__main__':main()
