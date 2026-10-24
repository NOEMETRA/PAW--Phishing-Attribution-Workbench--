"""Read-only reconciliation of host-created S14 validation evidence; no extraction."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import socket
import struct
import zipfile

def packet_attempts(data):
    if data[:4]!=b'\xd4\xc3\xb2\xa1':raise ValueError('Unsupported capture encoding')
    if len(data)<24 or struct.unpack_from('<I',data,20)[0]!=1:raise ValueError('Expected Ethernet PCAP')
    offset=24;attempts={};packets=0
    while offset<len(data):
        if offset+16>len(data):raise ValueError('Truncated capture record')
        _,_,length,original=struct.unpack_from('<IIII',data,offset);offset+=16
        if length>192 or offset+length>len(data):raise ValueError('Unexpected capture length')
        frame=data[offset:offset+length];offset+=length;packets+=1
        if len(frame)<54:continue
        if frame[12:14]==b'\x08\x00':
            source=socket.inet_ntoa(frame[26:30]);target=socket.inet_ntoa(frame[30:34])
            protocol=frame[23];transport=14+(frame[14]&15)*4
        elif frame[12:14]==b'\x86\xdd':
            source=socket.inet_ntop(socket.AF_INET6,frame[22:38]);target=socket.inet_ntop(socket.AF_INET6,frame[38:54])
            protocol=frame[20];transport=54
        else:continue
        if protocol not in (6,17) or len(frame)<transport+4:continue
        port=struct.unpack_from('!H',frame,transport+2)[0]
        if source in ['192.0.2.20','198.18.9.9','fd42:14::20']:
            key=f'{source}->{target}:{port}/{protocol}';attempts[key]=attempts.get(key,0)+1
    required=['192.0.2.20->192.0.2.10:18080/6','192.0.2.20->192.0.2.10:5353/17',
              '192.0.2.20->198.18.0.1:18081/6','192.0.2.20->198.18.1.2:18082/6',
              '192.0.2.20->198.18.1.2:5353/17','fd42:14::20->fd42:14:1::1:18081/6',
              'fd42:14::20->fd42:14:2::2:18082/6','198.18.9.9->198.18.0.1:18081/17']
    if not all(attempts.get(key,0)>0 for key in required):raise ValueError('Missing independent packet attempts')
    return {'pcap_packets':packets,'snaplen':192,'guest_attempts':attempts}

def verify(path):
    with zipfile.ZipFile(path) as archive:
        entries=archive.infolist()
        if len(entries)>128 or sum(item.file_size for item in entries)>64*1024**2:
            raise ValueError('Validation evidence exceeds admission budget')
        names=[item.filename for item in entries]
        if len(names)!=len(set(names)):raise ValueError('Duplicate evidence member')
        for item in entries:
            member=PurePosixPath(item.filename)
            if member.is_absolute() or '..' in member.parts or '\\' in item.filename or stat.S_ISLNK(item.external_attr>>16):
                raise ValueError('Unsafe evidence member')
        inventory=json.loads(archive.read('inventory.json'))
        report=json.loads(archive.read('results.json'))
        vendor={'vendor/provenance.json','vendor/SHA256SUMS','vendor/SHA256SUMS.gpg'}
        if set(names)!=set(inventory)|{'inventory.json'}|vendor:
            raise ValueError('Incomplete or unexpected evidence membership')
        for name,expected in inventory.items():
            if hashlib.sha256(archive.read(name)).hexdigest()!=expected:
                raise ValueError('Evidence hash mismatch: '+name)
        if report['result']!='PASS' or report.get('cleanup_error') or report.get('fixture_writers_stopped') is not True:
            raise ValueError('Incomplete validation or unconfirmed writers')
        expected={'traffic':'completed','capture-loss':'interrupted','supervisor-kill':'interrupted',
                  'expiry':'interrupted','fixture-loss':'interrupted'}
        if {job['name']:job['status'] for job in report['jobs']}!=expected:
            raise ValueError('Missing or incorrectly qualified completed/interrupted jobs')
        for job in report['jobs']:
            if job['tree_stopped'] is not True or job.get('vendor_base_unchanged') is not True:
                raise ValueError('Unknown stop or changed base')
            admission=job['admission']
            if admission['uuid']!=job['uuid'] or admission['apparmor']!=f"libvirt-{job['uuid']} (enforce)":
                raise ValueError('Domain identity/confinement mismatch')
            if admission['limits']!={'pids.max':'64','memory.max':str(768*1024**2),'memory.swap.max':'0','cpu.max':'75000 100000'}:
                raise ValueError('Unexpected effective resource budget')
            if job['guest_snapshot']['data']['marker_exists']:
                raise ValueError('Prior marker survived overlay reset')
            if job['name']=='supervisor-kill':
                if job['owner_exit']!=-9:raise ValueError('Supervisor SIGKILL not observed')
            elif job['name']!='traffic':
                owner=json.loads(archive.read(job['name']+'-owner-result.json'))
                reason='deadline' if job['name']=='expiry' else 'health_process_lost'
                if owner['reason']!=reason:raise ValueError('Wrong independent failure trigger')
            if job['name']!='traffic' and not 0<=job['stop_latency_seconds']<12:
                raise ValueError('Failure stop exceeded budget')
        if {case['policy'] for case in report['guard_admission_faults']}!={'empty','absent'}:
            raise ValueError('Missing effective-policy admission faults')
        if not all(case['creation_rejected'] and case['no_domain_created'] for case in report['guard_admission_faults']):
            raise ValueError('Guest created without required guard')
        if report['exclusive_image_lock']['second_writer_denied'] is not True:
            raise ValueError('Missing image-lock refusal')
        packets=packet_attempts(archive.read('traffic.pcap'))
        listeners={}
        for role in ['host','lan','peer']:
            events=[json.loads(line)['event'] for line in archive.read(role+'.jsonl').decode().splitlines()]
            listeners[role]={kind:events.count(kind) for kind in ['tcp','udp','stream_start']}
        if any(listeners[role]['tcp']!=1 or listeners[role]['udp']!=0 for role in ['host','lan']):
            raise ValueError('Forbidden listener received traffic beyond the host positive control')
        if listeners['peer']['tcp']!=5 or listeners['peer']['udp']!=1 or listeners['peer']['stream_start']!=4:
            raise ValueError('Missing independent allowed/established-stream observations')
        return {'result':'PASS','jobs':len(report['jobs']),'inventory_files':len(inventory),
                'stop_latencies':{j['name']:j.get('stop_latency_seconds') for j in report['jobs']},
                'packet_reconciliation':packets,'listener_counts':listeners,
                'scope':'Internal artifact integrity and bounded fixture reconciliation; no report authenticity, accuracy or complete S14 gate claim'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    print(json.dumps(verify(parser.parse_args().archive),indent=2))
