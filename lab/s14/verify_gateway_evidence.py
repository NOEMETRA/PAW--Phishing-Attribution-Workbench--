"""Read-only offline reconciliation of exported fixed S14 gateway evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import xml.etree.ElementTree as ET

CASES=['traffic','extractor','proxy-loss','dns-loss','host-inet-loss','host-l2-loss',
       'guest-filter-loss','clock-back','capture-loss','supervisor-loss','management-loss','expiry']
REASONS={'proxy-loss':'broker_or_dns_lost','dns-loss':'broker_or_dns_lost',
         'host-inet-loss':'host_filter_changed','host-l2-loss':'host_filter_changed',
         'guest-filter-loss':'guest_filter_changed','clock-back':'guest_clock_changed',
         'capture-loss':'capture_or_fixture_lost','management-loss':'management_heartbeat_lost','expiry':'deadline'}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def check(condition,reason):
    if not condition:raise ValueError(reason)

def pcap(path):
    data=path.read_bytes();check(24<=len(data)<=8388608,'pcap_size')
    endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}.get(data[:4]);check(endian,'pcap_magic')
    check(struct.unpack_from(endian+'I',data,20)[0]==1,'pcap_ethernet')
    offset=24;packets=[]
    while offset<len(data):
        check(offset+16<=len(data),'pcap_record_header')
        sec,usec,size,original=struct.unpack_from(endian+'4I',data,offset);offset+=16
        check(0<=size<=256 and size<=original and offset+size<=len(data),'pcap_record_size')
        frame=data[offset:offset+size];offset+=size
        if len(frame)<14:continue
        kind=struct.unpack_from('!H',frame,12)[0]
        value={'ether_type':kind}
        if kind==0x800 and len(frame)>=34:
            start=14;length=(frame[start]&15)*4
            value.update({'src':socket.inet_ntoa(frame[26:30]),'dst':socket.inet_ntoa(frame[30:34]),'protocol':frame[23]})
            if value['protocol'] in {6,17} and len(frame)>=start+length+4:
                value['sport'],value['dport']=struct.unpack_from('!HH',frame,start+length)
        packets.append(value)
    return packets

def verify(root,components_only=False):
    report=json.loads((root/'results.json').read_text())
    if components_only:
        check(report['result']=='FAIL' and report.get('error') is None and
              report.get('cleanup_error')=='Cannot write data: Broken pipe' and
              'self.wan.isActive()' in report.get('cleanup_traceback',''),'unexpected_component_failure')
    else:check(report['result']=='PASS' and report['source_freeze_unchanged'],'matrix_result_or_freeze')
    check([j['case'] for j in report['jobs']]==CASES,'case_inventory')
    budget=int(next(line.split('=',1)[1] for line in report['host_inventory']['slice'].splitlines() if line.startswith('MemoryMax=')))
    check(budget in {1280*1024**2,2*1024**3},'unrecognized_aggregate_budget')
    for name,digest in report['source_hashes'].items():check(sha(root/'sources'/name)==digest,'frozen_source:'+name)
    memory=tasks=0
    for job in report['jobs']:
        case=job['case'];check(job['tree_stopped'],'stop_oracle:'+case)
        check(job['status']==('completed' if case in {'traffic','extractor'} else 'interrupted'),'job_status:'+case)
        peak=job['aggregate_peak_sampled'];memory=max(memory,peak['memory_bytes']);tasks=max(tasks,peak['tasks'])
        check(peak['memory_bytes']<=budget and peak['tasks']<=128,'aggregate_budget:'+case)
        for node in job['nodes']:
            actual=node['actual'];check(actual['uuid']==node['uuid'],'domain_identity:'+case)
            check(actual['limits']['pids.max']=='64' and actual['limits']['memory.max']==str(768*1024**2) and actual['limits']['memory.swap.max']=='0','domain_budget:'+case)
            check(actual['apparmor'].startswith('libvirt-') and '(enforce)' in actual['apparmor'],'apparmor:'+case)
            check(all(int(v)!=0 for v in actual['uid'].split()[1:]),'qemu_uid:'+case)
        for role,state in job['states'].items():
            routes=json.loads(state['routes']);check(not any(v.get('dst')=='default' for v in routes),'guest_default_route:'+case)
        if case=='extractor':
            xml=ET.fromstring((root/'extractor-attached.xml').read_bytes())
            check(not xml.findall('devices/interface'),'extractor_has_nic')
            source=[d for d in xml.findall('devices/disk') if d.find('target').get('dev')=='vdc']
            check(len(source)==1 and source[0].find('readonly') is not None,'evidence_disk_not_readonly')
        if case in REASONS:
            owner=json.loads((root/(case+'-owner-result.json')).read_text())
            check(owner['reason']==REASONS[case] and owner['connection_closed'],'failure_reason:'+case)
            check(job['stop_latency_seconds']<12,'stop_deadline:'+case)
        if case=='supervisor-loss':check(job['owner_exit']==-9,'supervisor_kill')
    traffic=report['jobs'][0]['traffic']
    for key in ['tls_verified','redirect_allowed']:check(traffic[key]['body']['status']=='completed','positive:'+key)
    check(traffic['tls_verified']['body']['hops'][0]['tls_verified'],'verified_tls')
    for key in ['redirect_private','rebinding','loopback','metadata','mixed','bad_dns_wire','response_budget','redirect_budget','wrong_job_token']:
        check(traffic[key]['body']['status']=='refused','negative:'+key)
    check(traffic['bad_tls_name']['body']['reason']=='SSLCertVerificationError','bad_tls_name')
    check(len(traffic['l2'])==12 and all(any(d>0 for d in v['counter_deltas']) and v['no_fixture_request'] for v in traffic['l2'].values()),'l2_drop_counters')
    check(traffic['storage_full']['enospc'] and not traffic['storage_full']['stable_output_published'],'enospc')
    check(traffic['request_budget']['last']['body']['reason']=='budget','request_budget')
    check(len(report['admission_faults'])==7 and all(v['rejected_before_creation'] for v in report['admission_faults']),'admission_faults')
    check(report['startup_failure']['guard_failed'] and report['startup_failure']['libvirt_start_rejected'],'startup_dependency')
    check(report['startup_failure']['whole_host_reboot']=='not_measured','honest_reboot_scope')
    if not components_only:check(report['final_domains']==[] and report['final_bridges']=={'pawbr-int':[]},'final_topology')
    canary=[json.loads(v) for v in (root/'host-canary.jsonl').read_text().splitlines()]
    check(len(canary)==1 and canary[0]['path']=='/positive','host_canary')
    events=[json.loads(v) for v in (root/'wan.jsonl').read_text().splitlines()]
    requests=[v for v in events if v['event']=='http']
    check(not any(v['path'] in {'/forbidden','/second'} for v in requests),'forbidden_http_request')
    check(len([v for v in requests if v['local']=='198.18.40.11'])==1,'forbidden_wan_canary')
    check(all(v['peer']=='198.18.40.2' for v in requests if v['path']!='/positive'),'gateway_only_wan_requests')
    extraction=report['jobs'][1]['extraction']
    check(extraction['network_interfaces']==1 and len(extraction['accepted'])==3 and len(extraction['refused'])==4,'extractor')
    manifest=json.loads((root/'quarantine-manifest.json').read_text())
    check(len(manifest)==3 and sorted(v['stored_as'] for v in manifest)==sorted(p.name for p in (root/'quarantine').iterdir()),'quarantine_inventory')
    for value in manifest:
        path=root/'quarantine'/value['stored_as'];check(sha(path)==value['sha256'] and path.stat().st_size==value['bytes'],'quarantine_hash')
    packet_results={}
    for job in report['jobs']:
        case=job['case']
        lan=pcap(root/(case+'-pawbr-int.pcap'));wan=pcap(root/(case+'-pawbr-wan.pcap'))
        # The bridge capture includes attempted L2 frames; the independent WAN
        # capture must contain only gateway<->owned fixture IP/port tuples.
        for value in wan:
            if value['ether_type']==0x806:continue
            check(value['ether_type']==0x800,'wan_non_ipv4')
            check({value['src'],value['dst']}=={'198.18.40.2','198.18.40.10'},'wan_ip_binding')
            check(value['protocol'] in {6,17},'wan_transport')
            ports={value.get('sport'),value.get('dport')}
            check(bool(ports & ({18080,8443} if value['protocol']==6 else {5353})),'wan_port_binding')
        if case=='traffic':
            check(any(v.get('dport')==3128 for v in lan),'lan_proxy_positive')
            check(any(v.get('dport')==8443 for v in wan),'wan_tls_positive')
            check(any(v.get('dport')==5353 for v in wan),'wan_dns_positive')
        if case=='extractor':check(not lan and not wan,'networkless_extractor_capture')
        packet_results[case]={'lan_packets':len(lan),'wan_packets':len(wan)}
    inventory={str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file()}
    return {'result':'COMPONENTS_PASS' if components_only else 'PASS',
            'original_matrix_result':report['result'],'known_cleanup_error':report.get('cleanup_error'),
            'scope':'Measured offline components; whole-host reboot and live acceptance remain open. Component mode never promotes the original FAIL to PASS.',
            'cases':len(CASES),'aggregate_memory_limit_bytes':budget,'peak_sampled_bytes':memory,'peak_sampled_tasks':tasks,
            'packets':packet_results,'inventory':inventory}

def verify_composed(main,correction,reproduction):
    components=verify(main,components_only=True)
    current=json.loads((correction/'results.json').read_text())
    before=json.loads((reproduction/'results.json').read_text())
    check(before['result']=='FAIL' and before['reproduced_unstopped_peer'] and before['source_freeze_unchanged'] and not before.get('cleanup_error'),'missing_reproduced_domain_loss')
    check(not before['jobs'][0]['fault_oracle']['all_writers_stopped_automatically'],'domain_loss_not_reproduced')
    check(current['result']=='PASS' and current['source_freeze_unchanged'] and not current.get('cleanup_error'),'correction_result')
    check([j['case'] for j in current['jobs']]==['worker-loss','gateway-loss','unexpected-port'],'correction_case_inventory')
    check(current['final_domains']==[] and current['final_bridges']=={'pawbr-int':[]},'correction_final_topology')
    for name,digest in current['source_hashes'].items():check(sha(correction/'sources'/name)==digest,'correction_frozen_source:'+name)
    old=json.loads((main/'results.json').read_text())
    delta={name for name,digest in old['source_hashes'].items() if current['source_hashes'].get(name)!=digest}
    check(delta=={'gw_validation.py','machine-paws14.slice'},'unexpected_runtime_delta:'+str(delta))
    new=(correction/'sources/gw_validation.py').read_text()
    new=new.replace("            if any(process_identity(v['pid'])!=v['identity'] for v in ready):reason='domain_process_lost';break\n",'')
    new=new.replace("            # Network handles are tied to the pre-restart libvirt connection.\n            # Reacquire this owned network before the final cleanup.\n            if self.network_created:self.wan=self.connection.networkLookupByName('paw-s14-wan')\n",'')
    check(new==(main/'sources/gw_validation.py').read_text(),'unreviewed_supervisor_delta')
    check((correction/'sources/machine-paws14.slice').read_text().replace('MemoryMax=2G','MemoryMax=1280M')==(main/'sources/machine-paws14.slice').read_text(),'unreviewed_slice_delta')
    check('MemoryMax=2147483648' in current['host_inventory']['slice'] and 'MemorySwapMax=0' in current['host_inventory']['slice'],'actual_two_gib_budget')
    peaks=[]
    for job in current['jobs']:
        case=job['case'];fault=job['fault_oracle']
        check(job['tree_stopped'] and fault['all_writers_stopped_automatically'] and fault['latency_seconds']<12,'correction_stop:'+case)
        owner=json.loads((correction/(case+'-owner-result.json')).read_text())
        check(owner['reason']==('unexpected_bridge_port' if case=='unexpected-port' else 'domain_process_lost'),'correction_stop_reason:'+case)
        peak=job['aggregate_peak_sampled'];check(peak['memory_bytes']<=2*1024**3 and peak['tasks']<=128,'new_budget_exceeded')
        peaks.append(peak)
        for bridge in ['pawbr-int','pawbr-wan']:pcap(correction/(case+'-'+bridge+'.pcap'))
    check(current['startup_failure']['guard_failed'] and current['startup_failure']['libvirt_start_rejected'],'corrected_startup_test')
    inventory={}
    for label,root in [('main',main),('correction',correction),('reproduction',reproduction)]:
        for path in sorted(root.rglob('*')):
            if path.is_file():inventory[label+'/'+str(path.relative_to(root))]=sha(path)
    return {'result':'PASS','scope':'Composed offline component evidence plus targeted corrected supervision/startup/cleanup; no full exact-current-source rerun is claimed',
            'original_matrix_result':'FAIL (stale network handle); preserved unchanged',
            'component_cases':components['cases'],'correction_cases':3,'reviewed_runtime_delta':sorted(delta),
            'main_packet_counts':components['packets'],'main_peak_sampled_bytes':components['peak_sampled_bytes'],
            'current_peak_sampled_bytes':max(v['memory_bytes'] for v in peaks),'current_peak_sampled_tasks':max(v['tasks'] for v in peaks),
            'whole_host_reboot':'NOT_RUN','live_egress':'UNAVAILABLE','detonation':'NOT_RUN','inventory':inventory}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);parser.add_argument('--components-only',action='store_true')
    parser.add_argument('--correction',type=Path);parser.add_argument('--reproduction',type=Path);args=parser.parse_args()
    if args.correction:
        check(args.reproduction,'reproduction_required');result=verify_composed(args.directory,args.correction,args.reproduction)
    else:result=verify(args.directory,args.components_only)
    print(json.dumps(result,indent=2))
