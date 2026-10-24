"""Read-only reconciliation of KVM-to-host routed fixture evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_gateway_evidence import pcap

def require(value,reason):
    if not value:raise ValueError(reason)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def verify(root):
    report=json.loads((root/'results.json').read_text())
    require(report['result']=='PASS' and not report.get('cleanup_error'),'result_or_cleanup')
    require(all(report[k] for k in ['source_freeze_unchanged','host_network_restored','writers_stopped','base_unchanged']),'restoration_or_freeze')
    require(report['host_before']==report['host_after'],'host_policy_or_routes_changed')
    names=['trusted_kvm_probe_ready_with_bounded_scope','empty_kernel_lease_blocks_guest',
           'kvm_through_actual_host_docker_user_nat_tls','kvm_existing_tls_stops_on_kernel_expiry',
           'kvm_existing_tls_stops_on_revoke','owner_sigkill_autodestroys_kvm_and_tap']
    require([v['name'] for v in report['tests']]==names and all(v['result']=='PASS' for v in report['tests']),'test_inventory')
    for name,digest in report['source_hashes'].items():require(sha(root/'sources'/name)==digest,'source_hash:'+name)
    domain=report['domain'];limits=domain['limits_after_parent_tightening']
    require(limits['memory.max']==str(768*1024**2) and limits['memory.swap.max']=='0' and limits['pids.max']=='64','scope_limits')
    require(limits['cpu.max'].startswith('50000 '),'scope_cpu')
    require(domain['apparmor'].startswith('libvirt-') and '(enforce)' in domain['apparmor'],'apparmor')
    xml=ET.fromstring((root/'actual-domain.xml').read_bytes())
    require(xml.find('memory').text=='524288' or xml.find('memory').text=='512','guest_memory')
    nics=xml.findall('devices/interface');require(len(nics)==1 and nics[0].get('type')=='bridge' and nics[0].find('source').get('bridge')=='pawbr-up','guest_nic')
    require(not xml.findall('devices/filesystem') and not xml.findall('devices/hostdev'),'guest_host_shares')
    dac=[v for v in xml.findall('seclabel') if v.get('model')=='dac']
    require(len(dac)==1 and not dac[0].find('label').text.startswith('+0:'),'guest_dac')
    cases={v['name']:v for v in report['tests']}
    fetch=cases['kvm_through_actual_host_docker_user_nat_tls']['observation']
    require(fetch['status']=='completed' and fetch['http_status']==200 and fetch['tls_verified'] and fetch['peer']=='198.18.43.10','fetch_positive')
    for name in ['kvm_existing_tls_stops_on_kernel_expiry','kvm_existing_tls_stops_on_revoke']:
        value=cases[name]['observed'];require(value['bytes']>0 and value['running'] and not value['eof'],'stream_peer_alive:'+name)
    require(cases['owner_sigkill_autodestroys_kvm_and_tap']['seconds']<12,'stop_deadline')
    events=[json.loads(v) for v in (root/'fixture.jsonl').read_text().splitlines()]
    requests=[v for v in events if v['event']=='request']
    require(requests and all(v['peer']=='198.18.42.1' and v['local']=='198.18.43.10' and v['path']=='/get' for v in requests),'fixture_requests')
    packets=pcap(root/'uplink-vm.pcap')
    for packet in packets:
        if packet['ether_type']==0x806:continue
        require(packet['ether_type']==0x800 and packet.get('protocol')==6,'wire_protocol')
        require({packet.get('src'),packet.get('dst')}=={'198.18.42.1','198.18.43.10'},'wire_address')
        require(443 in {packet.get('sport'),packet.get('dport')},'wire_port')
    require(any(p.get('protocol')==6 and p.get('src')=='198.18.42.1' and
                p.get('dst')=='198.18.43.10' and p.get('dport')==443
                for p in packets),'no_snat_request_packet')
    require(any(p.get('protocol')==6 and p.get('src')=='198.18.43.10' and
                p.get('dst')=='198.18.42.1' and p.get('sport')==443
                for p in packets),'no_fixture_response_packet')
    return {'result':'PASS','scope':'KVM and actual host routing/NAT to an owned namespace; physical Wi-Fi forwarding and live coordinator NOT_RUN',
            'tests':len(names),'captured_packets':len(packets),'fixture_requests':len(requests),
            'host_network_restored':True,'live_connections':0,
            'inventory':{str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file()}}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);args=parser.parse_args()
    print(json.dumps(verify(args.directory),indent=2))
