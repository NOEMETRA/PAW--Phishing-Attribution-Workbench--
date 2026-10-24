"""Read-only reconciliation of disconnected routed-uplink component evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_gateway_evidence import pcap
from uplink_policy import validate,guard_tables,bridge_table,nat_table,interop_commands,fingerprint

EXPECTED=['forbidden_owned_listener_positive_controls','docker_forward_drop_reproduced_without_interop',
          'empty_lease_denies_even_with_scoped_docker_user_accept','owned_tls_and_snat_positive',
          'other_addresses_ports_udp_dns_quic_router_denied','private_destination_denied_despite_forced_kernel_tuple',
          'gateway_source_spoof_denied','alternate_uplink_route_cannot_fallback',
          'guard_paw_s14_up_floor_empty_rejects_new_lease','guard_paw_s14_up_floor_absent_rejects_new_lease',
          'guard_paw_s14_up_lease_empty_rejects_new_lease','guard_paw_s14_up_lease_absent_rejects_new_lease',
          'lease_expiry_stops_established_tls','lease_revocation_stops_established_tls',
          'issuer_death_cannot_keep_established_lease_alive','request_log_reconciliation_no_forbidden_routed_request']

def require(value,reason):
    if not value:raise ValueError(reason)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def verify(root,prepared):
    result=json.loads((root/'results.json').read_text())
    require(result['result']=='PASS' and result['source_freeze_unchanged'],'result_or_freeze')
    require([v['name'] for v in result['tests']]==EXPECTED and all(v['result']=='PASS' for v in result['tests']),'test_inventory')
    require(all(result[key] for key in ['children_stopped','namespaces_removed','host_network_unchanged']),'cleanup_or_host_state')
    require(result['host_before']==result['host_after'],'host_network_changed')
    for name,digest in result['source_hashes'].items():require(sha(root/'sources'/name)==digest,'source_hash:'+name)
    for interfaces in result['topology'].values():
        require(all(v['ifname'] in {'lo','wan0','gw-tap','up0','out0','out1','peer0','peer1'} for v in interfaces),'physical_interface_in_test')
    request_events=result['actual_requests']
    routed=[v for v in request_events if v['event']=='request' and v['peer']=='198.18.42.1']
    require(routed and all(v['local']=='198.18.43.10' and v['path']=='/get' for v in routed),'unadmitted_routed_request')
    packets=pcap(root/'uplink.pcap')
    for packet in packets:
        if packet['ether_type']==0x806:continue
        require(packet['ether_type']==0x800 and packet.get('protocol')==6,'unexpected_wire_protocol')
        require({packet.get('src'),packet.get('dst')}=={'198.18.42.1','198.18.43.10'},'unexpected_wire_address')
        require(443 in {packet.get('sport'),packet.get('dport')},'unexpected_wire_port')
    require(any(p.get('src')=='198.18.42.1' and p.get('dport')==443 for p in packets),'no_snat_positive_packet')
    by_name={v['name']:v for v in result['tests']}
    for name in ['lease_expiry_stops_established_tls','lease_revocation_stops_established_tls','issuer_death_cannot_keep_established_lease_alive']:
        event=by_name[name]
        require(event['no_eof_or_peer_exit'] and event['bytes_received']>0 and event['bytes_stable_for_seconds']>=.8,'stream_oracle:'+name)
        require(event['last_byte_after_trigger_seconds']<=2.2,'unbounded_old_flow:'+name)
    profile=validate(json.loads((prepared/'profile.json').read_text()))
    require(fingerprint(profile)==result.get('prepared_profile_sha256'),'catalog_not_bound_to_measured_preflight')
    require(set(result['prepared_files_sha256'])=={p.name for p in prepared.iterdir() if p.is_file()},'prepared_inventory_changed')
    for name,digest in result['prepared_files_sha256'].items():require(sha(prepared/name)==digest,'prepared_file_hash:'+name)
    require(profile['mode']=='wifi-routed' and profile['enabled'] is False,'live_profile_enabled')
    require(all(not t['pinned_ipv4'] for t in profile['targets']),'unexpected_real_address_pin')
    require((prepared/'host-guards.nft').read_text()==guard_tables(profile)+bridge_table(profile),'prepared_guard_tamper')
    require((prepared/'nat.nft').read_text()==nat_table(profile),'prepared_nat_tamper')
    require(json.loads((prepared/'docker-user-commands.json').read_text())==interop_commands(profile),'interop_command_tamper')
    for table in result['effective_namespace_rules']['nftables']:
        if 'set' in table and table['set']['name']=='targets4':require(not table['set'].get('elem'),'namespace_lease_not_cleared')
    return {'result':'PASS','scope':'Disabled Wi-Fi profile syntax/binding and disconnected kernel NAT/lease components only',
            'tests':len(EXPECTED),'captured_packets':len(packets),'routed_requests':len(routed),
            'profile_sha256':fingerprint(profile),'physical_host_policy_and_routes_unchanged':True,
            'target':profile['targets'][0]['url'],'target_address_binding':'PENDING','profile_active':False,
            'real_dns_queries':0,'real_connections':0,'kvm_uplink_integration':'NOT_RUN','physical_wifi_forwarding':'NOT_RUN',
            'inventory':{str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file()}}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);parser.add_argument('prepared',type=Path);args=parser.parse_args()
    print(json.dumps(verify(args.directory,args.prepared),indent=2))
