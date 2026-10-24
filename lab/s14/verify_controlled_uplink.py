"""Read-only reconciliation of a stopped trusted one-shot connectivity test."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_gateway_evidence import pcap
from uplink_policy import validate, address, fingerprint


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def positive_packets(packets, source, peer, allow_arp):
    for packet in packets:
        if allow_arp and packet['ether_type'] == 0x806:
            continue
        require(packet['ether_type'] == 0x800 and packet.get('protocol') == 6, 'wire_protocol')
        require({packet.get('src'), packet.get('dst')} == {source, peer}, 'wire_address')
        require((packet['src'] == source and packet.get('dport') == 443) or
                (packet['src'] == peer and packet.get('sport') == 443), 'wire_service_direction')
    require(any(p.get('src') == source and p.get('dport') == 443 for p in packets), 'no_request_packet')
    require(any(p.get('src') == peer and p.get('sport') == 443 for p in packets), 'no_response_packet')


def verify(root, mode, case='success', current_sources=None):
    root = Path(root)
    report = json.loads((root / 'results.json').read_text())
    require(report['result'] == 'PASS' and not report.get('cleanup_error'), 'result_or_cleanup')
    require(report['mode'] == mode and report['case'] == case, 'mode_or_case')
    require(all(report[k] for k in ['writers_stopped', 'host_network_restored',
                                    'source_freeze_unchanged', 'base_unchanged']), 'stop_restore_freeze')
    require(report['host_before'] == report['host_after'], 'host_changed')
    require(set(report['source_hashes']) == {p.name for p in (root / 'sources').iterdir()}, 'source_inventory')
    for name, expected in report['source_hashes'].items():
        require(sha(root / 'sources' / name) == expected, 'source_hash:' + name)
        if current_sources:
            require(sha(Path(current_sources) / name) == expected, 'current_source_changed:' + name)
    if current_sources:
        names = {p.name for p in Path(current_sources).iterdir()
                 if p.suffix in {'.py', '.nft', '.xml', '.service', '.conf', '.slice'}}
        require(names == set(report['source_hashes']), 'current_source_inventory')
    domain = report['domain']; limits = domain['limits_after_parent_tightening']
    require(limits['memory.max'] == str(768 * 1024**2) and limits['memory.swap.max'] == '0' and
            limits['pids.max'] == '64' and limits['cpu.max'].startswith('50000 '), 'domain_budget')
    require(domain['apparmor'].startswith('libvirt-') and '(enforce)' in domain['apparmor'], 'apparmor')
    xml = ET.fromstring((root / 'actual-domain.xml').read_bytes())
    interfaces = xml.findall('devices/interface')
    require(len(interfaces) == 1 and interfaces[0].get('type') == 'bridge' and
            interfaces[0].find('source').get('bridge') == 'pawbr-up', 'guest_nic')
    require(not xml.findall('devices/filesystem') and not xml.findall('devices/hostdev'), 'host_shares')
    require(xml.find('seclabel[@model="dac"]/label').text.split(':')[0] != '+0', 'root_dac')
    require(xml.find('memory').text in {'512', '524288'}, 'guest_memory')
    packets = pcap(root / 'uplink-vm.pcap')
    if case != 'success':
        require(mode == 'fixture' and not report['public_get_attempted'] and 'plan' not in report, 'fault_opened_lease')
        require(report['fault_stop_seconds'] < 12, 'fault_stop_deadline')
        require([v['name'] for v in report['tests']] == ['local_fault_stopped_without_lease'], 'fault_inventory')
        return {'result': 'PASS', 'mode': mode, 'case': case, 'stop_seconds': report['fault_stop_seconds'],
                'source_count': len(report['source_hashes']), 'public_connections': 0}
    require(not report.get('monitor_abort'), 'monitor_aborted')
    profile = validate(report['profile']); plan = report['plan']; result = report['fetch']
    require(plan['profile_sha256'] == fingerprint(profile), 'plan_profile')
    peer = address(plan['address'], mode == 'fixture')
    require(peer in profile['targets'][0]['pinned_ipv4'] and result['peer'] == peer, 'peer_binding')
    host = 'httpbingo.org' if mode == 'public' else 'allow.fixture.invalid'
    require(result['status'] == 'completed' and result['tls_verified'] and result['tls_hostname'] == host and
            result['http_status'] == 200 and 0 < result['bytes'] <= 8192 and
            result['requests'] == 1 and result['redirects'] == 0 and result['elapsed_seconds'] <= 5.5, 'fetch_contract')
    require(report['second_request']['status'] == 'refused' and
            report['second_request']['reason'] == 'request_budget', 'retry_not_refused')
    require([v['name'] for v in report['tests']] == ['one_pinned_verified_get_and_retry_refusal'], 'success_inventory')
    positive_packets(packets, '198.18.41.2' if mode == 'public' else '198.18.42.1', peer, True)
    counts = {'uplink': len(packets)}
    if mode == 'public':
        require(report['public_get_attempted'], 'public_not_attempted')
        first, second = report['dns_observations']
        require(first['answers'] == second['answers'] == plan['all_addresses'] == profile['targets'][0]['pinned_ipv4'], 'dns_pins')
        require(0 <= plan['issued_monotonic'] - second['observed_monotonic'] < min(second['ttl'], 10), 'dns_stale_at_admission')
        wifi = pcap(root / 'wifi-target.pcap')
        positive_packets(wifi, profile['uplink']['host_ipv4'], peer, False)
        counts['wifi'] = len(wifi)
    else:
        require(not report['public_get_attempted'], 'unexpected_public_attempt')
    return {'result': 'PASS', 'mode': mode, 'case': case, 'target': 'https://' + host + '/get',
            'peer': peer, 'packet_counts': counts, 'source_count': len(report['source_hashes']),
            'response_bytes': result['bytes'], 'body_sha256': result['sha256'],
            'real_gets': int(mode == 'public'), 'host_restored': True, 'detonation': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path); parser.add_argument('--mode', choices=['fixture', 'public'], required=True)
    parser.add_argument('--case', default='success', choices=['success', 'guard-loss', 'owner-loss'])
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.mode, args.case), indent=2))
