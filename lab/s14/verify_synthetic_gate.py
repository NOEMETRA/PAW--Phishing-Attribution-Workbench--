"""Read-only finite synthetic gate evidence; never enables an arbitrary launcher."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Mandatory inventory of the measured finite profile. Later exports may add
# sources, but may not silently discard its runner, guest or isolation policy.
REQUIRED_SOURCES = frozenset('''all-guards.nft benign_guest_validation.py
benign_synthetic.py controlled_guest.py controlled_scope.py controlled_uplink.py
fetch_trusted_image.py fixture_server.py gate_channel.py gate_guest.py gate_payload.py
gateway-bridge.nft gateway-guest.nft gateway-host.nft gateway-wan.xml guest_agent.py
gw_admission.py gw_broker.py gw_fault_validation.py gw_fixture.py gw_node.py
gw_quarantine.py gw_validation.py host-guard.nft host_task_budget_probe.py
internal-network.xml libvirtd-guard.conf machine-paws14.slice networkless_synthetic.py
paused-probe.xml paw-s14-guard.service prepare_uplink.py synthetic_gate.py
test_controlled_uplink.py test_gate_channel.py test_gate_stdio.py test_gw_contracts.py
test_networkless_synthetic.py test_uplink_policy.py test_uplink_vm_evidence.py
uplink_guest_probe.py uplink_policy.py validate_uplink_namespace.py validate_uplink_vm.py
verify_benign_evidence.py verify_controlled_uplink.py verify_gateway_evidence.py
verify_gateway_reboot.py verify_synthetic_gate.py verify_uplink_evidence.py
verify_uplink_vm_evidence.py'''.split())

CHECKS = ['unprivileged_no_nic_host_canary_socket_mount_and_capability_denials',
          'kernel_enforced_fork_budget', 'kernel_enforced_memory_budget', 'kernel_enforced_file_budget',
          'untrusted_output_and_live_publication_refused',
          'malformed_protocol_and_owner_loss_stop_stubborn_descendants_before_late_write',
          'fresh_overlay_excludes_previous_job_marker',
          'host_enforced_overlay_cap_stops_vm_without_filling_host_disk',
          'host_cgroup_oom_before_admission_stops_only_identified_vm']


def require(value, reason):
    if not value: raise ValueError(reason)


def verify_sources(root, manifest, required=REQUIRED_SOURCES):
    require(type(manifest) is dict and required <= manifest.keys(), 'mandatory_source_inventory')
    require(all(type(name) is str and Path(name).name == name and name not in {'.', '..'}
                for name in manifest), 'source_name')
    folder = root / 'sources'
    require(folder.is_dir() and not folder.is_symlink(), 'source_directory')
    exported = {path.name: path for path in folder.iterdir()}
    require(exported.keys() == manifest.keys(), 'exported_source_inventory')
    for name, path in exported.items():
        require(path.is_file() and not path.is_symlink(), 'source_file:' + name)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest[name], 'source_hash:' + name)


def verify_vm_bindings(vms, oom):
    require(len(vms) == 3 and {vm['label'] for vm in vms} == {'boundaries', 'reset-storage', 'host-oom'}, 'vm_label_inventory')
    require(len({vm['uuid'] for vm in vms}) == 3, 'reused_vm_uuid')
    identities = []
    for vm in vms:
        actual = vm['actual']
        require(actual['uuid'] == vm['uuid'] and type(actual['pid']) is int and actual['pid'] > 0, 'actual_vm_identity')
        require(type(actual['pid_identity']) is str and actual['pid_identity'].isdecimal(), 'pid_start_identity')
        identities.append((actual['pid'], actual['pid_identity']))
    require(len(set(identities)) == 3, 'reused_process_identity')
    victim = next(vm['actual']['pid'] for vm in vms if vm['label'] == 'host-oom')
    require('Killed process ' + str(victim) + ' (' in oom['kernel_witness'], 'oom_victim_does_not_match_vm')


def verify(root):
    root = Path(root); r = json.loads((root / 'results.json').read_text())
    require(r['result'] == 'PASS' and not r.get('cleanup_error'), 'matrix_or_cleanup')
    require(all(r[k] for k in ['host_restored', 'source_freeze_unchanged', 'base_unchanged', 'host_canary_unchanged', 'writers_stopped', 'stable_publication']), 'stop_restore_integrity')
    require(r['host_before'] == r['host_after'] and r['real_connections'] == 0, 'host_or_network_changed')
    require([v['name'] for v in r['checks']] == CHECKS and all(v['result'] == 'PASS' for v in r['checks']), 'case_inventory')
    verify_sources(root, r['source_hashes'])
    require(len(r['vms']) == 3, 'vm_inventory')
    verify_vm_bindings(r['vms'], r['checks'][8])
    for vm in r['vms']:
        require(vm['stopped'] and vm['stop_seconds'] < 12 and vm['overlay_bytes'] <= vm['fsize_limit'] <= 256 * 1024**2, 'vm_stop_or_storage_bound')
        actual = vm['actual']; limits = actual['limits']
        require(limits['memory.max'] == str(768 * 1024**2) and limits['memory.swap.max'] == '0' and limits['pids.max'] == '64', 'host_budget')
        require(limits.get('cpu.max') == '50000 100000', 'host_cpu_quota')
        require(actual['apparmor'].startswith('libvirt-') and '(enforce)' in actual['apparmor'], 'apparmor')
        require('Seccomp:\t2' in vm['host_status'], 'qemu_seccomp')
        xml = ET.fromstring((root / (vm['label'] + '-domain.xml')).read_bytes())
        require(xml.findtext('uuid') == vm['uuid'], 'domain_xml_uuid:' + vm['label'])
        require(not xml.findall('devices/interface') and not xml.findall('devices/filesystem') and not xml.findall('devices/hostdev'), 'guest_exposure')
        require(xml.find('defaultiothread').get('thread_pool_max') == '8' and xml.find('memory').text in {'512', '524288'}, 'guest_budget')
        require(xml.find('seclabel[@model="dac"]/label').text.split(':')[0] != '+0', 'qemu_root')
    by = {v['name']: v for v in r['checks']}
    boundary = r['checks'][0]['observation']['data']
    require(boundary['uid'] == boundary['gid'] == 65534 and boundary['no_new_privs'] == '1' and int(boundary['cap_eff'], 16) == 0, 'guest_privilege')
    require(boundary['stdin_path'] == '/dev/null', 'inherited_control_descriptor')
    require(boundary['interfaces'] == ['lo'] and boundary['positive_read'] and all(boundary['denied_paths'].values()) and all(p['denied'] for p in boundary['network']), 'boundary_denials')
    require(boundary['setuid_denied'] and boundary['mount_denied'] and boundary['cgroup_write_denied'], 'guest_escalation')
    fork = by['kernel_enforced_fork_budget']['observation']
    require(fork['data']['denied'] and fork['data']['spawned'] == fork['data']['reaped'] and int(fork['events']['pids.peak']) <= 16, 'fork_limit')
    require(int(dict(line.split() for line in fork['events']['pids.events'].splitlines())['max']) > 0, 'fork_injection_not_observed')
    memory = by['kernel_enforced_memory_budget']['observation']
    require(memory['data']['actual_guest_cgroup_oom'] and memory['returncode'] == -9 and int(dict(line.split() for line in memory['events']['memory.events'].splitlines())['oom_kill']) > 0, 'oom_injection_not_observed')
    disk = by['kernel_enforced_file_budget']['observation']['data']
    require(disk['refused'] and disk['bytes'] <= 1024, 'guest_file_cap')
    protocol = by[CHECKS[5]]
    require('frame_object_required' in protocol['channel_failure'] and protocol['stop_seconds'] < 10, 'protocol_or_descendant_stop')
    require(by[CHECKS[6]]['observation']['data']['prior_marker_absent'], 'fresh_overlay_reset')
    host_disk = by[CHECKS[7]]
    require(host_disk['overlay_bytes'] <= host_disk['cap_bytes'] and 'File too large' in host_disk['emulator_io_error'] and host_disk['fault_seconds'] < 12, 'host_disk_cap_injection')
    oom = by[CHECKS[8]]
    require(oom['injected_limit_bytes'] == 1024**2 and not oom['guest_payload_started'] and
            'Memory cgroup out of memory' in oom['kernel_witness'] and oom['fault_seconds'] < 12, 'host_vm_oom_admission_injection')
    require(len(r['quarantine']) == 1, 'quarantine_inventory')
    folder = root / 'quarantine'
    require(folder.is_dir() and not folder.is_symlink(), 'quarantine_directory')
    require({p.name for p in folder.iterdir()} == {v['stored_as'] for v in r['quarantine']}, 'quarantine_inventory')
    for number, item in enumerate(r['quarantine']):
        require(item['stored_as'] == f'artifact-{number:02d}.bin', 'quarantine_name')
        path = folder / item['stored_as']
        require(path.is_file() and not path.is_symlink(), 'quarantine_file')
        require(path.stat().st_size == item['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], 'quarantine_digest')
    return {'result': 'PASS', 'scope': 'finite offline synthetic adversarial vectors only', 'checks': len(CHECKS),
            'vms': 3, 'real_connections': 0, 'source_count': len(r['source_hashes']),
            'general_hostile_gate': 'OPEN: arbitrary-input integration and independent review not established',
            'general_hostile_launcher': r['general_hostile_launcher']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('directory', type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
