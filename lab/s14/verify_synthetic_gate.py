"""Read-only finite synthetic gate evidence; never enables an arbitrary launcher."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))

CHECKS = ['unprivileged_no_nic_host_canary_socket_mount_and_capability_denials',
          'kernel_enforced_fork_budget', 'kernel_enforced_memory_budget', 'kernel_enforced_file_budget',
          'untrusted_output_and_live_publication_refused',
          'malformed_protocol_and_owner_loss_stop_stubborn_descendants_before_late_write',
          'fresh_overlay_excludes_previous_job_marker',
          'host_enforced_overlay_cap_stops_vm_without_filling_host_disk',
          'host_cgroup_oom_before_admission_stops_only_identified_vm']


def require(value, reason):
    if not value: raise ValueError(reason)


def verify(root):
    root = Path(root); r = json.loads((root / 'results.json').read_text())
    require(r['result'] == 'PASS' and not r.get('cleanup_error'), 'matrix_or_cleanup')
    require(all(r[k] for k in ['host_restored', 'source_freeze_unchanged', 'base_unchanged', 'host_canary_unchanged', 'writers_stopped', 'stable_publication']), 'stop_restore_integrity')
    require(r['host_before'] == r['host_after'] and r['real_connections'] == 0, 'host_or_network_changed')
    require([v['name'] for v in r['checks']] == CHECKS and all(v['result'] == 'PASS' for v in r['checks']), 'case_inventory')
    for name, expected in r['source_hashes'].items():
        require(hashlib.sha256((root / 'sources' / name).read_bytes()).hexdigest() == expected, 'source_hash:' + name)
    require(len(r['vms']) == 3, 'vm_inventory')
    for vm in r['vms']:
        require(vm['stopped'] and vm['stop_seconds'] < 12 and vm['overlay_bytes'] <= vm['fsize_limit'] <= 256 * 1024**2, 'vm_stop_or_storage_bound')
        actual = vm['actual']; limits = actual['limits']
        require(limits['memory.max'] == str(768 * 1024**2) and limits['memory.swap.max'] == '0' and limits['pids.max'] == '64', 'host_budget')
        require(actual['apparmor'].startswith('libvirt-') and '(enforce)' in actual['apparmor'], 'apparmor')
        require('Seccomp:\t2' in vm['host_status'], 'qemu_seccomp')
        xml = ET.fromstring((root / (vm['label'] + '-domain.xml')).read_bytes())
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
    for item in r['quarantine']:
        path = root / 'quarantine' / item['stored_as']
        require(path.name.startswith('artifact-') and path.suffix == '.bin' and path.stat().st_size == item['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], 'quarantine_digest')
    return {'result': 'PASS', 'scope': 'finite offline synthetic adversarial vectors only', 'checks': len(CHECKS),
            'vms': 3, 'real_connections': 0, 'source_count': len(r['source_hashes']),
            'general_hostile_gate': 'OPEN: arbitrary-input integration and independent review not established',
            'general_hostile_launcher': r['general_hostile_launcher']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('directory', type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
