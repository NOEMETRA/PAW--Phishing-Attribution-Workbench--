"""Read-only reconciliation of immutable-input synthetic acceptance exports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offline_input import admit
from offline_input_matrix import SAMPLES, PARENT
from verify_synthetic_gate import require, verify_sources

EXTRA_SOURCES = {'offline_input.py', 'offline_input_guest.py', 'offline_input_matrix.py',
                 'verify_offline_input.py', 'test_offline_input.py'}


def _verify(root, expected):
    root = Path(root); r = json.loads((root / 'results.json').read_text())
    require(r['result'] == 'PASS' and not r.get('cleanup_error'), 'matrix_failed')
    require(all(r.get(k) is True for k in ['host_restored', 'base_unchanged', 'host_canary_unchanged',
                'source_freeze_unchanged', 'writers_stopped', 'replay_refused_before_vm', 'unknown_stop_publication_refused']), 'lifecycle_or_integrity')
    require(r['real_connections'] == 0 and r['host_before'] == r['host_after'], 'host_or_network')
    require(EXTRA_SOURCES <= r['source_hashes'].keys(), 'input_profile_sources')
    verify_sources(root, r['source_hashes'])
    require(len(r['vms']) == len(r['input_runs']) == len(expected), 'job_inventory')
    require({v['label'] for v in r['vms']} == {'owned-' + case for case in expected}, 'vm_labels')
    require(len({v['uuid'] for v in r['vms']}) == len(expected), 'vm_reuse')
    require(len({(v['actual']['pid'], v['actual']['pid_identity']) for v in r['vms']}) == len(expected), 'process_reuse')
    require({j['job']['job_id'] for j in r['input_runs']} == {'owned-' + case for case in expected}, 'job_ids')
    for run in r['input_runs']:
        job = run['job']; case = job['job_id'].removeprefix('owned-')
        admitted = admit(job, now=job['created_at'])
        require(admitted['source'] == SAMPLES[case] and job['parent_sha256'] == PARENT, 'synthetic_input_binding')
        require(admitted['job_sha256'] == run['job_sha256'], 'job_digest')
        ledger = json.loads((root / 'admissions' / (job['job_id'] + '.json')).read_text())
        require(ledger == job, 'admission_ledger')
        vm = next(v for v in r['vms'] if v['label'] == job['job_id'])
        require(run['vm_uuid'] == vm['uuid'] == vm['actual']['uuid'], 'job_vm_binding')
        xml = ET.fromstring((root / (vm['label'] + '-domain.xml')).read_bytes())
        require(xml.findtext('uuid') == vm['uuid'], 'xml_uuid_binding')
        dac = re.fullmatch(r'\+([0-9]+):\+([0-9]+)', xml.findtext('seclabel[@model="dac"]/label') or '')
        require(dac is not None and all(int(part) > 0 for part in dac.groups()), 'qemu_dac_identity')
        memory = xml.find('memory')
        require(memory is not None and (memory.get('unit'), memory.text) in {('MiB', '512'), ('KiB', '524288')}, 'guest_memory_budget')
        require(xml.find('defaultiothread').get('thread_pool_max') == '8', 'guest_io_budget')
        require(not any(xml.findall('devices/' + name) for name in ['interface', 'filesystem', 'hostdev']), 'vm_exposure')
        require(vm['actual']['apparmor'].startswith('libvirt-') and '(enforce)' in vm['actual']['apparmor'] and 'Seccomp:\t2' in vm['host_status'], 'mandatory_controls')
        limits = vm['actual']['limits']
        require(limits['memory.max'] == str(768 * 1024**2) and limits['memory.swap.max'] == '0' and limits['pids.max'] == '64', 'host_limits')
        require(vm['stopped'] is True and run['writers_stopped'] is True and vm['stop_seconds'] < 12 and run['stop_seconds'] == vm['stop_seconds'], 'unknown_stop')
        require(vm['overlay_bytes'] <= vm['fsize_limit'] == 256 * 1024**2, 'file_cap')
        guest = run['guest_admission']
        require(guest['job_sha256'] == run['job_sha256'] and guest['source_sha256'] == job['source_sha256'] and guest['prior_marker_absent'] is True, 'guest_input_or_reset')
        outcome = run['outcome']; require(outcome['status'] == expected[case], 'job_status')
        if case != 'cancel':
            require(outcome['done'] is True and outcome['writers_stopped'] is True and outcome['events']['pids.current'] == '0', 'guest_descendants')
        if case == 'success':
            require(outcome['returncode'] == 0 and bytes.fromhex(outcome['records'][0]['bytes_hex']) == b'OWNED-IMMUTABLE-INPUT\n', 'positive_oracle')
        records = outcome['records']; manifest = run['quarantine']
        require(len(records) == len(manifest) == (0 if case == 'cancel' else 2), 'output_inventory')
        folder = root / (job['job_id'] + '-quarantine')
        require(folder.is_dir() and not folder.is_symlink(), 'quarantine_directory')
        require({p.name for p in folder.iterdir()} == {v['stored_as'] for v in manifest}, 'quarantine_inventory')
        for index, item in enumerate(manifest):
            require(item['stored_as'] == f'artifact-{index:02d}.bin', 'quarantine_path')
            path = folder / item['stored_as']
            require(path.is_file() and not path.is_symlink(), 'quarantine_file')
            data = path.read_bytes()
            require(data == bytes.fromhex(records[index]['bytes_hex']) and len(data) == item['bytes'] <= 1024 and hashlib.sha256(data).hexdigest() == item['sha256'], 'output_bytes')
    return {'result': 'PASS', 'jobs': len(expected), 'sources': len(r['source_hashes']), 'real_connections': 0,
            'profile': 'synthetic-only offline input path; arbitrary execution unavailable',
            'general_hostile_gate': 'OPEN pending independent I08/platform disposition'}


def verify(root):
    return _verify(root, {'success': 'completed', 'timeout': 'timeout', 'cancel': 'cancelled', 'overflow': 'output_budget'})


def verify_fixed_positive(root):
    """Narrow one-job witness for the PAW bridge; default matrix remains four jobs."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from paw.core import synthetic_bridge as contract
    root = Path(root); report = json.loads((root / 'results.json').read_text())
    require('paw_synthetic_bridge.py' in report['source_hashes'], 'linked_bridge_source')
    raw = (root / 'paw-request.json').read_bytes()
    # Historical validation checks the recorded admission time, not a fresh lease.
    require(type(report.get('paw_payload_started_at')) is int, 'linked_bridge_clock')
    contract.validate_request(raw, now=report['paw_payload_started_at'])
    require(report.get('paw_request_sha256') == contract.digest(raw) and
            report.get('bridge_contract_sha256') == contract.digest(Path(contract.__file__).read_bytes()), 'linked_bridge_contract')
    return _verify(root, {'success': 'completed'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('root', type=Path)
    print(json.dumps(verify(parser.parse_args().root), indent=2))
