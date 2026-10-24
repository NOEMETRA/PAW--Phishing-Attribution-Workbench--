"""Explicit root operator bridge: one fixed PAW-linked harmless fixture, no NIC."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1])); sys.path.insert(0, str(HERE))
from paw.core import synthetic_bridge as contract
from offline_input_matrix import InputGate, SAMPLES, job, run_job
from benign_guest_validation import BASE, digest
from gw_quarantine import publish
from verify_offline_input import verify_fixed_positive

CONTROL = Path('/var/lib/paw-s14/control')


def root_directory(path):
    """Fixed operator directories must be real, root-owned and not writable by readers."""
    current = Path('/')
    for component in path.parts[1:]:
        current /= component
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted_root_operator_directory')


def export_receipt(request_raw, request, receipt, records):
    prefix = contract.EXPORT_ROOT
    if not prefix.exists(): prefix.mkdir(mode=0o755); prefix.chmod(0o755)
    root_directory(prefix)
    destination = prefix / request['request_id']
    if destination.exists() or destination.is_symlink(): raise ValueError('request_export_already_exists')
    staging = prefix / ('.pending-' + request['request_id']); staging.mkdir(mode=0o700)
    files = {'request.json': request_raw, 'receipt.json': contract.canonical(receipt)}
    for item in records:
        files[item['stored_as']] = item['data']
    for name, data in files.items():
        fd = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        (staging / name).chmod(0o444)
    staging.chmod(0o755)
    os.rename(staging, destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True, help='Explicitly approved exact PAW request bytes')
    args = parser.parse_args()
    if os.geteuid() != 0 or Path('/proc/self/attr/current').read_text().strip() != 'unconfined':
        raise ValueError('explicit_root_PID1_operator_service_required')
    raw = contract._read_regular(args.request, contract.REQUEST_LIMIT)
    if not contract._hex(args.expected_sha256) or contract.digest(raw) != args.expected_sha256:
        raise ValueError('approved_request_digest_mismatch')
    request = contract.validate_request(raw)
    if hashlib.sha256(SAMPLES['success']).hexdigest() != contract.FIXTURE_SHA256:
        raise ValueError('trusted_catalog_contract_mismatch')
    if shutil.disk_usage('/var/lib/libvirt/images').free < 10 * 1024**3:
        raise ValueError('free_disk_admission')
    root_directory(CONTROL)
    output = CONTROL / ('paw-request-' + request['request_id'])
    contract_hash = contract.digest(Path(contract.__file__).read_bytes())

    class LinkedGate(InputGate):
        def start(self, label, boot=True):
            value = super().start(label, boot=boot)
            contract.validate_request(raw)  # Actual payload admission must remain inside the PAW lease.
            self.bridge_started_at = int(time.time())
            self.report['paw_payload_started_at'] = self.bridge_started_at
            return value

    gate = LinkedGate(argparse.Namespace(output=output)); gate.active_vm = None
    (output / 'paw-request.json').write_bytes(raw); (output / 'paw-request.json').chmod(0o400)
    gate.canary = output / 'host-owned-canary.bin'; gate.canary.write_bytes(os.urandom(32)); gate.canary.chmod(0o600)
    canary = digest(gate.canary); before = gate.snapshot_host()
    gate.report.update(scope='PAW-linked fixed positive no-NIC synthetic fixture only', vms=[], input_runs=[],
                       real_connections=0, paw_request_sha256=contract.digest(raw), bridge_contract_sha256=contract_hash)
    try:
        result = run_job(gate, job('success'))
        if result['outcome']['status'] != 'completed': raise ValueError('fixed_fixture_not_completed')
        gate.report['input_runs'].append(result)
        try: run_job(gate, job('success'))
        except FileExistsError: gate.report['replay_refused_before_vm'] = True
        else: raise ValueError('inner_job_replay')
        unknown = output / 'unknown-stop-must-not-publish'
        try: publish(unknown, [], stopped=None)
        except ValueError: gate.report['unknown_stop_publication_refused'] = not unknown.exists()
        else: raise ValueError('unknown_stop_publication')
        gate.report['result'] = 'PASS'
    except Exception as error:
        gate.report.update(result='FAIL', error=str(error), traceback=traceback.format_exc())
        print(gate.report['traceback'], flush=True)
    finally:
        try:
            if gate.active_vm: gate.stop(gate.active_vm)
            if gate.connection.listAllDomains(0) or before != gate.snapshot_host(): raise ValueError('host_not_restored')
            if digest(BASE) != gate.root_image_sha or digest(gate.canary) != canary: raise ValueError('immutable_base_or_canary_changed')
            if any(digest(HERE / name) != expected for name, expected in gate.source_hashes.items()): raise ValueError('lab_source_freeze_changed')
            if contract.digest(Path(contract.__file__).read_bytes()) != contract_hash: raise ValueError('bridge_contract_changed')
            gate.report.update(host_before=before, host_after=gate.snapshot_host(), host_restored=True,
                               base_unchanged=True, host_canary_unchanged=True, writers_stopped=True, source_freeze_unchanged=True)
        except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error))
        gate.connection.close()
        (output / 'results.json').write_text(json.dumps(gate.report, indent=2) + '\n')
    if gate.report['result'] != 'PASS': raise SystemExit(1)
    verified = verify_fixed_positive(output)
    (output / 'independent-verification.json').write_text(json.dumps(verified, indent=2) + '\n')
    run = gate.report['input_runs'][0]
    records = []
    for item in run['quarantine']:
        data = (output / 'owned-success-quarantine' / item['stored_as']).read_bytes()
        records.append({'stored_as': item['stored_as'], 'data': data})
    if [v['data'] for v in records] != [contract.MARKER, b'']: raise ValueError('positive_marker_oracle')
    receipt = {'schema': 'paw-s14-synthetic-result-v1', 'request_id': request['request_id'],
               'request_sha256': contract.digest(raw), 'case_reference_sha256': request['case_reference_sha256'],
               'profile': contract.PROFILE, 'fixture_sha256': contract.FIXTURE_SHA256,
               'producer_kind': 'local-root-verified-no-nic-synthetic', 'status': 'completed',
               'raw_result_sha256': digest(output / 'results.json'),
               'runtime': {'vm_uuid': run['vm_uuid'], 'job_sha256': run['job_sha256'],
                           'image_sha256': gate.root_image_sha, 'source_inventory_sha256': contract.digest(contract.canonical(gate.source_hashes)),
                           'bridge_contract_sha256': contract_hash, 'source_count': len(gate.source_hashes),
                           'started_at': gate.bridge_started_at, 'completed_at': int(time.time()),
                           'stop_seconds': run['stop_seconds'], 'writers_stopped': True},
               'artifacts': [{'stored_as': v['stored_as'], 'bytes': len(v['data']), 'sha256': contract.digest(v['data'])} for v in records]}
    contract.validate_receipt(contract.canonical(receipt), request, contract.digest(raw))
    exported = export_receipt(raw, request, receipt, records)
    print(json.dumps({'result': 'PASS', 'request_id': request['request_id'], 'export': str(exported),
                      'raw_control': str(output), 'scope': 'one fixed harmless fixture, no NIC; no generic execution'}), flush=True)


if __name__ == '__main__': main()
