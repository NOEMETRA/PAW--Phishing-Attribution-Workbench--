"""Root operator: exact PAW attachment request -> reviewed hash adapter -> protected export."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1])); sys.path.insert(0, str(HERE))
from paw.core import offline_bridge as contract
import hash_authorization as auth
from offline_candidate import inspect_candidate, canonical
from verify_hash_offline import verify_single
from benign_guest_validation import digest

CONTROL = Path('/var/lib/paw-s14/control')


def export_receipt(raw, request, receipt, artifacts):
    """Publish only complete root-owned ordinal data, never caller-chosen paths."""
    require = contract.require
    require(os.geteuid() == 0, 'root_operator_required')
    require(raw == contract.canonical(request), 'case_export_request_bytes')
    contract.validate_request(raw, now=request['candidate']['created_at'])
    contract.validate_receipt(contract.canonical(receipt), request, contract.digest(raw))
    prefix = contract.EXPORT_ROOT
    with auth.fs.root_directory(prefix.parent): pass
    try: prefix.mkdir(mode=0o755)
    except FileExistsError: pass
    with auth.fs.root_directory(prefix) as parent:
        rid = request['candidate']['request_id']
        require(not (prefix / rid).exists() and not (prefix / rid).is_symlink(), 'case_export_exists')
        name = '.pending-' + rid
        os.mkdir(name, mode=0o700, dir_fd=parent)
        with auth.fs.root_directory(prefix / name) as fd:
            files = {'request.json': raw, 'receipt.json': contract.canonical(receipt), **artifacts}
            require(set(artifacts) == {v['stored_as'] for v in receipt['artifacts']}, 'case_export_artifacts')
            for filename, content in files.items():
                auth.fs.exclusive(fd, filename, content)
                os.chmod(filename, 0o444, dir_fd=fd, follow_symlinks=False)
            os.fchmod(fd, 0o755); os.fsync(fd)
        os.rename(name, rid, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
    return prefix / rid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    require = contract.require
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'explicit_root_PID1_operator_required')
    raw = contract.shared._read_regular(args.request, contract.REQUEST_LIMIT)
    require(contract.shared._hex(args.expected_sha256) and contract.digest(raw) == args.expected_sha256,
            'approved_case_request_digest')
    request = contract.validate_request(raw); frame = canonical(request['candidate']); summary = inspect_candidate(frame)
    require(contract.shared._hex(args.policy_sha256), 'policy_sha256')
    with auth.store() as fd: policy = auth.fs.read(fd, 'policy-' + args.policy_sha256 + '.json')
    require(auth.digest(policy) == args.policy_sha256, 'policy_digest_binding')
    context = auth.capture(); _, maintenance, ready = auth.installed(policy, context)
    require(json.loads(policy)['mode'] == 'sample-analysis' and ready is not None, 'reviewed_sample_mode_required')
    grant, checked, _, _ = auth.load_bound(frame, policy, context)
    require(checked == summary, 'case_grant_binding')
    # The exact source frame/parent digest is already root approved; PAW paths
    # are not interpreted by this privileged operator. PAW rechecks its case at import.
    rid = summary['request_id']; contract_sha = contract.contract_hash()
    with auth.fs.root_directory(CONTROL): pass
    jobdir = CONTROL / ('case-request-' + rid); jobdir.mkdir(mode=0o700)
    with auth.fs.root_directory(jobdir) as fd:
        auth.fs.exclusive(fd, 'request.json', raw); auth.fs.exclusive(fd, 'candidate.json', frame)
    completed = subprocess.run(['/usr/bin/python3', '-I', str(HERE / 'hash_offline_operator.py'),
        '--candidate', str(jobdir / 'candidate.json'), '--expected-sha256', auth.digest(frame),
        '--policy-sha256', args.policy_sha256], timeout=650)
    require(completed.returncode == 0, 'hash_operator_failed_no_case_export')
    output = CONTROL / ('hash-job-' + rid)
    with auth.fs.root_directory(output): pass
    verification = verify_single(output)
    result_raw = contract.shared._read_regular(output / 'results.json', 2 * 1024**2, root_owned=True)
    result = json.loads(result_raw); run = result['runs'][0]
    require(run['request_id'] == rid and run['job']['parent_sha256'] == summary['case_reference_sha256'] and
            contract.contract_hash() == contract_sha and auth.capture() == context, 'case_post_stop_binding')
    reread, checked, _, _ = auth.load_bound(frame, policy, context, now=run['admitted_at'])
    require(reread == grant and checked == summary, 'case_authority_changed')
    auth.confirm_consumed(run['consumption'])
    folder = output / 'authority-copy' / rid
    require(contract.shared._read_regular(folder / 'candidate.json', 36864, root_owned=True) == frame,
            'case_executed_frame_changed')
    artifacts = {}; metadata = []
    quarantine = output / ('hash-' + rid + '-quarantine')
    for item in run['quarantine']:
        data = contract.shared._read_regular(quarantine / item['stored_as'], 1024, root_owned=True)
        require(digest(quarantine / item['stored_as']) == item['sha256'] and len(data) == item['bytes'], 'case_artifact_digest')
        artifacts[item['stored_as']] = data
        metadata.append({k: item[k] for k in ['stored_as', 'bytes', 'sha256']})
    receipt = {'schema': 'paw-s14-case-result-v1', 'producer_kind': 'local-root-verified-hash-offline',
        'request_id': rid, 'request_sha256': contract.digest(raw), 'candidate_sha256': auth.digest(frame),
        'binding_sha256': summary['case_reference_sha256'], 'source_sha256': summary['source_sha256'],
        'execution_status': run['outcome']['status'], 'artifacts': metadata,
        'runtime': {'vm_uuid': run['vm_uuid'], 'job_sha256': run['job_sha256'], 'image_sha256': auth.fs.IMAGE_SHA256,
            'source_inventory_sha256': auth.digest(canonical(result['source_hashes'])), 'source_count': len(result['source_hashes']),
            'policy_sha256': auth.digest(policy), 'grant_sha256': auth.digest(grant), 'readiness_sha256': auth.digest(ready),
            'consumption_sha256': auth.digest(canonical(run['consumption'])), 'raw_result_sha256': auth.digest(result_raw),
            'bridge_contract_sha256': contract_sha, 'admitted_at': run['admitted_at'], 'completed_at': int(time.time()),
            'stop_seconds': run['stop_seconds'], 'writers_stopped': run['writers_stopped']}}
    contract.validate_receipt(contract.canonical(receipt), request, contract.digest(raw))
    exported = export_receipt(raw, request, receipt, artifacts)
    with auth.fs.root_directory(jobdir) as fd:
        auth.fs.exclusive(fd, 'receipt.json', contract.canonical(receipt))
        auth.fs.exclusive(fd, 'independent-verification.json', canonical(verification))
    print(json.dumps({'result': 'PASS', 'request_id': rid, 'export': str(exported),
                     'execution_status': receipt['execution_status'], 'meaning': 'custody/execution, not a risk verdict'}), flush=True)


if __name__ == '__main__': main()
