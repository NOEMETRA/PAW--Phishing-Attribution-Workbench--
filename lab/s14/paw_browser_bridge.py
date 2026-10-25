"""Explicit root HTML-case bridge; no input-selected commands or case-path reads."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[1]))
from paw.core import browser_bridge as contract
import browser_authorization as auth
from browser_offline_operator import execute
from verify_browser_offline import verify_single


def export_receipt(raw, request, receipt, artifacts, reader_gid):
    require = contract.require
    require(os.geteuid() == 0 and type(reader_gid) is int and 0 <= reader_gid < 2**31, 'root_and_explicit_reader_gid')
    require(raw == contract.canonical(request), 'browser_case_request_bytes')
    contract.validate_request(raw, now=request['candidate']['created_at'])
    contract.validate_receipt(contract.canonical(receipt), request, contract.digest(raw))
    prefix = contract.EXPORT_ROOT
    with auth.fs.root_directory(prefix.parent): pass
    try: prefix.mkdir(mode=0o755)
    except FileExistsError: pass
    with auth.fs.root_directory(prefix) as parent:
        identifier = request['candidate']['request_id']; pending = '.pending-'+identifier
        require(not (prefix/identifier).exists() and not (prefix/identifier).is_symlink(), 'browser_case_export_exists')
        os.mkdir(pending, mode=0o700, dir_fd=parent)
        with auth.fs.root_directory(prefix/pending) as fd:
            require(set(artifacts) == {v['stored_as'] for v in receipt['artifacts']}, 'browser_export_artifacts')
            for name, data in {'request.json': raw, 'receipt.json': contract.canonical(receipt), **artifacts}.items():
                auth.fs.exclusive(fd, name, data)
                os.chown(name, 0, reader_gid, dir_fd=fd, follow_symlinks=False)
                os.chmod(name, 0o440, dir_fd=fd, follow_symlinks=False)
            os.fchown(fd, 0, reader_gid); os.fchmod(fd, 0o750); os.fsync(fd)
        os.rename(pending, identifier, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
    return prefix/identifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--policy-sha256', required=True); parser.add_argument('--reader-gid', type=int, required=True)
    args = parser.parse_args(); require = contract.require
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'explicit_root_browser_PID1_operator')
    raw = contract.shared._read_regular(args.request, contract.REQUEST_LIMIT)
    require(contract.shared._hex(args.expected_sha256) and contract.digest(raw) == args.expected_sha256,
            'approved_browser_case_request_digest')
    request = contract.validate_request(raw); frame = contract.canonical(request['candidate']); summary = auth.inspect(frame)
    require(contract.shared._hex(args.policy_sha256), 'browser_policy_digest')
    with auth.store() as fd: policy_raw = auth.fs.read(fd, 'policy-'+args.policy_sha256+'.json', 1024**2)
    require(auth.digest(policy_raw) == args.policy_sha256, 'browser_policy_digest_binding')
    context = auth.capture(); policy, ready = auth.installed(policy_raw, context)
    require(policy['mode'] == 'sample-analysis' and ready is not None, 'browser_reviewed_sample_mode_required')
    grant_raw, checked, _, _ = auth.load_bound(frame, policy_raw, context)
    require(checked == summary, 'browser_case_grant_binding'); contract_sha = contract.contract_hash()
    report, output = execute(frame, policy_raw)
    require(report['result'] == 'PASS', 'browser_operator_failed_no_case_export')
    verification = verify_single(output)
    run = report['runs'][0]
    require(run['request_id'] == summary['request_id'] and run['job']['parent_sha256'] == summary['case_reference_sha256'] and
            contract.contract_hash() == contract_sha and auth.capture() == context, 'browser_case_post_stop_binding')
    reread, checked, _, _ = auth.load_bound(frame, policy_raw, context, now=run['admitted_at'])
    require(reread == grant_raw and checked == summary, 'browser_case_authority_changed')
    auth.confirm_consumed(run['consumption'])
    artifacts = {}; metadata = []; quarantine = output/('html-'+summary['request_id']+'-quarantine')
    for item in run['quarantine']:
        data = contract.shared._read_regular(quarantine/item['stored_as'], 1024, root_owned=True)
        require(len(data) == item['bytes'] and auth.digest(data) == item['sha256'], 'browser_case_artifact_digest')
        artifacts[item['stored_as']] = data; metadata.append({k: item[k] for k in ['stored_as', 'bytes', 'sha256']})
    result_raw = contract.shared._read_regular(output/'results.json', 2*1024**2, root_owned=True)
    receipt = {'schema': 'paw-s14-browser-case-result-v1', 'producer_kind': 'local-root-verified-browser-offline',
        'request_id': summary['request_id'], 'request_sha256': auth.digest(raw), 'candidate_sha256': auth.digest(frame),
        'binding_sha256': summary['case_reference_sha256'], 'source_sha256': summary['source_sha256'],
        'execution_status': run['outcome']['status'], 'artifacts': metadata,
        'runtime': {'vm_uuid': run['vm_uuid'], 'job_sha256': run['job_sha256'], 'image_sha256': context['image_sha256'],
            'image_certificate_sha256': context['image_certificate_sha256'], 'context_sha256': auth.digest(auth.canonical(context)),
            'chrome_binary_sha256': context['chrome_binary_sha256'],
            'source_inventory_sha256': auth.digest(auth.canonical(report['source_hashes'])), 'source_count': len(report['source_hashes']),
            'policy_sha256': auth.digest(policy_raw), 'grant_sha256': auth.digest(grant_raw), 'readiness_sha256': auth.digest(ready),
            'consumption_sha256': auth.digest(auth.canonical(run['consumption'])), 'raw_result_sha256': auth.digest(result_raw),
            'bridge_contract_sha256': contract_sha, 'admitted_at': run['admitted_at'], 'completed_at': int(time.time()),
            'stop_seconds': run['stop_seconds'], 'writers_stopped': run['writers_stopped']}}
    contract.validate_receipt(contract.canonical(receipt), request, auth.digest(raw))
    exported = export_receipt(raw, request, receipt, artifacts, args.reader_gid)
    print(json.dumps({'result': 'PASS', 'request_id': summary['request_id'], 'export': str(exported),
        'execution_status': run['outcome']['status'], 'verification': verification,
        'meaning': 'local execution/custody only; no risk verdict'}), flush=True)


if __name__ == '__main__': main()
