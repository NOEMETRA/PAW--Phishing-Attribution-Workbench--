"""Explicit execution of an already issued browser hash grant; never issuance."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[1]))
import browser_authorization as auth
from browser_vm import BrowserVM, BROWSER_BASE, BROWSER_META
from browser_offline_adapter import input_media, job, run_browser_granted
from verify_browser_offline import verify_single
from verify_granted_offline import regular
from benign_guest_validation import BASE, digest


def execute(raw, policy_raw, *, cancel=False):
    require = auth.require
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'explicit_root_browser_PID1_operator')
    context = auth.capture(); grant_raw, summary, frame, source = auth.load_bound(raw, policy_raw, context)
    policy, ready = auth.installed(policy_raw, context)
    identifier = summary['request_id']; value = job(frame); job_sha = auth.digest(auth.canonical(value))
    image = input_media(source, identifier)
    output = Path('/var/lib/paw-s14/control') / ('browser-job-'+identifier)
    with auth.fs.root_directory(output.parent): pass
    gate = BrowserVM(argparse.Namespace(output=output), phase='job', media=image,
        seed_config={'source_sha256': summary['source_sha256'], 'source_bytes': len(source),
                     'job_sha256': job_sha, 'request_id': identifier})
    gate.canary = output/'host-owned-canary.bin'; gate.canary.write_bytes(os.urandom(32)); gate.canary.chmod(0o600)
    canary = digest(gate.canary); before = gate.snapshot_host()
    gate.report.update(runs=[], vms=[], real_connections=0, scope=auth.SCOPE)
    with auth.fs.root_directory(BROWSER_META.parent) as fd: certificate = auth.fs.read(fd, BROWSER_META.name, 1024**2)
    with auth.fs.root_directory(output) as fd:
        auth.fs.exclusive(fd, 'policy.json', policy_raw)
        auth.fs.exclusive(fd, 'browser-image-certificate.json', certificate)
        if ready is not None: auth.fs.exclusive(fd, 'readiness.json', ready)
    try:
        result = run_browser_granted(gate, raw, policy_raw, cancel=cancel)
        gate.report.update(runs=[result], result='PASS')
    except Exception as error:
        gate.report.update(result='FAIL', error=str(error), traceback=traceback.format_exc())
    finally:
        try:
            if gate.active_vm is not None: gate.stop(gate.active_vm)
            require(not gate.connection.listAllDomains(0) and before == gate.snapshot_host(), 'browser_host_not_restored')
            require(digest(BASE) == auth.fs.IMAGE_SHA256 and digest(gate.canary) == canary and auth.capture() == context,
                    'browser_context_or_bytes_changed')
            gate.report.update(host_before=before, host_after=gate.snapshot_host(), host_restored=True,
                base_unchanged=True, browser_image_unchanged=True, host_canary_unchanged=True,
                source_freeze_unchanged=True, writers_stopped=True)
        except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error))
        gate.connection.close()
        (output/'results.json').write_bytes(auth.canonical(gate.report))
    if gate.report['result'] == 'PASS':
        try:
            verified = verify_single(output, production=policy['mode'] == 'sample-analysis')
            with auth.fs.root_directory(output) as fd:
                auth.fs.exclusive(fd, 'independent-verification.json', auth.canonical(verified))
        except Exception as error:
            gate.report.update(result='FAIL', verification_error=str(error))
            (output/'results.json').write_bytes(auth.canonical(gate.report))
    return gate.report, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True); parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args(); require = auth.require
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'explicit_root_browser_PID1_operator')
    raw = regular(args.candidate, auth.MAX_FRAME)
    require(auth.contract.shared._hex(args.expected_sha256) and auth.digest(raw) == args.expected_sha256,
            'approved_browser_frame_digest')
    require(auth.contract.shared._hex(args.policy_sha256), 'browser_policy_digest')
    with auth.store() as fd: policy_raw = auth.fs.read(fd, 'policy-'+args.policy_sha256+'.json', 1024**2)
    require(auth.digest(policy_raw) == args.policy_sha256 and json.loads(policy_raw)['mode'] == 'sample-analysis',
            'browser_production_policy_required')
    report, output = execute(raw, policy_raw)
    print(json.dumps({'result': report['result'], 'raw_control': str(output),
        'execution_status': report['runs'][0]['outcome']['status'] if report['runs'] else None,
        'meaning': 'execution/custody only; no risk verdict'}), flush=True)
    require(report['result'] == 'PASS', 'browser_operator_failed_no_export')


if __name__ == '__main__': main()
