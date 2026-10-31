"""PID1 finite owned acceptance from an immutable root snapshot; no real input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import uuid

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[1])]
from vm_release_contract import command, require
from benign_guest_validation import guard_fingerprint, BASE, digest
from vm_operator_host import write_state

STATE = Path('/var/lib/paw-vm')
EXPORTS = Path('/var/lib/paw-vm-exports')


def producer_names(auth):
    with auth.fs.root_directory(Path('/var/lib/paw-s14/control')) as fd:
        names = os.listdir(fd); require(len(names) <= 8192, 'operator_control_directory_budget')
    return {name for name in names if re.fullmatch('browser-acceptance-[0-9a-f]{32}', name)}


def owned_browser_capture(job,release,record,announce):
    from paw.core import owned_mail_channel
    from paw.core.browser_owned_broker import run_owned as broker_probe
    required=owned_mail_channel.admission_required(job,release)
    record['mail_admission_required']=required
    record['mail_capture_scope']=('owned email request and terminal sidecar'if required else
        'protected native enrollment generated fixtures only; no email custody claim')
    admission=owned_mail_channel.admit(job,release,announce)if required else None
    try:record['owned_broker_probe']=broker_probe(job,release)
    finally:
        if admission is not None:record['owned_mail_capture']=owned_mail_channel.publish(admission)
    if admission is not None:
        require(record['owned_mail_capture']['status']=='completed','operator_owned_mail_capture_failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', required=True); parser.add_argument('--job', required=True); args = parser.parse_args()
    command(['run', args.recipe])
    require(len(args.job) == 32 and all(v in '0123456789abcdef' for v in args.job), 'operator_job_identifier')
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined', 'root_PID1_owned_worker')
    if args.recipe == 'vm-acceptance-v1':
        # Restore only the reviewed finite runtime prerequisites. This recipe
        # starts no guest and does not install representation readiness/grants.
        from vm_runtime_revalidation import run_owned
        run_owned(args.job, HERE.parents[1].name)
        return
    if args.recipe == 'python-owned-v2':
        # Fixed staged representation acceptance: one pending existing profile
        # per bounded job (Python, HTML, then owned JS handoff), never caller input.
        from representation_producer import run_owned
        run_owned(args.job, HERE.parents[1].name)
        return
    if args.recipe in {'shell-owned-v1', 'elf-owned-v1'}:
        # Profile is selected by the fixed recipe, never from caller bytes/paths.
        from native_runtime import run_owned_native
        run_owned_native(args.job, HERE.parents[1].name,
                         'shell' if args.recipe == 'shell-owned-v1' else 'elf')
        return
    require(args.recipe == 'browser-owned-v1', 'operator_recipe_not_implemented')
    from browser_validation_inputs import make
    import browser_authorization as auth
    folder = STATE/'jobs'/args.job
    with auth.fs.root_directory(folder): pass
    record = {'result': 'FAIL', 'job': args.job, 'recipe': args.recipe, 'release_sha': HERE.parents[1].name,
              'real_samples_executed': 0, 'guard_before': guard_fingerprint()}
    context = auth.capture(); auth.validate_context(context)
    try:
        # Native enrollment retains only its live one-use generated recipe;
        # every enrolled ordinary run requires the fixed email handoff.
        owned_browser_capture(args.job,HERE.parents[1].name,record,
            lambda value:print(json.dumps(value),flush=True))
        # Fixed generated CDP fixtures in a no-NIC VM, before the existing nine
        # HTML cases. No URL/source/host network authority is accepted here.
        from paw.core.browser_owned_cdp_probe import run_owned as cdp_probe
        record['owned_cdp_probe'] = cdp_probe(args.job, HERE.parents[1].name)
        manifest = make(uuid.uuid4().hex[:16]); source = folder/'owned-inputs.json'
        with auth.fs.root_directory(folder) as fd: auth.fs.exclusive(fd, source.name, manifest)
        target = EXPORTS/args.job
        with auth.fs.root_directory(EXPORTS): pass
        before = producer_names(auth)
        completed = subprocess.run(['/usr/bin/python3', '-I', '-B', str(HERE/'browser_offline_matrix.py'),
            '--manifest', str(source), '--expected-sha256', hashlib.sha256(manifest).hexdigest(),
            '--export', str(target)], timeout=1650, check=False)
        record['returncode'] = completed.returncode
        require(completed.returncode == 0, 'operator_owned_matrix_failed')
        # Find the protected producer record matching this exact generated manifest.
        new = producer_names(auth) - before; require(len(new) == 1, 'operator_owned_matrix_producer')
        audit = Path('/var/lib/paw-s14/control')/next(iter(new))
        with auth.fs.root_directory(audit) as fd:
            require(auth.fs.read(fd, 'approved-inputs.json', 1024**2) == manifest, 'operator_owned_input_identity')
            matrix = json.loads(auth.fs.read(fd, 'results.json', 1024**2))
        require(matrix['result'] == 'PASS' and matrix['context'] == context and len(matrix['runs']) == 9 and
                matrix['actual_real_samples_executed'] == 0 and matrix['i08_accepted'] is False and
                matrix['production_grants_enabled'] is False, 'operator_owned_matrix_scope')
        record.update(result='PASS', cases=9, protected_matrix=str(audit), export=str(target))
    except Exception as error: record.update(error=str(error), traceback=traceback.format_exc())
    finally:
        record['guard_after'] = guard_fingerprint()
        try:
            require(record['guard_before'] == record['guard_after'] and auth.capture() == context and
                    digest(BASE) == auth.fs.IMAGE_SHA256, 'operator_owned_worker_context_changed')
            qemu = subprocess.run(['/usr/bin/pgrep', '-f', '^/usr/bin/qemu-system'], capture_output=True, timeout=10)
            domains = subprocess.check_output(['/usr/bin/virsh', 'list', '--all', '--name'], text=True, timeout=15)
            namespaces = subprocess.check_output(['/usr/sbin/ip', 'netns', 'list'], text=True, timeout=10)
            require(qemu.returncode == 1 and not domains.strip() and not namespaces.strip(), 'operator_owned_worker_residuals')
        except Exception as error: record.update(result='FAIL', cleanup_failed=True, cleanup_error=str(error))
        with auth.fs.root_directory(folder) as fd:
            write_state(fd, 'result.json', record)
    print(json.dumps({'result': record['result'], 'job': args.job, 'real_samples_executed': 0}), flush=True)
    require(record['result'] == 'PASS', 'operator_owned_worker_failed')


if __name__ == '__main__': main()
