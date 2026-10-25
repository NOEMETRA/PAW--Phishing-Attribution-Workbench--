"""Root-only one-use HTML execution, external stop before opaque quarantine."""
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import time

import browser_authorization as auth
from browser_vm import BrowserVM, BROWSER_BASE
from browser_policy import JOB_MEMORY, JOB_TASKS, JOB_SECONDS
from gw_quarantine import publish, validate_records

require = auth.require
RUNS = Path('/var/lib/libvirt/images/paw-s14/runs')


def input_media(source, identifier):
    """Private root/QEMU ISO; arbitrary bytes are copied, never interpreted."""
    require(os.geteuid() == 0 and type(source) is bytes and 0 < len(source) <= auth.contract.MAX_SOURCE,
            'root_bounded_browser_input')
    require(type(identifier) is str and len(identifier) == 32 and all(v in '0123456789abcdef' for v in identifier),
            'browser_input_identifier')
    with auth.fs.root_directory(RUNS): pass
    directory = RUNS / ('html-input-' + identifier); directory.mkdir(mode=0o700)
    tree = directory / 'tree'; tree.mkdir(mode=0o700)
    with auth.fs.root_directory(tree) as fd: auth.fs.exclusive(fd, 'input.html', source)
    (tree / 'input.html').chmod(0o444); tree.chmod(0o755)
    image = directory / 'input.iso'
    subprocess.run(['/usr/bin/genisoimage', '-quiet', '-output', str(image), '-volid', 'PAWBROWSERINPUT',
                    '-joliet', '-rock', str(tree)], check=True, timeout=30)
    shutil.rmtree(tree)
    # The ISO permissions also apply to the guest-mounted file. Chrome's UID
    # may read it in the guest; only the dedicated QEMU group may read the host ISO.
    group = pwd.getpwnam('libvirt-qemu').pw_gid
    os.chown(image, 0, group); image.chmod(0o440)
    os.chown(directory, 0, group); directory.chmod(0o750)
    return image


def job(frame):
    return {'profile': frame['profile'], 'job_id': 'html-' + frame['request_id'],
            'parent_sha256': frame['case_reference_sha256'], 'source_sha256': frame['source']['sha256'],
            'source_bytes': frame['source']['bytes'], 'operator_authorization': 'root-browser-hash-grant-v1',
            'created_at': frame['created_at'], 'expires_at': frame['expires_at']}


def available_memory():
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    amount, unit = values['MemAvailable'].split()
    require(amount.isdecimal() and unit == 'kB', 'browser_memory_accounting')
    return int(amount)*1024


def validate_outcome(value):
    require(type(value) is dict and set(value) == {'done', 'status', 'returncode', 'records', 'writers_stopped',
            'events', 'output_truncated', 'sandbox'} and value['done'] is True and
            type(value['status']) is str and value['status'] in auth.contract.STATUSES and
            type(value['returncode']) is int and value['writers_stopped'] is True and
            type(value['output_truncated']) is bool, 'browser_outcome_shape')
    events = value['events']
    require(type(events) is dict and set(events) == {'memory.events', 'pids.events', 'pids.current'} and
            all(type(v) is str and len(v) <= 4096 for v in events.values()) and events['pids.current'] == '0',
            'browser_guest_writers')
    sandbox = value['sandbox']
    require(type(sandbox) is dict and set(sandbox) == {'renderer_seen', 'renderer_nnp', 'renderer_seccomp',
            'renderer_pid_namespace', 'all_uids_nonroot'} and all(type(v) is bool for v in sandbox.values()),
            'browser_sandbox_shape')
    if value['status'] == 'completed': require(all(sandbox.values()), 'browser_sandbox_observation_failed')
    records = value['records']; validate_records(records)
    require(len(records) == (0 if value['status'] == 'cancelled' else 1) and
            all(v['name'] == 'observations.json' and v['scope'] == 'opaque untrusted guest browser output' for v in records),
            'browser_output_inventory')
    return value


def run_browser_granted(gate, raw, policy_raw, *, cancel=False):
    require(isinstance(gate, BrowserVM) and gate.phase == 'job', 'browser_runtime_gate_required')
    require(gate.active_vm is None, 'browser_gate_busy')
    with auth.fs.execution_lock():
        # Refusal before consuming a one-use grant or creating a guest.
        require(not gate.connection.listAllDomains(0), 'browser_host_busy')
        require(shutil.disk_usage(BROWSER_BASE.parent).free >= 10*1024**3, 'browser_disk_admission')
        require(available_memory() >= 2*1024**3, 'browser_available_memory_admission')
        context = auth.capture(); auth.validate_context(context)
        ledger, grant_raw, summary, frame, source = auth.consume(raw, policy_raw, context)
        current = job(frame); job_sha = auth.digest(auth.canonical(current)); rid = summary['request_id']
        require(gate.seed_config == {'source_sha256': summary['source_sha256'], 'source_bytes': len(source),
                'job_sha256': job_sha, 'request_id': rid}, 'browser_seed_binding')
        media_sha = auth.file_digest(gate.media)
        admissions = gate.output / 'admissions'; admissions.mkdir(mode=0o700, exist_ok=True)
        with auth.fs.root_directory(admissions) as fd: auth.fs.exclusive(fd, current['job_id']+'.json', auth.canonical(current))
        copied = gate.output / 'authority-copy' / rid; copied.mkdir(mode=0o700, parents=True)
        for name, data in [('candidate.json', raw), ('grant.json', grant_raw), ('consumed.json', auth.canonical(ledger))]:
            with auth.fs.root_directory(copied) as fd: auth.fs.exclusive(fd, name, data)
        vm = None
        try:
            vm = gate.start(current['job_id'])
            inspection = vm['channel'].call('inspect', seconds=10)
            require(inspection == {'chrome_version': context['chrome_version'], 'chrome_binary_sha256': context['chrome_binary_sha256'],
                    'kernel_release': '6.8.0-147-generic', 'network_interfaces': ['lo'], 'prior_marker_absent': True},
                    'browser_guest_image_or_reset')
            checked, checked_summary, _, checked_source = auth.load_bound(raw, policy_raw, auth.capture())
            require(checked == grant_raw and checked_summary == summary and checked_source == source and
                    auth.file_digest(gate.media) == media_sha, 'browser_authority_changed_after_boot')
            auth.confirm_consumed(ledger); admitted_at = int(time.time())
            admission = vm['channel'].call('start', seconds=10)
            require(type(admission) is dict and admission['started'] is True and admission['prior_marker_absent'] is True and
                    admission['source_sha256'] == summary['source_sha256'] and admission['job_sha256'] == job_sha and
                    admission['job_limits'] == {'memory.max': str(JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(JOB_TASKS)},
                    'browser_guest_admission')
            deadline = time.monotonic() + JOB_SECONDS + 10
            if cancel:
                time.sleep(.25); outcome = vm['channel'].call('cancel', seconds=8)
            else:
                while True:
                    outcome = vm['channel'].call('poll', seconds=8)
                    if outcome.get('done') is True: break
                    require(outcome == {'done': False} and time.monotonic() < deadline, 'browser_host_deadline_or_protocol')
                    time.sleep(.05)
            validate_outcome(outcome)
            gate.stop(vm)
            with auth.fs.root_directory(gate.output) as fd:
                owner = json.loads(auth.fs.read(fd, Path(vm['owner_result_path']).name, 65536))
            require(owner.get('reason') == 'requested_stop' and owner.get('connection_closed') is True and
                    owner.get('vm_uuid') == vm['node']['uuid'], 'browser_unexpected_owner_exit_blocks_publication')
            checked, checked_summary, _, checked_source = auth.load_bound(raw, policy_raw, auth.capture(), now=admitted_at)
            require(checked == grant_raw and checked_summary == summary and checked_source == source and
                    auth.capture() == context and auth.file_digest(gate.media) == media_sha, 'browser_authority_changed_before_publication')
            auth.confirm_consumed(ledger)
            quarantine = publish(gate.output / (current['job_id']+'-quarantine'), outcome['records'], stopped=vm.get('stopped'))
            return {'request_id': rid, 'job': current, 'job_sha256': job_sha, 'vm_uuid': vm['node']['uuid'],
                    'candidate_frame_sha256': auth.digest(raw), 'grant_sha256': auth.digest(grant_raw),
                    'policy_sha256': auth.digest(policy_raw), 'execution_purpose': json.loads(grant_raw)['execution_purpose'],
                    'consumption': ledger, 'admitted_at': admitted_at, 'guest_inspection': inspection,
                    'guest_admission': admission, 'outcome': outcome, 'quarantine': quarantine,
                    'input_media_sha256': media_sha, 'stop_seconds': vm['stop_seconds'], 'writers_stopped': vm['stopped'],
                    'owner_result': owner}
        finally:
            if gate.active_vm is not None: gate.stop(gate.active_vm)
