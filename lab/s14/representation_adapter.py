"""No-NIC adapters using only separate representation authority.

No ordinary recipe, CLI, Root grant issuer or readiness activation here.
"""
import os
import shutil
import time

import representation_authorization as auth
from hash_offline_adapter import HashGate
from browser_vm import BrowserVM, BROWSER_BASE
from browser_offline_adapter import available_memory, validate_outcome
from browser_policy import JOB_MEMORY, JOB_TASKS, JOB_SECONDS
from offline_input_matrix import _run_admitted_job
from benign_guest_validation import BASE
from gw_quarantine import publish

require = auth.require
PYTHON, HTML = (auth.contract.PROFILES[key][0] for key in ['python', 'html'])


def job(request):
    frame = request['candidate']; profile = frame['profile']
    require(profile in {PYTHON, HTML}, 'representation_adapter_profile')
    value = {'profile': profile, 'job_id': ('rep-python-' if profile == PYTHON else 'rep-html-')+frame['request_id'],
             'parent_sha256': frame['selection_binding_sha256'], 'source_sha256': frame['source']['sha256'],
             'operator_authorization': 'root-representation-grant-v1', 'created_at': frame['created_at'],
             'expires_at': frame['expires_at']}
    if profile == PYTHON: value['source_hex'] = frame['source']['data_hex']
    else: value['source_bytes'] = frame['source']['bytes']
    return value


def _copy(gate, raw, grant, ledger):
    rid = ledger['request_id']; directory = gate.output/'authority-copy'/rid
    directory.mkdir(mode=0o700, parents=True)
    with auth.fs.root_directory(directory) as fd:
        for name, data in [('request.json', raw), ('grant.json', grant), ('consumed.json', auth.canonical(ledger))]:
            auth.fs.exclusive(fd, name, data)


def _refresh(raw, policy, context, grant, summary, source, ledger, *, now=None):
    actual = auth.capture(context['profile'])
    require(auth.canonical(actual) == auth.canonical(context), 'representation_context_changed')
    current, checked, request, data = auth.load_bound(raw, policy, actual, now=now)
    require(current == grant and checked == summary and data == source, 'representation_authority_changed')
    auth.confirm_consumed(ledger)
    return request


def _owner(gate, uid, label, profile):
    with auth.fs.root_directory(gate.output) as fd:
        raw = auth.fs.read(fd, label+'-owner-result.json', 65536)
    value = auth.decode(raw, 65536)
    require(type(value) is dict and value.get('reason') == 'requested_stop' and
            value.get('connection_closed') is True, 'representation_unexpected_owner_exit_blocks_publication')
    if profile == HTML:
        require(value.get('vm_uuid') == uid, 'representation_owner_vm_identity')
    else:
        require(profile == PYTHON, 'representation_owner_profile')
        with auth.fs.root_directory(gate.output) as fd:
            ready = auth.decode(auth.fs.read(fd, label+'-ready.json', 65536), 65536)
        require(ready.get('uuid') == uid, 'representation_owner_vm_identity')
    return value


def _preflight(gate, profile):
    require(os.geteuid() == 0, 'root_representation_adapter_required')
    require(gate.active_vm is None and not gate.connection.listAllDomains(0), 'representation_gate_or_host_busy')
    base = BASE if profile == PYTHON else BROWSER_BASE
    require(shutil.disk_usage(base.parent).free >= 10*1024**3, 'representation_disk_admission')
    require(available_memory() >= 2*1024**3, 'representation_available_memory_admission')


def run_python(gate, raw, policy, *, cancel=False):
    require(os.geteuid() == 0, 'root_representation_adapter_required')
    require(isinstance(gate, HashGate) and not isinstance(gate, BrowserVM), 'representation_python_gate_required')
    with auth.fs.execution_lock():
        _preflight(gate, PYTHON)
        context = auth.capture(PYTHON)
        ledger, grant, summary, request, source = auth.consume(raw, policy, context)
        require(summary['profile'] == PYTHON, 'representation_python_profile')
        gate.hash_context = context['backend']; current_job = job(request)
        current = {'job': current_job, 'job_sha256': auth.digest(auth.canonical(current_job)), 'source': source}
        _copy(gate, raw, grant, ledger); admitted = {}; owner = {}
        def revalidate():
            _refresh(raw, policy, context, grant, summary, source, ledger)
            admitted['at'] = int(time.time())
        def before_publish():
            require(len(gate.report['vms']) == 1, 'representation_single_stopped_vm')
            vm = gate.report['vms'][0]
            require(vm['label'] == current_job['job_id'], 'representation_stopped_vm_label')
            owner.update(_owner(gate, vm['uuid'], vm['label'], PYTHON))
            _refresh(raw, policy, context, grant, summary, source, ledger, now=admitted['at'])
        result = _run_admitted_job(gate, current, revalidate, cancel, before_publish)
        result.update(request_id=summary['request_id'], request_sha256=auth.digest(raw),
            candidate_sha256=summary['candidate_sha256'], selection_binding_sha256=summary['selection_binding_sha256'],
            grant_sha256=auth.digest(grant), policy_sha256=auth.digest(policy), context_sha256=auth.digest(auth.canonical(context)),
            consumption=ledger, admitted_at=admitted['at'], owner_result=owner)
        return result


def run_html(gate, raw, policy, *, cancel=False):
    require(os.geteuid() == 0, 'root_representation_adapter_required')
    require(isinstance(gate, BrowserVM) and gate.phase == 'job', 'representation_html_gate_required')
    with auth.fs.execution_lock():
        _preflight(gate, HTML); context = auth.capture(HTML)
        ledger, grant, summary, request, source = auth.consume(raw, policy, context)
        require(summary['profile'] == HTML, 'representation_html_profile')
        current = job(request); job_sha = auth.digest(auth.canonical(current)); rid = summary['request_id']
        require(gate.seed_config == {'source_sha256': summary['source_sha256'], 'source_bytes': len(source),
                'job_sha256': job_sha, 'request_id': rid}, 'representation_html_seed_binding')
        media_sha = auth.html_backend.file_digest(gate.media)
        admissions = gate.output/'admissions'; admissions.mkdir(mode=0o700, exist_ok=True)
        with auth.fs.root_directory(admissions) as fd: auth.fs.exclusive(fd, current['job_id']+'.json', auth.canonical(current))
        _copy(gate, raw, grant, ledger); backend = context['backend']
        try:
            vm = gate.start(current['job_id'])
            inspection = vm['channel'].call('inspect', seconds=10)
            require(inspection == {'chrome_version': backend['chrome_version'], 'chrome_binary_sha256': backend['chrome_binary_sha256'],
                'kernel_release': '6.8.0-147-generic', 'network_interfaces': ['lo'], 'prior_marker_absent': True},
                'representation_html_guest_image_or_reset')
            _refresh(raw, policy, context, grant, summary, source, ledger)
            require(auth.html_backend.file_digest(gate.media) == media_sha, 'representation_html_media_changed')
            admitted = int(time.time()); admission = vm['channel'].call('start', seconds=10)
            require(type(admission) is dict and admission.get('started') is True and admission.get('prior_marker_absent') is True and
                admission.get('source_sha256') == summary['source_sha256'] and admission.get('job_sha256') == job_sha and
                admission.get('job_limits') == {'memory.max': str(JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(JOB_TASKS)},
                'representation_html_guest_admission')
            deadline = time.monotonic()+JOB_SECONDS+10
            if cancel:
                time.sleep(.25); outcome = vm['channel'].call('cancel', seconds=8)
            else:
                while True:
                    outcome = vm['channel'].call('poll', seconds=8)
                    if outcome.get('done') is True: break
                    require(outcome == {'done': False} and time.monotonic() < deadline, 'representation_html_deadline_or_protocol')
                    time.sleep(.05)
            validate_outcome(outcome); gate.stop(vm)
            owner = _owner(gate, vm['node']['uuid'], current['job_id'], HTML)
            _refresh(raw, policy, context, grant, summary, source, ledger, now=admitted)
            require(auth.html_backend.file_digest(gate.media) == media_sha, 'representation_html_media_changed_before_publication')
            quarantine = publish(gate.output/(current['job_id']+'-quarantine'), outcome['records'], stopped=vm.get('stopped'))
            return {'request_id': rid, 'job': current, 'job_sha256': job_sha, 'vm_uuid': vm['node']['uuid'],
                'request_sha256': auth.digest(raw), 'candidate_sha256': summary['candidate_sha256'],
                'selection_binding_sha256': summary['selection_binding_sha256'],
                'grant_sha256': auth.digest(grant), 'policy_sha256': auth.digest(policy),
                'context_sha256': auth.digest(auth.canonical(context)), 'consumption': ledger,
                'admitted_at': admitted, 'guest_inspection': inspection, 'guest_admission': admission,
                'outcome': outcome, 'quarantine': quarantine, 'input_media_sha256': media_sha,
                'stop_seconds': vm['stop_seconds'], 'writers_stopped': vm['stopped'], 'owner_result': owner}
        finally:
            if gate.active_vm is not None: gate.stop(gate.active_vm)
