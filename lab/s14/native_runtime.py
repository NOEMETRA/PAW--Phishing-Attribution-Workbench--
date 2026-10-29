"""Separate finite native Root authority/runtime for owned no-NIC acceptance.

Only immutable-generated harmless sources enter unattended recipes. No ordinary
caller may supply source bytes, host paths, interpreters, grants or readiness.
Native client frames remain separate from accepted Python/HTML contracts.
"""
import contextlib
import json
import os
from pathlib import Path
import re
import uuid
import time

from paw.core import native_bridge as contract
import hash_authorization as python_backend
import vm_release_storage as storage

fs = python_backend.fs
canonical, digest, require = contract.canonical, contract.digest, contract.require
ROOT = Path('/var/lib/paw-s14/native-authorization-v1')
HERE = Path(__file__).resolve().parent
SCOPE = 'explicit-native-selection-no-nic-v1'
PROFILES = frozenset(spec.engine for spec in contract.PROFILES.values())


def decode(raw, maximum=256*1024): return contract._decode(raw, maximum)


def guest_controller_hash(): return digest((HERE/'native_guest.py').read_bytes())


def validate_context(value):
    require(type(value) is dict and set(value) == {'profile', 'backend', 'contract_sha256',
            'runtime_sources_sha256', 'maintenance_sha256', 'guest_controller_sha256'}, 'native_context_shape')
    require(type(value['profile']) is str and value['profile'] in PROFILES, 'native_authority_profile')
    python_backend.validate_context(value['backend'])
    require(value['contract_sha256'] == contract.contract_hash() and
            value['guest_controller_sha256'] == guest_controller_hash() and
            all(contract.shared._hex(value[key]) for key in ['runtime_sources_sha256', 'maintenance_sha256']),
            'native_context_code_or_maintenance')
    return value


def capture(profile):
    require(type(profile) is str and profile in PROFILES, 'native_authority_profile')
    context = python_backend.capture(); python_backend.validate_context(context)
    platform = context
    with python_backend.store() as fd:
        names = os.listdir(fd); require(len(names) <= 4096, 'native_maintenance_inventory')
        records = []
        for name in sorted(names):
            if not re.fullmatch('maintenance-[0-9a-f]{64}\\.json', name): continue
            raw = fs.read(fd, name, 65536)
            require(name == 'maintenance-'+digest(raw)+'.json', 'native_maintenance_digest')
            try: python_backend.validate_maintenance(raw, platform)
            except ValueError: continue
            records.append(digest(raw))
    require(records, 'native_current_protected_maintenance_required')
    release = HERE.parents[1]
    with fs.root_directory(Path('/var/lib/paw-vm')) as fd: active = decode(fs.read(fd, 'active.json'))
    require(type(active) is dict and type(active.get('release_sha')) is str and
            re.fullmatch('[0-9a-f]{40}', active['release_sha']) and
            release == Path('/opt/paw-vm/releases')/active['release_sha'], 'native_immutable_active_release')
    with fs.root_directory(release.parent) as fd:
        manifest, _ = storage.verify(fd, active['release_sha'], active['manifest_sha256'])
    value = {'profile': profile, 'backend': context, 'contract_sha256': contract.contract_hash(),
             'runtime_sources_sha256': digest(storage.canonical(manifest['files'])), 'maintenance_sha256': min(records),
             'guest_controller_sha256': guest_controller_hash()}
    return validate_context(value)


def inspect(raw, now=None):
    request = contract.validate_request(raw, now); frame = request['candidate']
    return {'request_id': frame['request_id'], 'profile': frame['profile'], 'request_sha256': digest(raw),
            'candidate_sha256': digest(canonical(frame)), 'selection_binding_sha256': frame['selection_binding_sha256'],
            'source_sha256': frame['source']['sha256'], 'original_source_sha256': request['binding']['original_source']['sha256'],
            'graph_sha256': request['binding']['graph_sha256'], 'selected_node': request['binding']['derivation']['selected']}


def validate_readiness(raw, context, now=None):
    validate_context(context); value = decode(raw); now = time.time() if now is None else now
    require(raw == canonical(value) and type(value) is dict and set(value) == {'schema', 'scope', 'decision',
            'context_sha256', 'matrix_sha256', 'reviewed_head', 'review_url', 'ci_runs', 'ci_successful_jobs',
            'created_at', 'expires_at'}, 'native_readiness_shape')
    require(value['schema'] == 'paw-s14-native-i08-v1' and value['scope'] == SCOPE and
            value['decision'] == 'ready-for-explicit-single-native-no-nic' and
            value['context_sha256'] == digest(canonical(context)) and contract.shared._hex(value['matrix_sha256']),
            'native_readiness_binding')
    require(type(value['reviewed_head']) is str and re.fullmatch('[0-9a-f]{40}', value['reviewed_head']) and
            type(value['review_url']) is str and re.fullmatch(r'https://github\.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/[1-9][0-9]*#issuecomment-[1-9][0-9]*', value['review_url']),
            'native_readiness_review')
    require(type(value['ci_runs']) is list and len(value['ci_runs']) == 2 and
            all(type(v) is int and v > 0 for v in value['ci_runs']) and len(set(value['ci_runs'])) == 2 and
            type(value['ci_successful_jobs']) is int and value['ci_successful_jobs'] == 7, 'native_readiness_ci')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at']+86400, 'native_readiness_clock')
    return value


def validate_policy(raw, context, ready=None, now=None):
    validate_context(context); value = decode(raw); now = time.time() if now is None else now
    require(raw == canonical(value) and type(value) is dict and set(value) == {'schema', 'scope', 'context',
            'context_sha256', 'mode', 'approved_requests', 'readiness_sha256', 'owned_manifest_sha256', 'created_at', 'expires_at'},
            'native_policy_shape')
    require(value['schema'] == 'paw-s14-native-policy-v1' and value['scope'] == SCOPE and
            canonical(value['context']) == canonical(context) and value['context_sha256'] == digest(canonical(context)),
            'native_policy_context')
    approvals = value['approved_requests']
    require(type(approvals) is list and 1 <= len(approvals) <= 32, 'native_approval_budget')
    hashes = []
    for item in approvals:
        require(type(item) is dict and set(item) == {'request_sha256', 'source_sha256'} and
                all(contract.shared._hex(v) for v in item.values()), 'native_exact_request_approval')
        hashes.append(item['request_sha256'])
    require(len(set(hashes)) == len(hashes), 'native_duplicate_approval')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at']+86400, 'native_policy_clock')
    if value['mode'] == 'owned-validation':
        require(value['readiness_sha256'] is None and contract.shared._hex(value['owned_manifest_sha256']),
                'native_owned_validation_scope')
    elif value['mode'] == 'explicit-source-analysis':
        require(len(approvals) == 1 and value['owned_manifest_sha256'] is None and ready is not None,
                'native_single_request_readiness_required')
        receipt = validate_readiness(ready, context, now)
        require(value['readiness_sha256'] == digest(ready) and value['expires_at'] <= receipt['expires_at'],
                'native_policy_readiness')
    else: raise ValueError('native_policy_mode')
    return value


def make_policy(context, requests, *, mode='owned-validation', owned_manifest_sha256=None, ready=None):
    require(type(requests) is list and 1 <= len(requests) <= 32, 'native_request_list_budget')
    now = int(time.time()); expiry = now+86400
    if ready is not None: expiry = min(expiry, decode(ready)['expires_at'])
    approvals = []
    for raw in requests:
        summary = inspect(raw)
        require(summary['profile'] == context['profile'], 'native_policy_profile')
        approvals.append({key: summary[key] for key in ['request_sha256', 'source_sha256']})
    raw = canonical({'schema': 'paw-s14-native-policy-v1', 'scope': SCOPE, 'context': context,
        'context_sha256': digest(canonical(context)), 'mode': mode, 'approved_requests': approvals,
        'readiness_sha256': digest(ready) if ready is not None else None,
        'owned_manifest_sha256': owned_manifest_sha256, 'created_at': now, 'expires_at': expiry})
    validate_policy(raw, context, ready); return raw


@contextlib.contextmanager
def store():
    with fs.root_directory(ROOT) as fd: yield fd


def initialize():
    require(os.geteuid() == 0, 'root_native_authority_required')
    with fs.root_directory(ROOT.parent):
        try: ROOT.mkdir(mode=0o700)
        except FileExistsError: pass
    with store() as fd: require(os.fstat(fd).st_mode & 0o777 == 0o700, 'native_private_authority')


def install_readiness(raw, context):
    require(os.geteuid() == 0, 'root_native_authority_required')
    validate_readiness(raw, context)
    require(canonical(capture(context['profile'])) == canonical(context), 'native_actual_context_changed')
    with store() as fd: fs.exclusive(fd, 'readiness-'+digest(raw)+'.json', raw)


def installed(raw, context, now=None):
    value = decode(raw)
    with store() as fd:
        require(fs.read(fd, 'policy-'+digest(raw)+'.json', 256*1024) == raw, 'native_policy_not_installed')
        ready = fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] is not None else None
    return validate_policy(raw, context, ready, now), ready


def install_policy(raw, context):
    require(os.geteuid() == 0, 'root_native_authority_required'); value = decode(raw)
    with store() as fd:
        ready = fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] is not None else None
        validate_policy(raw, context, ready)
        require(canonical(capture(context['profile'])) == canonical(context), 'native_actual_context_changed')
        fs.exclusive(fd, 'policy-'+digest(raw)+'.json', raw)


def validate_binding(raw, grant, policy_raw, context, ready=None, now=None):
    summary = inspect(raw, now); request = contract.validate_request(raw, now); frame = request['candidate']
    policy = validate_policy(policy_raw, context, ready, now); now = time.time() if now is None else now
    require(summary['profile'] == context['profile'] and type(grant) is dict and set(grant) == set(summary) | {
            'schema', 'scope', 'policy_sha256', 'context_sha256', 'execution_purpose', 'created_at', 'expires_at'},
            'native_grant_shape')
    require(grant['schema'] == 'paw-s14-native-grant-v1' and grant['scope'] == SCOPE and
            all(grant[key] == value for key, value in summary.items()) and
            grant['policy_sha256'] == digest(policy_raw) and grant['context_sha256'] == digest(canonical(context)) and
            grant['execution_purpose'] == policy['mode'], 'native_grant_binding')
    require({'request_sha256': summary['request_sha256'], 'source_sha256': summary['source_sha256']} in policy['approved_requests'],
            'native_request_not_explicitly_approved')
    require(type(grant['created_at']) is int and type(grant['expires_at']) is int and
            frame['created_at'] <= grant['created_at'] <= now < grant['expires_at'] <=
            min(frame['expires_at'], policy['expires_at'], grant['created_at']+900), 'native_grant_clock')
    return summary, request, bytes.fromhex(frame['source']['data_hex'])


def issue(raw, policy_raw, context):
    require(os.geteuid() == 0, 'root_native_authority_required')
    policy, ready = installed(policy_raw, context); summary = inspect(raw); frame = contract.validate_request(raw)['candidate']
    require(canonical(capture(context['profile'])) == canonical(context), 'native_actual_context_changed')
    now = int(time.time()); grant = {'schema': 'paw-s14-native-grant-v1', 'scope': SCOPE, **summary,
        'policy_sha256': digest(policy_raw), 'context_sha256': digest(canonical(context)),
        'execution_purpose': policy['mode'], 'created_at': now,
        'expires_at': min(now+900, frame['expires_at'], policy['expires_at'])}
    validate_binding(raw, grant, policy_raw, context, ready)
    with store() as fd:
        with fs.subdirectory(fd, 'grants') as target: fs.exclusive(target, summary['request_id']+'.json', canonical(grant))
    return grant


def load_bound(raw, policy_raw, context, now=None):
    summary = inspect(raw, now); policy, ready = installed(policy_raw, context, now)
    with store() as fd:
        with fs.subdirectory(fd, 'grants') as target: grant = fs.read(target, summary['request_id']+'.json', 8192)
    summary, request, source = validate_binding(raw, decode(grant, 8192), policy_raw, context, ready, now)
    return grant, summary, request, source


def consume(raw, policy_raw, context):
    require(os.geteuid() == 0, 'root_native_authority_required')
    require(canonical(capture(context['profile'])) == canonical(context), 'native_actual_context_changed')
    grant, summary, request, source = load_bound(raw, policy_raw, context)
    ledger = {'schema': 'paw-s14-native-consumed-v1', 'request_id': summary['request_id'],
              'request_sha256': digest(raw), 'grant_sha256': digest(grant),
              'policy_sha256': digest(policy_raw), 'context_sha256': digest(canonical(context)), 'consumed_at': int(time.time())}
    with store() as fd:
        with fs.subdirectory(fd, 'consumed') as target: fs.exclusive(target, summary['request_id']+'.json', canonical(ledger))
    return ledger, grant, summary, request, source


def confirm_consumed(ledger):
    with store() as fd:
        with fs.subdirectory(fd, 'consumed') as target:
            require(fs.read(target, ledger['request_id']+'.json', 8192) == canonical(ledger), 'native_consumption_changed')


# Native execution shares the accepted hypervisor lifecycle, with its own ABI.
import base64
import shutil
from hash_offline_adapter import HashGate
from synthetic_gate import Gate
from benign_guest_validation import BASE
from browser_offline_adapter import available_memory
from offline_input_matrix import _run_admitted_job
from gw_quarantine import validate_records

SHELL = contract.PROFILES['shell'].engine
ELF = contract.PROFILES['elf'].engine
GUEST_LIMITS = {'memory.max': str(64*1024**2), 'memory.swap.max': '0', 'memory.oom.group': '1',
                'pids.max': '16', 'cpu.max': '20000 100000'}
CHILD_LIMITS = {'Max cpu time': 2, 'Max file size': 4096, 'Max core file size': 0,
                'Max open files': 32, 'Max address space': 192*1024**2}


def native_job(request):
    frame = request['candidate']
    contract.validate_request(canonical(request), now=frame['created_at'])
    key = 'shell' if frame['profile'] == SHELL else 'elf'
    return {'profile': frame['profile'], 'job_id': 'native-'+key+'-'+frame['request_id'],
            'parent_sha256': frame['selection_binding_sha256'], 'source_sha256': frame['source']['sha256'],
            'source_bytes': frame['source']['bytes'], 'operator_authorization': 'root-native-grant-v1',
            'created_at': frame['created_at'], 'expires_at': frame['expires_at']}


def native_seed(current):
    job = current['job']; source = current['source']
    key = 'shell' if job['profile'] == SHELL else 'elf'
    metadata = contract.linux_profiles.inspect_source(key, source)
    require(metadata['profile'] == job['profile'] and metadata['source_sha256'] == job['source_sha256'] and
            type(job['source_bytes']) is int and len(source) == job['source_bytes'], 'native_seed_job_source')
    return {'schema': 'paw-native-seed-v1', 'profile': job['profile'], 'source_sha256': job['source_sha256'],
            'source_bytes': len(source), 'job_sha256': current['job_sha256'],
            'request_id': job['job_id'].removeprefix('native-'+key+'-'),
            'elf_interpreter': None if key == 'shell' else metadata['details']['interpreter']}


def validate_inspection(value, seed):
    keys = set(seed) | {'kernel_release', 'network_interfaces', 'prior_marker_absent',
                       'guest_controller_sha256', 'interpreter', 'interpreter_sha256'}
    require(type(value) is dict and set(value) == keys and all(value[k] == v for k,v in seed.items()) and
            canonical({k:value[k] for k in seed}) == canonical(seed) and
            value['kernel_release'] == '6.8.0-147-generic' and value['network_interfaces'] == ['lo'] and
            value['prior_marker_absent'] is True and value['guest_controller_sha256'] == guest_controller_hash(),
            'native_guest_inspection_identity')
    interpreter = '/bin/dash' if seed['profile'] == SHELL else seed['elf_interpreter']
    require(value['interpreter'] == interpreter and (value['interpreter_sha256'] is None if interpreter is None
            else contract.shared._hex(value['interpreter_sha256'])), 'native_guest_fixed_interpreter')
    return value


def validate_boundary(value):
    keys = {'uid', 'gid', 'groups', 'no_new_privileges', 'capabilities', 'pid', 'pid_identity', 'stdin',
            'cgroup', 'limits', 'rlimits', 'session_id', 'controlling_tty', 'working_directory', 'observed_before_exec'}
    require(type(value) is dict and set(value) == keys and value['uid'] == value['gid'] == 65534 and
            value['groups'] == [] and value['no_new_privileges'] is True and
            value['capabilities'] == 'all zero including bounding' and type(value['pid']) is int and value['pid'] > 1 and
            type(value['pid_identity']) is str and re.fullmatch('[0-9]{1,20}', value['pid_identity']) and
            value['stdin'] == '/dev/null' and value['cgroup'] == '/paw-synthetic-job' and
            canonical(value['limits']) == canonical(GUEST_LIMITS) and canonical(value['rlimits']) == canonical(CHILD_LIMITS) and
            type(value['session_id']) is int and value['session_id'] == value['pid'] and value['controlling_tty'] is None and
            value['working_directory'] == '/tmp/paw-gate-fixture' and value['observed_before_exec'] is True, 'native_guest_boundary')
    return value


def validate_native_admission(value, inspection):
    require(type(value) is dict and set(value) == {'started', 'pid', 'source_sha256', 'job_sha256', 'profile',
            'prior_marker_absent', 'boundary', 'inspection'} and value['started'] is True and
            value['prior_marker_absent'] is True and value['inspection'] == inspection and
            canonical(value['inspection']) == canonical(inspection) and
            all(value[k] == inspection[k] for k in ['source_sha256', 'job_sha256', 'profile']), 'native_guest_admission')
    boundary = validate_boundary(value['boundary'])
    require(type(value['pid']) is int and value['pid'] == boundary['pid'], 'native_guest_child_identity')
    return value


def counters(raw):
    require(type(raw) is str and len(raw) <= 4096, 'native_guest_counter_budget')
    rows = {}
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) == 2 and re.fullmatch('[a-z_]{1,64}', fields[0]) and
                re.fullmatch('[0-9]{1,20}', fields[1]) and fields[0] not in rows, 'native_guest_counter_shape')
        rows[fields[0]] = int(fields[1])
    return rows


def validate_native_outcome(value, admission):
    require(type(value) is dict and set(value) == {'done', 'status', 'returncode', 'records', 'events',
            'boundary', 'writers_stopped', 'file_observation'} and value['done'] is True and
            value['writers_stopped'] is True and type(value['status']) is str and value['status'] in contract.STATUSES and
            type(value['returncode']) is int and -128 <= value['returncode'] <= 255 and
            canonical(validate_boundary(value['boundary'])) == canonical(admission['boundary']), 'native_guest_outcome')
    records = validate_records(value['records'])
    require([row['name'] for row in value['records']] == ['stdout.bin', 'stderr.bin'], 'native_guest_fixed_output_streams')
    events = value['events']
    require(type(events) is dict and set(events) == {'memory.events', 'memory.peak', 'pids.events', 'pids.peak', 'pids.current'} and
            events['pids.current'] == '0' and all(type(events[k]) is str and re.fullmatch('[0-9]{1,20}', events[k])
            for k in ['memory.peak', 'pids.peak']) and 1 <= int(events['pids.peak']) <= 16, 'native_guest_kernel_events')
    memory, pids = counters(events['memory.events']), counters(events['pids.events'])
    require({'oom', 'oom_kill'} <= memory.keys() and 'max' in pids and
            (value['status'] == 'memory_budget') == (memory['oom_kill'] > 0) and
            (value['status'] != 'completed' or value['returncode'] == 0), 'native_guest_outcome_kernel_binding')
    observation = value['file_observation']
    require(observation is None or type(observation) is dict and set(observation) == {'regular', 'bytes'} and
            type(observation['regular']) is bool and type(observation['bytes']) is int and observation['bytes'] >= 0 and
            (not observation['regular'] or observation['bytes'] <= 4096), 'native_guest_file_budget')
    return value


class NativeChannel:
    """Validate the trusted-controller ABI before common lifecycle publication."""
    def __init__(self, channel, seed):
        self.channel = channel; self.admission = None; self.closed = False
        self.inspection = validate_inspection(channel.call('inspect', seconds=8), seed)

    def call(self, operation, **kwargs):
        require(not self.closed, 'native_channel_closed')
        require(operation in {'start', 'poll', 'cancel'}, 'native_fixed_channel_operation')
        if operation == 'start': require(self.admission is None, 'native_channel_single_use')
        else: require(self.admission is not None, 'native_channel_not_admitted')
        value = self.channel.call(operation, **kwargs)
        if operation == 'start': self.admission = validate_native_admission(value, self.inspection)
        elif not (type(value) is dict and set(value) == {'done'} and value['done'] is False):
            validate_native_outcome(value, self.admission)
        return value

    def close(self):
        if not self.closed:
            self.channel.close(); self.closed = True


class NativeGate(HashGate):
    def seed(self, folder, role, job_id, token):
        Gate.seed(self, folder, role, job_id, token)
        cloud = json.loads((folder/'user-data').read_text().split('\n', 1)[1]); services = 0
        for item in cloud['write_files']:
            if item['path'].endswith('/paw-gate.service'):
                service = base64.b64decode(item['content'])
                require(service.count(b'/gate_guest.py') == 1, 'native_guest_service_template')
                service = service.replace(b'/gate_guest.py', b'/native_guest.py').replace(b'python3 -I -u', b'python3 -I -B -u')
                item['content'] = base64.b64encode(service).decode('ascii'); services += 1
        require(services == 1, 'native_single_guest_controller')
        config = native_seed(self.current)
        files = [('/usr/local/lib/paw-s14/native_guest.py', (HERE/'native_guest.py').read_bytes(), '0444'),
                 ('/opt/paw-input/sample.bin', self.current['source'], '0444' if config['profile'] == SHELL else '0555'),
                 ('/etc/paw-native.json', canonical(config), '0444')]
        cloud['write_files'] += [{'path': name, 'encoding': 'b64', 'content': base64.b64encode(raw).decode('ascii'),
                                  'permissions': mode} for name,raw,mode in files]
        (folder/'user-data').write_text('#cloud-config\n'+json.dumps(cloud))
        self.run(['/usr/bin/genisoimage', '-quiet', '-output', str(folder/'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                  str(folder/'user-data'), str(folder/'meta-data'), str(folder/'network-config')])

    def start(self, label, boot=True):
        vm = super().start(label, boot=boot)
        if boot: vm['channel'] = NativeChannel(vm['channel'], native_seed(self.current))
        return vm


def copy_authority(gate, raw, grant, ledger):
    with fs.root_directory(gate.output) as output, fs.subdirectory(output, 'authority-copy') as parent, \
         fs.subdirectory(parent, ledger['request_id']) as fd:
        for name,data in [('request.json',raw), ('grant.json',grant), ('consumed.json',canonical(ledger))]: fs.exclusive(fd,name,data)


def refresh(raw, policy, context, grant, summary, source, ledger, *, now=None):
    actual = capture(context['profile']); require(canonical(actual) == canonical(context), 'native_context_changed')
    current, checked, request, data = load_bound(raw, policy, actual, now=now)
    require(current == grant and checked == summary and data == source, 'native_authority_changed')
    confirm_consumed(ledger); return request


def run_native(gate, raw, policy, *, cancel=False):
    require(os.geteuid() == 0 and isinstance(gate, NativeGate), 'root_native_adapter_required')
    require(gate.active_vm is None and not gate.connection.listAllDomains(0), 'native_gate_or_host_busy')
    require(shutil.disk_usage(BASE.parent).free >= 10*1024**3 and available_memory() >= 2*1024**3, 'native_resource_admission')
    with fs.execution_lock():
        context = capture(inspect(raw)['profile']); ledger, grant, summary, request, source = consume(raw, policy, context)
        current_job = native_job(request); gate.hash_context = context['backend']
        current = {'job': current_job, 'job_sha256': digest(canonical(current_job)), 'source': source}
        copy_authority(gate, raw, grant, ledger); admitted = {}; owner = {}
        def revalidate():
            refresh(raw, policy, context, grant, summary, source, ledger); admitted['at'] = int(time.time())
        def before_publish():
            require(len(gate.report['vms']) == 1 and gate.report['vms'][0]['label'] == current_job['job_id'], 'native_single_stopped_vm')
            vm = gate.report['vms'][0]
            with fs.root_directory(gate.output) as fd:
                outcome = decode(fs.read(fd, current_job['job_id']+'-owner-result.json', 65536), 65536)
                ready = decode(fs.read(fd, current_job['job_id']+'-ready.json', 65536), 65536)
            require(outcome.get('reason') == 'requested_stop' and outcome.get('connection_closed') is True and
                    ready.get('uuid') == vm['uuid'], 'native_owner_identity_or_exit')
            owner.update(outcome); refresh(raw, policy, context, grant, summary, source, ledger, now=admitted['at'])
        result = _run_admitted_job(gate, current, revalidate, cancel, before_publish)
        result.update(request_id=summary['request_id'], request_sha256=digest(raw), candidate_sha256=summary['candidate_sha256'],
            selection_binding_sha256=summary['selection_binding_sha256'], grant_sha256=digest(grant), policy_sha256=digest(policy),
            context_sha256=digest(canonical(context)), consumption=ledger, admitted_at=admitted['at'], owner_result=owner)
        return result


# Serialized verifier: hardware observations are checked independently of the
# launcher; copied audits alone do not establish Root provenance.
import math
import stat
import traceback
import argparse
from verify_representation import read, inventory, verify_snapshot
from verify_hash_offline import vm_evidence
from verify_synthetic_gate import REQUIRED_SOURCES
from hostile_maintenance import SIGNER
import representation_producer as common
from reader_export import publish_reader_tree

CONTROL = Path('/var/lib/paw-s14/control')
STATE = Path('/var/lib/paw-vm')
READER_GID = 1000
FAULTS = {'paused-refusal': 'owned_native_paused_refusal', 'owner-loss': 'owned_native_owner_loss',
          'protocol-loss': 'owned_native_protocol_closed'}


def root_only():
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'root_PID1_native_producer_required')


def audit_path(identifier):
    require(type(identifier) is str and re.fullmatch('[0-9a-f]{32}', identifier), 'native_audit_identifier')
    return CONTROL/('native-job-'+identifier)


def verify_platform(root, report, vm, context):
    backend = context['backend']; validate_context(context)
    require(report['source_hashes'] == verify_snapshot(root, context) == backend['host']['source_hashes'],
            'native_complete_source_context')
    required = REQUIRED_SOURCES | {'hash_authorization.py', 'hash_offline_adapter.py', 'native_runtime.py', 'native_guest.py'}
    require(required <= report['source_hashes'].keys() and inventory(root/'sources') == set(report['source_hashes']),
            'native_source_copy_inventory')
    for name, expected in report['source_hashes'].items():
        require(digest(read(root, 'sources/'+name, storage.MAX_FILE)) == expected, 'native_source_copy_changed')
    maintenance = read(root, 'maintenance.json', 65536)
    require(digest(maintenance) == context['maintenance_sha256'], 'native_maintenance_copy')
    python_backend.validate_maintenance(maintenance, backend)
    vm_evidence(root, vm, backend)
    ready = decode(read(root, vm['label']+'-ready.json', 65536), 65536)
    require(ready['uuid'] == vm['uuid'] and ready['pid'] == vm['actual']['pid'] and
            ready['pid_identity'] == vm['actual']['pid_identity'], 'native_actual_owner_vm_identity')
    proof = decode(read(root, 'image-provenance.json', 65536), 65536)
    require(proof['result'] == 'PASS' and proof['signed_manifest'] is True and proof['image'] == BASE.name and
            proof['sha256'] == backend['host']['image_sha256'] == fs.IMAGE_SHA256 and
            type(proof['bytes']) is int and 0 < proof['bytes'] <= 8*1024**3 and
            type(proof['signature_status']) is str and len(proof['signature_status']) <= 8192 and
            any(line.startswith('[GNUPG:] VALIDSIG '+SIGNER+' ') for line in proof['signature_status'].splitlines()),
            'native_signed_base_provenance')


def audit_authority(root, when, *, production=False):
    policy_raw = read(root, 'policy.json', 256*1024); policy = decode(policy_raw); context = policy['context']
    copies = inventory(root/'authority-copy')
    ids = {name.split('/')[0] for name in copies}
    require(len(ids) == 1, 'native_one_authority_copy')
    rid = next(iter(ids)); require(re.fullmatch('[0-9a-f]{32}', rid), 'native_authority_copy_identifier')
    require(copies == {rid+'/', *(rid+'/'+name for name in ['request.json','grant.json','consumed.json'])},
            'native_authority_copy_inventory')
    prefix = 'authority-copy/'+rid+'/'
    raw = read(root, prefix+'request.json', contract.REQUEST_LIMIT)
    grant_raw = read(root, prefix+'grant.json', 8192); grant = decode(grant_raw, 8192)
    ledger_raw = read(root, prefix+'consumed.json', 8192); ledger = decode(ledger_raw, 8192)
    require(grant_raw == canonical(grant) and ledger_raw == canonical(ledger) and
            type(ledger.get('consumed_at')) is int, 'native_canonical_consumption')
    when = ledger['consumed_at'] if when is None else when
    require(type(when) is int, 'native_admission_clock')
    ready = read(root, 'readiness.json', 65536) if policy['mode'] == 'explicit-source-analysis' else None
    if production: require(ready is not None and policy['mode'] == 'explicit-source-analysis', 'native_analysis_readiness')
    summary, request, source = validate_binding(raw, grant, policy_raw, context, ready, now=when)
    expected = {'schema':'paw-s14-native-consumed-v1','request_id':rid,'request_sha256':digest(raw),
        'grant_sha256':digest(grant_raw),'policy_sha256':digest(policy_raw),'context_sha256':digest(canonical(context)),
        'consumed_at':ledger['consumed_at']}
    require(ledger == expected and summary['request_id'] == rid and
            request['candidate']['created_at'] <= ledger['consumed_at'] <= when < grant['expires_at'], 'native_consumption_binding')
    job = native_job(request); label = job['job_id']
    require(inventory(root/'admissions') == {label+'.json'} and
            decode(read(root,'admissions/'+label+'.json',65536),65536) == job, 'native_single_admission_job')
    names = {label+suffix for suffix in ['-control.json','-ready.json','-owner.json','-owner-result.json',
        '-owner.log','-domain.xml','-serial.log','-quarantine']}
    names |= {'authorized-'+label+'-extractor.xml','results.json','policy.json','maintenance.json',
        'host-owned-canary.bin','independent-verification.json','authority-copy','admissions','sources','runtime-snapshot',
        'image-provenance.json'}
    if ready is not None: names.add('readiness.json')
    require(set(os.listdir(root)) <= names, 'native_complete_job_inventory')
    return policy_raw, context, raw, grant_raw, ledger, summary, request, source, job, when


def verify_native(root, *, production=False):
    root = Path(root); report = decode(read(root,'results.json',2*1024**2),2*1024**2)
    require(report.get('result') == 'PASS' and not report.get('cleanup_error') and
            all(report.get(key) is True for key in ['host_restored','base_unchanged','host_canary_unchanged',
                'writers_stopped','source_freeze_unchanged']) and report['host_before'] == report['host_after'] and
            type(report['real_connections']) is int and report['real_connections'] == 0 and
            report['scope'] == SCOPE and len(report['runs']) == len(report['vms']) == 1, 'native_host_lifecycle')
    run,vm = report['runs'][0],report['vms'][0]
    policy_raw,context,raw,grant,ledger,summary,request,source,job,when = audit_authority(root,run['admitted_at'],production=production)
    label = job['job_id']; job_sha = digest(canonical(job))
    require(run['job'] == job and run['job_sha256'] == job_sha and run['request_id'] == summary['request_id'] and
            run['request_sha256'] == digest(raw) and run['candidate_sha256'] == summary['candidate_sha256'] and
            run['selection_binding_sha256'] == summary['selection_binding_sha256'] and run['consumption'] == ledger and
            run['grant_sha256'] == digest(grant) and run['policy_sha256'] == digest(policy_raw) and
            run['context_sha256'] == digest(canonical(context)) and vm['label'] == label and run['vm_uuid'] == vm['uuid'],
            'native_actual_run_binding')
    seconds = vm['stop_seconds']
    require(vm['stopped'] is True and run['writers_stopped'] is True and run['stop_seconds'] == seconds and
            type(seconds) in {int,float} and math.isfinite(seconds) and 0 <= seconds < 12, 'native_external_stop')
    verify_platform(root,report,vm,context)
    owner = decode(read(root,label+'-owner-result.json',65536),65536)
    require(owner == run['owner_result'] and owner.get('reason') == 'requested_stop' and owner.get('connection_closed') is True,
            'native_owner_requested_stop')
    seed = native_seed({'job':job,'source':source,'job_sha256':job_sha}); admission = run['guest_admission']
    inspection = validate_inspection(admission['inspection'],seed);validate_native_admission(admission,inspection)
    outcome = run['outcome']
    if outcome.get('status') == 'cancelled' and outcome.get('done') is False:
        require(canonical(outcome) == canonical({'status':'cancelled','records':[],'done':False}), 'native_host_cancel_shape')
    else: validate_native_outcome(outcome,admission)
    records = outcome['records'];validate_records(records); quarantine=root/(label+'-quarantine');manifest=run['quarantine']
    require(type(manifest) is list and len(manifest) == len(records) and inventory(quarantine) == {v['stored_as'] for v in manifest},
            'native_opaque_quarantine_inventory')
    for index,item in enumerate(manifest):
        require(item['stored_as'] == f'artifact-{index:02d}.bin' and item['source_name'] == records[index]['name'], 'native_opaque_ordinal')
        blob=read(quarantine,item['stored_as'],1024)
        require(blob == bytes.fromhex(records[index]['bytes_hex']) and len(blob) == item['bytes'] and digest(blob) == item['sha256'],
                'native_opaque_digest')
    return {'result':'PASS','jobs':1,'profile':context['profile'],'mode':decode(policy_raw)['mode'],
            'sources':len(report['source_hashes']),'request_sha256':digest(raw),
            'meaning':'opaque native execution/custody only, not classification or origin authentication'}


def execute_native(raw, policy_raw, *, cancel=False, _fault=None, _witness=None, _probe=False):
    root_only(); summary = inspect(raw); context = capture(summary['profile'])
    _,checked,request,source = load_bound(raw,policy_raw,context); require(checked == summary,'native_producer_request_changed')
    policy,ready = installed(policy_raw,context)
    require(_fault is None or policy['mode'] == 'owned-validation' and _fault in FAULTS and type(_witness) is dict,
            'native_owned_fault_policy')
    require(type(_probe) is bool and not (_probe and _fault is not None) and
            (not _probe or policy['mode'] == 'owned-validation' and type(_witness) is dict), 'native_owned_probe_policy')
    gate_class = NativeGate if _fault is None and not _probe else owned_native_gate(_fault,_witness,_probe)
    output = audit_path(summary['request_id']); gate = gate_class(argparse.Namespace(output=output));gate.active_vm=None
    gate.report.update(runs=[],vms=[],real_connections=0,scope=SCOPE);before=None;canary=os.urandom(32)
    try:
        gate.canary=output/'host-owned-canary.bin'
        with fs.root_directory(output) as fd:
            fs.exclusive(fd,gate.canary.name,canary);fs.exclusive(fd,'policy.json',policy_raw)
            with python_backend.store() as protected:maintenance=fs.read(protected,'maintenance-'+context['maintenance_sha256']+'.json',65536)
            require(digest(maintenance) == context['maintenance_sha256'],'native_producer_maintenance')
            fs.exclusive(fd,'maintenance.json',maintenance)
            name,proof = common.image_proof(common.adapter.PYTHON,context);fs.exclusive(fd,name,proof)
            if ready is not None:fs.exclusive(fd,'readiness.json',ready)
        common.copy_runtime(output,context);before=gate.snapshot_host()
        run=run_native(gate,raw,policy_raw,cancel=cancel);gate.report.update(result='PASS',runs=[run])
    except Exception as error:gate.report.update(result='FAIL',error=str(error),traceback=traceback.format_exc(),diagnostic=common.failure_diagnostic(error))
    finally:
        try:
            if gate.active_vm is not None:gate.stop(gate.active_vm)
            after=gate.snapshot_host()
            require(before is not None and before == after and not gate.connection.listAllDomains(0),'native_producer_host_restore')
            require(python_backend.file_digest(BASE) == fs.IMAGE_SHA256 and gate.canary.read_bytes() == canary and
                    canonical(capture(context['profile'])) == canonical(context),'native_producer_context_changed')
            gate.report.update(host_before=before,host_after=after,host_restored=True,base_unchanged=True,
                host_canary_unchanged=True,source_freeze_unchanged=True,writers_stopped=True)
        except Exception as error:gate.report.update(result='FAIL',cleanup_error=str(error),cleanup_diagnostic=common.failure_diagnostic(error))
        gate.connection.close();common.save_results(output,gate.report)
    if gate.report['result'] == 'PASS':
        try:
            verified=verify_native(output,production=policy['mode']=='explicit-source-analysis')
            with fs.root_directory(output) as fd:fs.exclusive(fd,'independent-verification.json',canonical(verified))
        except Exception as error:
            gate.report.update(result='FAIL',verification_error=str(error),verification_diagnostic=common.failure_diagnostic(error))
            common.save_results(output,gate.report)
    return gate.report,output


@contextlib.contextmanager
def native_export_parent():
    root=contract.EXPORT_ROOT
    with fs.root_directory(root.parent) as parent:
        created=False
        try:os.mkdir(root.name,mode=0o700,dir_fd=parent);created=True
        except FileExistsError:pass
        fd=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            fs.trusted(os.fstat(fd),True)
            if created:
                require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'native_export_new_mode')
                os.fchown(fd,fs.OWNER_UID,READER_GID);os.fchmod(fd,0o750);os.fsync(fd);os.fsync(parent)
            info=os.fstat(fd);require(info.st_gid==READER_GID and stat.S_IMODE(info.st_mode)==0o750,'native_export_root_mode')
            yield fd
        finally:os.close(fd)


def publish_native(raw):
    root_only();request=contract.validate_request(raw,decode(raw,contract.REQUEST_LIMIT)['candidate']['created_at'])
    rid=request['candidate']['request_id'];output=audit_path(rid);verified=verify_native(output,production=True)
    report_raw=read(output,'results.json',2*1024**2);report=decode(report_raw,2*1024**2);run=report['runs'][0]
    policy_raw=read(output,'policy.json',256*1024);context=decode(policy_raw)['context']
    require(canonical(capture(context['profile']))==canonical(context),'native_publish_current_context')
    policy,ready=installed(policy_raw,context)
    require(policy['mode']=='explicit-source-analysis' and ready is not None and verified['request_sha256']==digest(raw) and
            read(output,'authority-copy/'+rid+'/request.json',contract.REQUEST_LIMIT)==raw,'native_publish_analysis_request')
    grant,_,_,_=load_bound(raw,policy_raw,context,now=run['admitted_at'])
    require(grant==read(output,'authority-copy/'+rid+'/grant.json',8192),'native_publish_protected_grant');confirm_consumed(run['consumption'])
    name,proof=common.image_proof(common.adapter.PYTHON,context)
    require(read(output,name,65536)==proof,'native_publish_image_proof')
    manifest,_=common.snapshot_proof()
    require(digest(storage.canonical(manifest['files']))==context['runtime_sources_sha256'],'native_publish_full_inventory')
    receipt={'schema':'paw-s14-native-result-v1','producer_kind':'local-root-verified-native-no-nic-v1',
        'request_id':rid,'request_sha256':digest(raw),'candidate_sha256':digest(canonical(request['candidate'])),
        'selection_binding_sha256':request['candidate']['selection_binding_sha256'],'source_sha256':request['candidate']['source']['sha256'],
        'profile':context['profile'],'execution_status':run['outcome']['status'],'runtime':{
            'job_sha256':run['job_sha256'],'raw_result_sha256':digest(report_raw),'source_inventory_sha256':context['runtime_sources_sha256'],
            'policy_sha256':digest(policy_raw),'grant_sha256':digest(grant),'readiness_sha256':digest(ready),
            'consumption_sha256':digest(canonical(run['consumption'])),'bridge_contract_sha256':contract.contract_hash(),
            'image_certificate_sha256':digest(proof),'context_sha256':digest(canonical(context)),
            'vm_uuid':run['vm_uuid'],'image_sha256':context['backend']['host']['image_sha256'],'source_count':len(manifest['files']),
            'admitted_at':run['admitted_at'],'completed_at':int(time.time()),'stop_seconds':run['stop_seconds'],
            'writers_stopped':True,'network_interfaces':[]},'artifacts':[{k:v[k] for k in ['stored_as','bytes','sha256']} for v in run['quarantine']]}
    receipt_raw=canonical(receipt);contract.validate_receipt(receipt_raw,request,digest(raw));destination=contract.EXPORT_ROOT/rid
    with native_export_parent() as parent:os.mkdir(rid,mode=0o700,dir_fd=parent);os.fsync(parent)
    with fs.root_directory(destination) as fd:
        fs.exclusive(fd,'request.json',raw);fs.exclusive(fd,'receipt.json',receipt_raw)
        for item in receipt['artifacts']:
            blob=read(output,run['job']['job_id']+'-quarantine/'+item['stored_as'],1024)
            require(digest(blob)==item['sha256'] and len(blob)==item['bytes'],'native_publish_opaque_digest')
            fs.exclusive(fd,item['stored_as'],blob)
    publish_reader_tree(destination)
    return {'request_id':rid,'result':'PASS','export':str(destination),'receipt_sha256':digest(receipt_raw)}


def owned_native_gate(case,witness,probe=False):
    require((case is None and probe is True or case in FAULTS and probe is False) and type(witness) is dict,
            'native_fixed_owned_fault_or_probe')
    class OwnedNative(NativeGate):
        def start(self,label,boot=True):
            vm=super().start(label,boot=case!='paused-refusal')
            if probe:
                try:
                    with fs.execution_lock():raise ValueError('native_busy_lock_not_exclusive')
                except BlockingIOError:witness['live_busy_lock_refused']=True
                return vm
            witness.update(schema='paw-s14-native-fault-v1',case=case,vm_uuid=vm['node']['uuid'])
            if case=='paused-refusal':
                witness['paused_before_refusal']=self.connection.lookupByUUIDString(vm['node']['uuid']).state()[0]==self.libvirt.VIR_DOMAIN_PAUSED
                witness['_fault_at']=time.monotonic();raise ValueError(FAULTS[case])
            channel=vm['channel'];original=channel.call
            def observed(operation,**kwargs):
                if operation=='poll':
                    witness['_fault_at']=time.monotonic()
                    if case=='owner-loss':
                        from benign_guest_validation import process_identity
                        witness['owner_pid']=vm['owner'].pid;witness['owner_identity']=process_identity(vm['owner'].pid)
                        vm['owner'].kill();vm['owner'].wait(timeout=3);witness['owner_returncode']=vm['owner'].returncode
                    else:channel.close();witness['serial_closed']=True
                    raise ValueError(FAULTS[case])
                value=original(operation,**kwargs)
                if operation=='start':witness.update(guest_admission=value,admitted_at=int(time.time()))
                return value
            channel.call=observed;return vm

        def stop(self,vm,kill=False):
            seconds=super().stop(vm,kill=kill)
            if '_fault_at' in witness:witness['stop_after_fault_seconds']=time.monotonic()-witness['_fault_at']
            return seconds
    return OwnedNative


def verify_native_fault(root,raw,case,witness):
    root=Path(root);require(type(case) is str and case in FAULTS,'native_expected_fault')
    report=decode(read(root,'results.json',2*1024**2),2*1024**2)
    require(report.get('result')=='FAIL' and report.get('error')==FAULTS[case] and not report.get('cleanup_error') and
            all(report.get(key) is True for key in ['host_restored','base_unchanged','host_canary_unchanged',
                'writers_stopped','source_freeze_unchanged']) and report['host_before']==report['host_after'] and
            report['runs']==[] and len(report['vms'])==1 and report['real_connections']==0 and report['scope']==SCOPE,
            'native_expected_fault_lifecycle')
    policy,context,copied,grant_raw,ledger,summary,request,source,job,when=audit_authority(root,None)
    require(copied==raw and decode(policy)['mode']=='owned-validation','native_fault_request_scope')
    vm=report['vms'][0];label=job['job_id']
    require(vm.get('stopped') is True and type(vm.get('stop_seconds')) in {int,float} and
            math.isfinite(vm['stop_seconds']) and 0<=vm['stop_seconds']<12,'native_fault_external_stop')
    require(vm['label']==label and not (root/(label+'-quarantine')).exists() and
            witness.get('schema')=='paw-s14-native-fault-v1' and witness.get('case')==case and
            witness.get('vm_uuid')==vm['uuid'],'native_fault_no_publication')
    verify_platform(root,report,vm,context)
    seconds=witness.get('stop_after_fault_seconds')
    require(type(seconds) in {int,float} and math.isfinite(seconds) and 0<=seconds<12 and
            vm['stop_seconds']<=seconds,'native_fault_known_stop')
    if case=='paused-refusal':
        require(witness.get('paused_before_refusal') is True and 'guest_admission' not in witness and
                not (root/(label+'-serial.log')).exists(),'native_fault_paused_before_exec')
    else:
        at=witness.get('admitted_at');require(type(at) is int and ledger['consumed_at']<=at<decode(grant_raw)['expires_at'],
                                            'native_fault_admission_clock')
        admission=witness['guest_admission'];seed=native_seed({'job':job,'source':source,'job_sha256':digest(canonical(job))})
        validate_native_admission(admission,validate_inspection(admission['inspection'],seed))
        if case=='owner-loss':
            require(type(witness.get('owner_pid')) is int and witness['owner_pid']>1 and witness['owner_pid']!=vm['actual']['pid'] and
                    type(witness.get('owner_identity')) is str and witness['owner_identity'].isdecimal() and
                    type(witness.get('owner_returncode')) is int and witness['owner_returncode']==-9 and
                    not (root/(label+'-owner-result.json')).exists(),'native_fault_owner_identity')
        else:require(witness.get('serial_closed') is True,'native_fault_serial_closed')
    if case!='owner-loss':
        owner=decode(read(root,label+'-owner-result.json',65536),65536)
        require(owner.get('reason')=='requested_stop' and owner.get('connection_closed') is True,'native_fault_owner_clean_stop')
    return {'result':'PASS','case':case,'profile':context['profile'],'request_sha256':digest(raw),
            'stop_after_fault_seconds':seconds,'writers_stopped':True,'output_published':False}


from representation_owned_inputs import native_fixtures, NATIVE_CASES, validate_owned


def native_owned_request(job,nonce,profile,mode,slot):
    spec=common.client_command(job,nonce,profile,mode,'request',slot=slot)
    raw=read(spec['workspace'],'slots/'+slot+'/request.json',contract.REQUEST_LIMIT)
    entry=next(row for row in native_fixtures(nonce,profile) if row['slot']==slot)
    request=validate_owned(raw,entry,contract);case_id=request['binding']['case_reference']['case_id']
    parent=spec['workspace']/'cases'/case_id;ref=request['binding']['case_reference']
    require(read(parent,'source.bin',8*1024**2)==entry['original'] and
            digest(read(parent,'manifest.json',1024**2))==ref['manifest_sha256'] and
            digest(read(parent,'evidence/merkle_index.json',2*1024**2))==ref['merkle_index_sha256'] and
            read(parent,'evidence/merkle_root.bin',128).decode().strip()==ref['merkle_root_blake3'],
            'native_owned_actual_parent_binding')
    return raw,parent,common.case_inventory(parent)


def native_owned_assert(report,slot,profile,nonce):
    require(report['result']=='PASS' and len(report['runs'])==1,'native_owned_execution_failed')
    run=report['runs'][0];value=run['outcome'];status=value['status']
    if slot in {'positive','derived','pie','dynamic','smoke'}:
        marker=('OWNED-NATIVE-'+profile.upper()+'-'+nonce+'\n').encode('ascii')
        require(status=='completed' and value['returncode']==0 and
                bytes.fromhex(value['records'][0]['bytes_hex'])==marker and
                value['records'][1]['bytes_hex']=='','native_owned_completion_oracle')
    elif slot=='cancel':
        require(canonical(value)==canonical({'status':'cancelled','records':[],'done':False}) and
                run['writers_stopped'] is True,'native_owned_host_cancellation')
    elif slot=='error':require(status=='failed' and value['returncode']==7,'native_owned_error_oracle')
    elif slot=='loop':require(status=='timeout','native_owned_wall_oracle')
    elif slot=='fork':
        require(status in {'failed','timeout'} and counters(value['events']['pids.events'])['max']>0 and
                int(value['events']['pids.peak'])==16,'native_owned_task_oracle')
    elif slot=='output':require(status=='output_budget' and len(value['records'][0]['bytes_hex'])==2048,'native_owned_output_oracle')
    elif slot=='memory':
        require(status=='memory_budget' and value['returncode']==-9 and
                counters(value['events']['memory.events'])['oom_kill']>0,'native_owned_memory_oracle')
    elif slot=='file':
        require(status=='failed' and value['file_observation']=={'regular':True,'bytes':4096},'native_owned_file_oracle')
    else:raise ValueError('native_owned_fixed_oracle')


def new_native_readiness(context,matrix_raw):
    manifest,proof=common.snapshot_proof();review=proof['review'];runs=[r for r in proof['ci'] if r['event']=='pull_request']
    require(review['decision']=='no_findings' and review['open_threads']==0 and review['resolved_head_sha']==manifest['head_sha'] and
            len(runs)==2 and all(r['status']=='completed' and r['conclusion']=='success' and r['head_sha']==manifest['head_sha'] for r in runs) and
            sum(len(r['jobs']) for r in runs)==7,'native_owned_review_head_ci')
    now=int(time.time());raw=canonical({'schema':'paw-s14-native-i08-v1','scope':SCOPE,
        'decision':'ready-for-explicit-single-native-no-nic','context_sha256':digest(canonical(context)),
        'matrix_sha256':digest(matrix_raw),'reviewed_head':manifest['head_sha'],
        'review_url':'https://github.com/'+storage.REPOSITORY+'/pull/'+str(proof['pull_request']['number'])+'#issuecomment-'+str(review['receipt_id']),
        'ci_runs':[r['run_id'] for r in runs],'ci_successful_jobs':7,'created_at':now,'expires_at':now+86400})
    validate_readiness(raw,context);return raw


def accepted_native(profile,context):
    prefix='acceptance-'+profile+'-'+digest(canonical(context))+'-'
    with store() as fd:
        names=os.listdir(fd);require(len(names)<=4096,'native_owned_acceptance_inventory')
        for name in names:
            if not re.fullmatch(re.escape(prefix)+'[0-9a-f]{64}\\.json',name):continue
            value=decode(fs.read(fd,name,65536))
            try:ready=fs.read(fd,'readiness-'+value['readiness_sha256']+'.json',65536)
            except FileNotFoundError:continue
            parsed=decode(ready);validate_readiness(ready,context,now=parsed['created_at'])
            require(name==prefix+digest(ready)+'.json' and value['schema']=='paw-s14-native-owned-acceptance-v1' and
                    value['context_sha256']==digest(canonical(context)) and value['profile']==context['profile'] and value['result']=='PASS' and
                    type(value['job']) is str and re.fullmatch('[0-9a-f]{32}',value['job']),'native_owned_cached_context')
            if parsed['expires_at']<=time.time():continue
            matrix=CONTROL/('native-owned-'+value['job'])
            require(digest(read(matrix,'validation.json',2*1024**2))==parsed['matrix_sha256']==value['matrix_sha256'] and
                    digest(read(matrix,'acceptance.json',2*1024**2))==value['acceptance_sha256'],'native_owned_cached_matrix')
            return True
    return False


def validation_batches(profile):
    require(type(profile) is str and profile in NATIVE_CASES,'native_fixed_stage_profile')
    slots=NATIVE_CASES[profile]
    return tuple(tuple(slots[n:n+3]) for n in range(0,len(slots),3))


def stage_name(profile,context,index):
    require(type(index) is int and 0<=index<len(validation_batches(profile)),'native_stage_index')
    return 'owned-stage-'+profile+'-'+digest(canonical(context))+'-'+str(index)+'.json'


def stage_client_call(job,nonce,profile,mode,phase,context,slot=None):
    value=common.run_client(job,nonce,profile,mode,phase,context,slot=slot,_capture=capture)
    # Each stage uses a fresh private client workspace and nonce. The final
    # matrix retains those bindings instead of claiming one shared client job.
    return dict(value,fixture_nonce=nonce,fixture_job=job)


def verify_owned_stage(value,profile,context,index):
    require(type(value) is dict and set(value)=={'schema','result','profile','context','job','release_sha',
        'stage_index','nonce','validations','clients','real_samples_executed'} and
        value['schema']=='paw-s14-native-owned-stage-v1' and value['result']=='PASS' and
        value['profile']==profile and value['context']==context and type(value['stage_index']) is int and
        value['stage_index']==index and type(value['real_samples_executed']) is int and value['real_samples_executed']==0,
        'native_stage_scope')
    job=value['job'];nonce=value['nonce'];slots=validation_batches(profile)[index]
    require(type(job) is str and re.fullmatch('[0-9a-f]{32}',job) and type(nonce) is str and
            re.fullmatch('[0-9a-f]{16}',nonce) and type(value['release_sha']) is str and
            re.fullmatch('[0-9a-f]{40}',value['release_sha']),'native_stage_identity')
    reader=common.READERS/(job+'-client-source');verify_snapshot(reader,context)
    manifest=decode(read(reader,'runtime-snapshot/release.json',storage.MAX_MANIFEST),storage.MAX_MANIFEST)
    require(manifest['release_sha']==value['release_sha'],'native_stage_snapshot_release')
    clients=value['clients'];require(type(clients) is list and len(clients)==len(slots)+2,'native_stage_clients')
    for client in clients:
        require(client['result']=='PASS' and client['fixture_job']==job and client['fixture_nonce']==nonce and
                client['terminal']['writers_stopped'] is True and client['terminal']['cgroup_removed'] is True and
                client['terminal']['main_pid']==0,'native_stage_client_terminal')
    rows=value['validations']
    require(type(rows) is list and [row['slot'] for row in rows]==list(slots),'native_stage_exact_cases')
    expected={row['slot']:row for row in native_fixtures(nonce,profile)}
    for row in rows:
        slot=row['slot'];rid=row['request_id'];audit=audit_path(rid)
        require(row['audit']==str(audit) and all(row[key] is True for key in
            ['replay_refused','wrong_parent_and_digest_refused','parent_unchanged']),'native_stage_validation_binding')
        policy,ctx,raw,_,ledger,_,request,_,_,_=audit_authority(audit,None)
        policy_value=decode(policy);entry=expected[slot];candidate=request['candidate'];binding=request['binding']
        node=next(node for node in binding['derivation']['nodes'] if node['id']==binding['derivation']['selected'])
        require(ctx==context and policy_value['mode']=='owned-validation' and
            policy_value['owned_manifest_sha256']==digest(canonical({'nonce':nonce,'slot':slot,'profile':context['profile'],
                'request_sha256':digest(raw)})) and candidate['source']['data_hex']==entry['selected'].hex() and
            binding['original_source']['sha256']==digest(entry['original']) and
            binding['original_source']['bytes']==len(entry['original']) and node['kind']==entry['kind'],
            'native_stage_owned_bytes')
        confirm_consumed(ledger)
        spec=common.client_command(job,nonce,profile,'source','request',slot=slot)
        require(read(spec['workspace'],'slots/'+slot+'/request.json',contract.REQUEST_LIMIT)==raw,'native_stage_client_request_changed')
        parent=spec['workspace']/'cases'/binding['case_reference']['case_id']
        require(digest(canonical(common.case_inventory(parent)))==row['parent_inventory_sha256'],'native_stage_parent_changed')
        if slot in FAULTS:verified=verify_native_fault(audit,raw,slot,row['witness'])
        else:
            verified=verify_native(audit)
            report=decode(read(audit,'results.json',2*1024**2),2*1024**2);native_owned_assert(report,slot,profile,nonce)
            if slot=='positive':require(row['witness'].get('live_busy_lock_refused') is True,'native_stage_busy_witness')
        require(verified==row['verification'] and verified['result']=='PASS','native_stage_independent_verification')
    return value


def completed_owned_stages(profile,context):
    stages=[];missing=False
    with store() as fd:
        for index in range(len(validation_batches(profile))):
            name=stage_name(profile,context,index)
            try:raw=fs.read(fd,name,65536)
            except FileNotFoundError:missing=True;continue
            require(not missing,'native_stage_gap')
            pointer=decode(raw,65536)
            require(raw==canonical(pointer) and type(pointer) is dict and set(pointer)=={
                'schema','context_sha256','profile','index','job','stage_sha256'} and
                pointer['schema']=='paw-s14-native-owned-stage-pointer-v1' and
                pointer['context_sha256']==digest(canonical(context)) and pointer['profile']==profile and
                type(pointer['index']) is int and pointer['index']==index and
                type(pointer['job']) is str and re.fullmatch('[0-9a-f]{32}',pointer['job']) and
                contract.shared._hex(pointer['stage_sha256']),'native_stage_pointer')
            stage_raw=read(CONTROL/('native-owned-stage-'+pointer['job']),'stage.json',2*1024**2)
            require(digest(stage_raw)==pointer['stage_sha256'],'native_stage_digest')
            value=decode(stage_raw,2*1024**2);require(stage_raw==canonical(value),'native_stage_canonical')
            stages.append(verify_owned_stage(value,profile,context,index))
    return stages


def run_validation_stage(job,release,profile,context,index,record):
    nonce=uuid.uuid4().hex[:16];matrix=CONTROL/('native-owned-stage-'+job)
    with fs.root_directory(CONTROL) as fd:os.mkdir(matrix.name,mode=0o700,dir_fd=fd)
    common.stage_client(job,context)
    summary={'schema':'paw-s14-native-owned-stage-v1','result':'PASS','profile':profile,'context':context,
             'job':job,'release_sha':release,'stage_index':index,'nonce':nonce,'validations':[],
             'clients':[],'real_samples_executed':0}
    for mode in ['source','installed']:
        summary['clients'].append(stage_client_call(job,nonce,profile,mode,'prepare',context))
    for slot in validation_batches(profile)[index]:
        summary['clients'].append(stage_client_call(job,nonce,profile,'source','request',context,slot=slot))
        raw,parent,before=native_owned_request(job,nonce,profile,'source',slot)
        policy=make_policy(context,[raw],owned_manifest_sha256=digest(canonical({
            'nonce':nonce,'slot':slot,'profile':context['profile'],'request_sha256':digest(raw)})))
        install_policy(policy,context);issue(raw,policy,context)
        for field in ['selection_binding_sha256','source']:
            changed=decode(raw,contract.REQUEST_LIMIT)
            if field=='source':changed['candidate']['source']['sha256']='0'*64
            else:changed['candidate'][field]='0'*64
            try:inspect(canonical(changed))
            except ValueError:pass
            else:raise ValueError('native_owned_changed_request_admitted')
        witness={};report,audit=execute_native(raw,policy,cancel=slot=='cancel',_fault=slot if slot in FAULTS else None,
            _witness=witness,_probe=slot=='positive')
        record['backend_diagnostics']={key:report[key] for key in ['diagnostic','cleanup_diagnostic','verification_diagnostic'] if key in report}
        if slot in FAULTS:verified=verify_native_fault(audit,raw,slot,witness)
        else:
            require(report['result']=='PASS','native_owned_execution_failed:'+slot+':'+report.get('error','')+report.get('verification_error',''))
            verified=verify_native(audit);native_owned_assert(report,slot,profile,nonce)
            if slot=='positive':require(witness.get('live_busy_lock_refused') is True,'native_owned_live_busy_witness')
        require(verified['result']=='PASS' and common.case_inventory(parent)==before,'native_owned_verification_or_parent')
        try:consume(raw,policy,context)
        except FileExistsError:pass
        else:raise ValueError('native_owned_replay_admitted')
        summary['validations'].append({'slot':slot,'request_id':decode(raw,contract.REQUEST_LIMIT)['candidate']['request_id'],
            'audit':str(audit),'verification':verified,'witness':witness,'replay_refused':True,
            'wrong_parent_and_digest_refused':True,'parent_unchanged':True,
            'parent_inventory_sha256':digest(canonical(before))})
    require(canonical(capture(context['profile']))==canonical(context),'native_stage_final_context')
    verify_owned_stage(summary,profile,context,index)
    raw=canonical(summary);require(len(raw)<=2*1024**2,'native_stage_report_budget')
    with fs.root_directory(matrix) as fd:fs.exclusive(fd,'stage.json',raw)
    publish_reader_tree(matrix)
    pointer=canonical({'schema':'paw-s14-native-owned-stage-pointer-v1','context_sha256':digest(canonical(context)),
        'profile':profile,'index':index,'job':job,'stage_sha256':digest(raw)})
    with store() as fd:fs.exclusive(fd,stage_name(profile,context,index),pointer)
    return summary,matrix


def finish_owned_native(job,release,profile,context,stages,record):
    from gw_quarantine import publish as quarantine_publish
    # A distinct bounded call runs only two final smokes. Cached stages have
    # already been independently re-read against the exact maintained context.
    nonce=uuid.uuid4().hex[:16];matrix=CONTROL/('native-owned-'+job)
    with fs.root_directory(CONTROL) as fd:os.mkdir(matrix.name,mode=0o700,dir_fd=fd)
    common.stage_client(job,context)
    summary={'schema':'paw-s14-native-owned-matrix-v2','profile':context['profile'],'context':context,
        'nonce':nonce,'validations':[row for stage in stages for row in stage['validations']],
        'clients':[client for stage in stages for client in stage['clients']],
        'stages':[{'job':stage['job'],'stage_index':stage['stage_index'],'nonce':stage['nonce'],
            'stage_sha256':digest(canonical(stage))} for stage in stages],'real_samples_executed':0}
    require([row['slot'] for row in summary['validations']]==list(NATIVE_CASES[profile]),'native_complete_stage_coverage')
    for mode in ['source','installed']:
        summary['clients'].append(stage_client_call(job,nonce,profile,mode,'prepare',context))
    ready_raw=None;ready_installed=False;completed=False
    try:
        refused=matrix/'unknown-stop-must-not-publish'
        try:quarantine_publish(refused,[],stopped=None)
        except ValueError:require(not refused.exists(),'native_owned_unknown_stop_output')
        else:raise ValueError('native_owned_unknown_stop_publication')
        require(canonical(capture(context['profile']))==canonical(context),'native_owned_final_context')
        summary.update(result='PASS',unknown_stop_publication_refused=True);validation_raw=canonical(summary)
        with fs.root_directory(matrix) as fd:fs.exclusive(fd,'validation.json',validation_raw)
        ready_raw=new_native_readiness(context,validation_raw);install_readiness(ready_raw,context);ready_installed=True;smokes=[]
        for mode in ['source','installed']:
            common.run_client(job,nonce,profile,mode,'request',context,slot='smoke',_capture=capture)
            raw,parent,before=native_owned_request(job,nonce,profile,mode,'smoke')
            policy=make_policy(context,[raw],mode='explicit-source-analysis',ready=ready_raw)
            install_policy(policy,context);issue(raw,policy,context)
            report,audit=execute_native(raw,policy)
            record['backend_diagnostics']={key:report[key] for key in ['diagnostic','cleanup_diagnostic','verification_diagnostic'] if key in report}
            require(report['result']=='PASS','native_owned_smoke_failed')
            native_owned_assert(report,'smoke',profile,nonce);exported=publish_native(raw)
            client=stage_client_call(job,nonce,profile,mode,'import',context,slot='smoke')
            require(common.case_inventory(parent)==before,'native_owned_smoke_parent_changed')
            sidecar=common.client_command(job,nonce,profile,mode,'import',slot='smoke')['workspace']/'sidecar-smoke/result'
            receipt_raw=read(sidecar,'receipt.json',contract.RECEIPT_LIMIT)
            require(read(sidecar,'request.json',contract.REQUEST_LIMIT)==raw and digest(receipt_raw)==exported['receipt_sha256'],
                    'native_owned_sidecar_binding')
            request=contract.validate_request(raw,decode(raw,contract.REQUEST_LIMIT)['candidate']['created_at'])
            receipt=contract.validate_receipt(receipt_raw,request,digest(raw))
            for item in receipt['artifacts']:
                require(digest(read(sidecar,item['stored_as'],1024))==item['sha256'],'native_owned_sidecar_output')
            try:consume(raw,policy,context)
            except FileExistsError:pass
            else:raise ValueError('native_owned_smoke_replay_admitted')
            smokes.append({'mode':mode,'request_id':exported['request_id'],'export':exported,'client':client,
                           'original_unchanged':True,'replay_refused':True})
        acceptance=canonical({'result':'PASS','job':job,'profile':context['profile'],'matrix_sha256':digest(validation_raw),
            'readiness_sha256':digest(ready_raw),'smokes':smokes,'real_source_grants_issued':0})
        with fs.root_directory(matrix) as fd:fs.exclusive(fd,'acceptance.json',acceptance)
        value={'schema':'paw-s14-native-owned-acceptance-v1','result':'PASS','job':job,'profile':context['profile'],
            'context_sha256':digest(canonical(context)),'readiness_sha256':digest(ready_raw),
            'matrix_sha256':digest(validation_raw),'acceptance_sha256':digest(acceptance)}
        publish_reader_tree(matrix)
        with store() as fd:fs.exclusive(fd,'acceptance-'+profile+'-'+value['context_sha256']+'-'+value['readiness_sha256']+'.json',canonical(value))
        record.update(result='PASS',profile=profile,stage_only=False,cases=2,matrix_cases=len(NATIVE_CASES[profile])+2,
                      stages_complete=len(stages),stages_required=len(validation_batches(profile)),i08_installed=True,
                      vm_started=True,matrix=str(matrix),readiness_sha256=digest(ready_raw),matrix_sha256=digest(validation_raw));completed=True
    finally:
        if ready_installed and not completed:
            with store() as fd:
                try:os.unlink('readiness-'+digest(ready_raw)+'.json',dir_fd=fd)
                except FileNotFoundError:pass
                os.fsync(fd)
            record['new_readiness_revoked']=True


def run_owned_native(job,release,profile):
    """Only reserved fixed-profile recipes; never accepts a path/source from CLI."""
    root_only();require(type(profile) is str and profile in {'shell','elf'} and re.fullmatch('[0-9a-f]{32}',job) and
                        re.fullmatch('[0-9a-f]{40}',release) and HERE.parents[1]==Path('/opt/paw-vm/releases')/release,
                        'native_owned_active_job')
    from vm_operator_host import write_state
    from vm_runtime_revalidation import revalidate
    folder=STATE/'jobs'/job
    record={'result':'FAIL','job':job,'recipe':profile+'-owned-v1','release_sha':release,
            'real_samples_executed':0,'real_source_grants_issued':0}
    with fs.root_directory(folder):pass
    try:
        common.snapshot_proof();runtime=revalidate();initialize();context=capture(contract.PROFILES[profile].engine)
        if accepted_native(profile,context):record.update(result='PASS',already_accepted=True,cases=0,vm_started=False)
        else:
            stages=completed_owned_stages(profile,context)
            if len(stages)<len(validation_batches(profile)):
                stage,matrix=run_validation_stage(job,release,profile,context,len(stages),record)
                record.update(result='PASS',profile=profile,stage_only=True,stage_index=len(stages),
                    stages_complete=len(stages)+1,stages_required=len(validation_batches(profile)),
                    cases=len(stage['validations']),vm_started=True,matrix=str(matrix),i08_installed=False)
            else:
                finish_owned_native(job,release,profile,context,stages,record)
        record['runtime_sha256']=digest(canonical(runtime))
    except Exception as error:record.update(result='FAIL',error=str(error),traceback=traceback.format_exc(),diagnostic=common.failure_diagnostic(error))
    finally:
        with fs.root_directory(folder) as fd:write_state(fd,'result.json',record)
    print(json.dumps({'result':record['result'],'job':job,'profile':profile,'diagnostic':record.get('diagnostic'),
        'backend_diagnostics':record.get('backend_diagnostics'),'stage_only':record.get('stage_only',False),
        'stages_complete':record.get('stages_complete'),'stages_required':record.get('stages_required'),
        'i08_installed':record.get('i08_installed',False),'matrix':record.get('matrix'),
        'real_samples_executed':0}),flush=True)
    require(record['result']=='PASS','native_owned_recipe_failed')


# One reproduced owned historical failure; never a caller-selected Root reader.
HISTORICAL_NATIVE_JOB='9ab7f09d2a8640a39a7c2f9a2ab590ad'
HISTORICAL_NATIVE_REQUEST='e51ae5f1725d401592ed67eea27e04d2'
HISTORICAL_NATIVE_RELEASE='3a8446b3034a998bb876cc55b4bd14020b3ad8ee'
HISTORICAL_NATIVE_MANIFEST='edf94ac1d9e9114cc6cdef578c1154cadd8828f7082e6ccbcae25ac86b8b0fce'


def native_failure_metadata(report,modules,codes):
    """Publish only reviewed literal codes, bounded locations and booleans."""
    require(type(report) is dict and report.get('result')=='FAIL' and report.get('scope')==SCOPE and
        type(report.get('real_connections')) is int and report['real_connections']==0,'native_historical_failure_scope')
    diagnostics={}
    for field in ['error','verification_error','cleanup_error']:
        text=report.get(field)
        if text is None:continue
        require(type(text) is str and len(text)<=65536,'native_historical_error_budget')
        parts=text.split(':',8);code=parts[0]
        diagnostics[field]={'error_code':code if code in codes else 'non_code_failure',
            'causes':[part for part in parts[1:] if part in codes][:4]}
    trace=report.get('traceback','');require(type(trace) is str and len(trace)<=65536,'native_historical_trace_budget')
    locations=[]
    for filename,line in re.findall(r'  File "([^"\n]{1,4096})", line ([0-9]{1,7})',trace):
        name=Path(filename).name
        if name in modules and 0<int(line)<=1000000:locations.append({'module':name,'line':int(line)})
    for field in ['diagnostic','verification_diagnostic','cleanup_diagnostic']:
        value=report.get(field)
        if value is None:continue
        require(type(value) is dict and type(value.get('locations')) is list and len(value['locations'])<=6,
                'native_historical_stored_diagnostic')
        for location in value['locations']:
            require(type(location) is dict and set(location)=={'module','line'},'native_historical_stored_location')
            if location['module'] in modules and type(location['line']) is int and 0<location['line']<=1000000:
                locations.append(dict(location))
    return {'source_result':'FAIL','diagnostics':diagnostics,'locations':locations[-6:],
        'writers_stopped_attested':report.get('writers_stopped') is True,
        'host_restored_attested':report.get('host_restored') is True}


def previous_owned_native_failure():
    """Read only this fixed failed1MiB owned smoke; no guest or authority write."""
    import ast
    root_only();folder=STATE/'jobs'/HISTORICAL_NATIVE_JOB
    outer=decode(read(folder,'result.json',256*1024))
    require(outer.get('result')=='FAIL' and outer.get('job')==HISTORICAL_NATIVE_JOB and
        outer.get('recipe')=='elf-owned-v1' and outer.get('release_sha')==HISTORICAL_NATIVE_RELEASE and
        outer.get('error')=='native_owned_smoke_failed' and outer.get('new_readiness_revoked') is True and
        outer.get('real_samples_executed')==outer.get('real_source_grants_issued')==0,'native_historical_owned_job')
    root=audit_path(HISTORICAL_NATIVE_REQUEST)
    policy_raw=read(root,'policy.json',256*1024);policy=decode(policy_raw);context=policy['context']
    header=read(root,'runtime-snapshot/release.json',storage.MAX_MANIFEST)
    require(digest(header)==HISTORICAL_NATIVE_MANIFEST,'native_historical_manifest_digest')
    manifest=storage.manifest(header,HISTORICAL_NATIVE_RELEASE);verify_snapshot(root,context)
    modules=set();codes=set()
    for name,entry in manifest['files'].items():
        if not name.endswith('.py'):continue
        source=read(root,'runtime-snapshot/'+name,storage.MAX_FILE)
        require(digest(source)==entry['sha256'] and len(source)==entry['bytes'],'native_historical_source_digest')
        modules.add(Path(name).name)
        # These finite words are public literals in the exact reviewed snapshot,
        # not arbitrary error text, source bytes, guest output or caller data.
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,ast.Constant) and type(node.value) is str:
                prefix=node.value.split(':',1)[0]
                if re.fullmatch('[a-z][a-z0-9_]{0,95}',prefix):codes.add(prefix)
    matrix=CONTROL/('native-owned-'+HISTORICAL_NATIVE_JOB)
    validation=decode(read(matrix,'validation.json',2*1024**2),2*1024**2)
    require(validation.get('result')=='PASS' and validation.get('profile')==ELF and
        validation.get('context')==context,'native_historical_validation_context')
    raw=read(root,'authority-copy/'+HISTORICAL_NATIVE_REQUEST+'/request.json',contract.REQUEST_LIMIT)
    request=contract.validate_request(raw,decode(raw,contract.REQUEST_LIMIT)['candidate']['created_at']);candidate=request['candidate']
    expected=next(row for row in native_fixtures(validation['nonce'],'elf') if row['slot']=='smoke')
    require(candidate['request_id']==HISTORICAL_NATIVE_REQUEST and candidate['profile']==ELF and
        candidate['source']['bytes']==1024**2 and candidate['source']['data_hex']==expected['selected'].hex() and
        request['binding']['original_source']['sha256']==digest(expected['original']) and
        policy['mode']=='explicit-source-analysis' and policy['approved_requests']==[
            {'request_sha256':digest(raw),'source_sha256':candidate['source']['sha256']}],
        'native_historical_exact_owned_smoke')
    readiness=read(root,'readiness.json',65536)
    require(digest(readiness)==policy['readiness_sha256'],'native_historical_readiness_copy')
    with store() as fd:
        try:fs.read(fd,'readiness-'+digest(readiness)+'.json',65536)
        except FileNotFoundError:pass
        else:raise ValueError('native_historical_readiness_not_revoked')
    report_raw=read(root,'results.json',2*1024**2);report=decode(report_raw,2*1024**2)
    serial=read(root,'native-elf-'+HISTORICAL_NATIVE_REQUEST+'-serial.log',1024**2)
    value=native_failure_metadata(report,modules,codes)
    markers={'linux_boot':b'Linux version','cloud_init':b'cloud-init','traceback':b'Traceback (most recent call last)',
        'service_failure':b'Failed to start','emergency':b'emergency mode','kernel_panic':b'Kernel panic','oom':b'Out of memory'}
    value.update(scope='fixed historical owned native smoke diagnostic only; no acceptance or authority',
        job=HISTORICAL_NATIVE_JOB,request_id=HISTORICAL_NATIVE_REQUEST,release_sha=HISTORICAL_NATIVE_RELEASE,
        report_sha256=digest(report_raw),serial_sha256=digest(serial),serial_bytes=len(serial),
        serial_flags={key:marker in serial for key,marker in markers.items()},
        readiness_revoked=True,vm_started=False,i08_installed=False,real_source_grants_issued=0)
    return value
