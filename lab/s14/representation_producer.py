"""Root representation custody and finite owned acceptance; no arbitrary CLI.

Existing protected grants serve custody; the reserved recipe independently
restricts new authority to immutable-generated owned bytes and scoped I08.
"""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import json
import stat
import subprocess
import time
import traceback
import uuid

import representation_authorization as auth
import representation_adapter as adapter
from browser_vm import BROWSER_META
from browser_offline_adapter import input_media
from benign_guest_validation import BASE, digest
from verify_representation import read, verify_single
from reader_export import publish_reader_tree
from representation_owned_inputs import identity as client_identity
from representation_owned_inputs import fixtures, javascript_fixture, validate_owned
from verify_representation import verify_snapshot, verify_fault, FAULTS

CONTROL = Path('/var/lib/paw-s14/control')
STATE = Path('/var/lib/paw-vm')
RELEASES = Path('/opt/paw-vm/releases')
HISTORICAL_MANIFEST_SHA256 = '350e9cb3937ef497a1ad601e3001d4b87e71e9df81b2263b2d71f3d805c4d169'
HISTORICAL_JS_MANIFEST_SHA256 = '21e422c8d2fd1bd86f298d8f9d63dab8b6da8a90bfa35f9ea6e8bba7818380c7'
HISTORICAL_JS_REQUEST_SHA256 = '93e58ff6c4c12549c0c6570352ca4e1a349e963466176cc3d95f276177e820b1'
READER_GID = 1000
require = auth.require


def root_only():
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'root_PID1_representation_producer_required')


def audit_path(identifier):
    require(type(identifier) is str and len(identifier) == 32 and all(v in '0123456789abcdef' for v in identifier),
            'representation_producer_identifier')
    return CONTROL/('representation-job-'+identifier)


def copy_runtime(output, context):
    """The source is protected active state, never a caller-selected path."""
    with auth.fs.root_directory(STATE) as fd: active = auth.decode(auth.fs.read(fd, 'active.json'))
    source = auth.HERE.parents[1]
    require(source == RELEASES/active['release_sha'], 'representation_producer_active_release')
    with auth.fs.root_directory(source.parent) as parent:
        manifest, _ = auth.storage.verify(parent, active['release_sha'], active['manifest_sha256'])
    require(auth.digest(auth.storage.canonical(manifest['files'])) == context['runtime_sources_sha256'],
            'representation_producer_snapshot_context')
    def copy(fd, parts, raw):
        if len(parts) == 1: auth.fs.exclusive(fd, parts[0], raw)
        else:
            with auth.fs.subdirectory(fd, parts[0]) as child: copy(child, parts[1:], raw)
    with auth.fs.root_directory(source) as original, auth.fs.root_directory(output) as folder, \
         auth.fs.subdirectory(folder, 'runtime-snapshot') as target:
        for name, limit in [('release.json', auth.storage.MAX_MANIFEST), ('proof.json', 128*1024)]:
            auth.fs.exclusive(target, name, auth.storage.read_file(original, name, limit))
        for name, metadata in manifest['files'].items():
            parts = auth.storage.source_path(name); current = os.dup(original)
            try:
                for part in parts[:-1]:
                    child = auth.storage.open_dir(current, part); os.close(current); current = child
                raw = auth.storage.read_file(current, parts[-1], auth.storage.MAX_FILE)
                require(len(raw) == metadata['bytes'] and auth.digest(raw) == metadata['sha256'],
                        'representation_producer_snapshot_changed')
                copy(target, parts, raw)
            finally: os.close(current)


def save_results(output, report):
    """Atomic private result, including a final failed-verification disposition."""
    raw = auth.canonical(report); require(len(raw) <= 2*1024**2, 'representation_producer_report_budget')
    with auth.fs.root_directory(output) as fd:
        auth.fs.exclusive(fd, 'results.pending', raw)
        os.replace('results.pending', 'results.json', src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)


def image_proof(profile, context):
    if profile == adapter.HTML:
        with auth.fs.root_directory(BROWSER_META.parent) as fd: raw = auth.fs.read(fd, BROWSER_META.name, 1024**2)
        require(auth.digest(raw) == context['backend']['image_certificate_sha256'], 'representation_producer_browser_certificate')
        return 'browser-image-certificate.json', raw
    require(profile == adapter.PYTHON, 'representation_producer_image_profile')
    with auth.fs.root_directory(BASE.parent) as fd:
        raw = auth.fs.read(fd, 'provenance.json', 65536)
        signed = auth.fs.read(fd, 'SHA256SUMS', 65536)
        auth.fs.read(fd, 'SHA256SUMS.gpg', 65536)
    provenance = auth.decode(raw, 65536)
    require(provenance['result'] == 'PASS' and provenance['signed_manifest'] is True and
            provenance['image'] == BASE.name and provenance['sha256'] == auth.fs.IMAGE_SHA256,
            'representation_producer_base_provenance')
    sums = {row[1].lstrip('*'): row[0] for line in signed.decode('ascii').splitlines() if len(row := line.split()) == 2}
    require(sums[BASE.name] == provenance['sha256'], 'representation_producer_signed_image_hash')
    # Recheck the fixed vendor signature locally; no package/network operation.
    from hostile_maintenance import SIGNER
    keyring = Path('/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg')
    auth.fs.trusted(keyring.lstat())
    verified = subprocess.run(['/usr/bin/gpgv', '--status-fd=1', '--keyring', str(keyring),
        str(BASE.parent/'SHA256SUMS.gpg'), str(BASE.parent/'SHA256SUMS')], capture_output=True, text=True, timeout=15)
    require(verified.returncode == 0 and '[GNUPG:] VALIDSIG '+SIGNER+' ' in verified.stdout,
            'representation_producer_vendor_signature')
    return 'image-provenance.json', raw


def owned_fault_gate(profile, case, witness):
    require(profile in {adapter.PYTHON, adapter.HTML} and case in FAULTS and type(witness) is dict, 'owned_representation_fixed_fault')
    parent = adapter.HashGate if profile == adapter.PYTHON else adapter.BrowserVM
    class OwnedFaultGate(parent):
        def start(self, label, boot=True):
            vm = super().start(label, boot=case != 'paused-refusal')
            witness.update(schema='paw-s14-representation-fault-v1', case=case, vm_uuid=vm['node']['uuid'])
            if case == 'paused-refusal':
                witness['paused_before_refusal'] = self.connection.lookupByUUIDString(vm['node']['uuid']).state()[0] == self.libvirt.VIR_DOMAIN_PAUSED
                witness['_fault_at'] = time.monotonic(); raise ValueError(FAULTS[case])
            channel = vm['channel']; original = channel.call
            def observed(operation, **kwargs):
                if operation == 'poll':
                    witness['_fault_at'] = time.monotonic()
                    if case == 'owner-loss':
                        from benign_guest_validation import process_identity
                        witness['owner_pid'] = vm['owner'].pid; witness['owner_identity'] = process_identity(vm['owner'].pid)
                        vm['owner'].kill(); vm['owner'].wait(timeout=3); witness['owner_returncode'] = vm['owner'].returncode
                    else:
                        channel.serial.close(); channel.serial.close = channel.serial.log.close
                        witness['serial_closed'] = True
                    raise ValueError(FAULTS[case])
                value = original(operation, **kwargs)
                if operation == 'start': witness.update(guest_admission=value, admitted_at=int(time.time()))
                if operation == 'inspect': witness['guest_inspection'] = value
                return value
            channel.call = observed
            return vm
        def stop(self, vm, kill=False):
            value = super().stop(vm, kill=kill)
            if '_fault_at' in witness: witness['fault_stop_seconds'] = time.monotonic()-witness.pop('_fault_at')
            return value
    return OwnedFaultGate


def owned_probe_gate(profile, witness):
    require(profile in {adapter.PYTHON, adapter.HTML} and type(witness) is dict, 'owned_representation_fixed_probe')
    parent = adapter.HashGate if profile == adapter.PYTHON else adapter.BrowserVM
    class OwnedProbe(parent):
        def start(self, label, boot=True):
            vm = super().start(label, boot=boot)
            try:
                with auth.fs.execution_lock(): raise ValueError('owned_representation_busy_lock_not_exclusive')
            except BlockingIOError: witness['live_busy_lock_refused'] = True
            return vm
    return OwnedProbe


def execute(raw, policy_raw, *, cancel=False, _owned_fault=None, _witness=None, _owned_probe=False):
    root_only(); summary = auth.inspect(raw); profile = summary['profile']; identifier = summary['request_id']
    context = auth.capture(profile); _, checked, request, source = auth.load_bound(raw, policy_raw, context)
    require(checked == summary, 'representation_producer_request_changed')
    policy, ready = auth.installed(policy_raw, context)
    require(_owned_fault is None or policy['mode'] == 'owned-validation' and _owned_fault in FAULTS and
            type(_witness) is dict, 'representation_owned_fault_policy')
    gate_class = None if _owned_fault is None else owned_fault_gate(profile, _owned_fault, _witness)
    require(type(_owned_probe) is bool and not (_owned_probe and _owned_fault is not None), 'representation_owned_probe_shape')
    if _owned_probe:
        require(policy['mode'] == 'owned-validation' and type(_witness) is dict, 'representation_owned_probe_policy')
        gate_class = owned_probe_gate(profile, _witness)
    output = audit_path(identifier)
    with auth.fs.root_directory(CONTROL): pass
    current = adapter.job(request); job_sha = auth.digest(auth.canonical(current))
    image = None
    if profile == adapter.HTML:
        image = input_media(source, identifier)
        gate = (gate_class or adapter.BrowserVM)(argparse.Namespace(output=output), phase='job', media=image,
            seed_config={'source_sha256': summary['source_sha256'], 'source_bytes': len(source),
                         'job_sha256': job_sha, 'request_id': identifier})
    else:
        require(profile == adapter.PYTHON, 'representation_producer_profile')
        gate = (gate_class or adapter.HashGate)(argparse.Namespace(output=output)); gate.active_vm = None
    gate.report.update(runs=[], vms=[], real_connections=0, scope=auth.SCOPE)
    before = None; canary = os.urandom(32)
    try:
        gate.canary = output/'host-owned-canary.bin'
        with auth.fs.root_directory(output) as fd:
            auth.fs.exclusive(fd, gate.canary.name, canary); auth.fs.exclusive(fd, 'policy.json', policy_raw)
            with auth.python_backend.store() as store:
                maintenance = auth.fs.read(store, 'maintenance-'+context['maintenance_sha256']+'.json', 65536)
            require(auth.digest(maintenance) == context['maintenance_sha256'], 'representation_producer_maintenance')
            auth.fs.exclusive(fd, 'maintenance.json', maintenance)
            name, proof = image_proof(profile, context); auth.fs.exclusive(fd, name, proof)
            if ready is not None: auth.fs.exclusive(fd, 'readiness.json', ready)
        copy_runtime(output, context); before = gate.snapshot_host()
        run = (adapter.run_python if profile == adapter.PYTHON else adapter.run_html)(gate, raw, policy_raw, cancel=cancel)
        gate.report.update(result='PASS', runs=[run])
    except Exception as error:
        gate.report.update(result='FAIL', error=str(error), traceback=traceback.format_exc(), diagnostic=failure_diagnostic(error))
    finally:
        try:
            if gate.active_vm is not None: gate.stop(gate.active_vm)
            after = gate.snapshot_host()
            require(before is not None and before == after and not gate.connection.listAllDomains(0),
                    'representation_producer_host_not_restored')
            require(digest(BASE) == auth.fs.IMAGE_SHA256 and gate.canary.read_bytes() == canary and
                    auth.canonical(auth.capture(profile)) == auth.canonical(context), 'representation_producer_context_changed')
            gate.report.update(host_before=before, host_after=after, host_restored=True, base_unchanged=True,
                host_canary_unchanged=True, source_freeze_unchanged=True, writers_stopped=True)
            if profile == adapter.HTML: gate.report['browser_image_unchanged'] = True
        except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error), cleanup_diagnostic=failure_diagnostic(error))
        gate.connection.close(); save_results(output, gate.report)
    if gate.report['result'] == 'PASS':
        try:
            verified = verify_single(output, production=policy['mode'] == 'explicit-source-analysis')
            with auth.fs.root_directory(output) as fd:
                auth.fs.exclusive(fd, 'independent-verification.json', auth.canonical(verified))
        except Exception as error:
            gate.report.update(result='FAIL', verification_error=str(error), verification_diagnostic=failure_diagnostic(error)); save_results(output, gate.report)
    return gate.report, output


@contextmanager
def _export_parent():
    """Initialize only the fixed reader root beneath its protected parent.

    Existing inodes are validated, never repaired. Pin the leaf without following
    links and make only a newly created, trusted empty root traversable by the
    enrolled reader. Individual result trees stay private until publication.
    """
    root = auth.contract.EXPORT_ROOT
    with auth.fs.root_directory(root.parent) as ancestor:
        created = False
        try:
            os.mkdir(root.name, mode=0o700, dir_fd=ancestor); created = True
        except FileExistsError: pass
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
        try:
            auth.fs.trusted(os.fstat(fd), True)
            if created:
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'representation_export_new_root_mode')
                os.fchown(fd, auth.fs.OWNER_UID, READER_GID); os.fchmod(fd, 0o750)
                os.fsync(fd); os.fsync(ancestor)
            info = os.fstat(fd)
            require(info.st_gid == READER_GID and stat.S_IMODE(info.st_mode) == 0o750,
                    'representation_export_root_mode')
            yield fd
        finally: os.close(fd)


def publish(raw):
    """Only a current protected analysis-mode audit may enter the client export."""
    root_only(); request = auth.contract.validate_request(raw, auth.decode(raw, auth.contract.REQUEST_LIMIT)['candidate']['created_at'])
    identifier = request['candidate']['request_id']; output = audit_path(identifier)
    verified = verify_single(output, production=True)
    report = auth.decode(read(output, 'results.json', 2*1024**2), 2*1024**2); run = report['runs'][0]
    policy_raw = read(output, 'policy.json', 256*1024); context = auth.decode(policy_raw)['context']
    require(auth.canonical(auth.capture(context['profile'])) == auth.canonical(context), 'representation_publish_current_context')
    policy, ready = auth.installed(policy_raw, context)
    require(policy['mode'] == 'explicit-source-analysis' and ready is not None, 'representation_publish_analysis_only')
    copied = 'authority-copy/'+identifier
    require(read(output, copied+'/request.json', auth.contract.REQUEST_LIMIT) == raw and
            verified['request_sha256'] == auth.digest(raw), 'representation_publish_request')
    grant, _, _, _ = auth.load_bound(raw, policy_raw, context, now=run['admitted_at'])
    require(grant == read(output, copied+'/grant.json', 8192), 'representation_publish_protected_grant')
    auth.confirm_consumed(run['consumption'])
    name, proof = image_proof(context['profile'], context)
    require(read(output, name, 1024**2) == proof, 'representation_publish_image_proof')
    backend = context['backend']; image_sha = backend['image_sha256'] if context['profile'] == adapter.HTML else backend['host']['image_sha256']
    receipt = {'schema': 'paw-s14-representation-result-v1',
        'producer_kind': 'local-root-verified-representation-no-nic-v1', 'request_id': identifier,
        'request_sha256': auth.digest(raw), 'candidate_sha256': auth.digest(auth.canonical(request['candidate'])),
        'selection_binding_sha256': request['candidate']['selection_binding_sha256'],
        'source_sha256': request['candidate']['source']['sha256'], 'profile': context['profile'],
        'execution_status': run['outcome']['status'], 'runtime': {
            'job_sha256': run['job_sha256'], 'raw_result_sha256': auth.digest(read(output, 'results.json', 2*1024**2)),
            'source_inventory_sha256': auth.digest(auth.canonical(report['source_hashes'])),
            'policy_sha256': auth.digest(policy_raw), 'grant_sha256': auth.digest(grant),
            'readiness_sha256': auth.digest(ready), 'consumption_sha256': auth.digest(auth.canonical(run['consumption'])),
            'bridge_contract_sha256': auth.contract.contract_hash(), 'image_certificate_sha256': auth.digest(proof),
            'context_sha256': auth.digest(auth.canonical(context)), 'vm_uuid': run['vm_uuid'], 'image_sha256': image_sha,
            'source_count': len(report['source_hashes']), 'admitted_at': run['admitted_at'], 'completed_at': int(time.time()),
            'stop_seconds': run['stop_seconds'], 'writers_stopped': True, 'network_interfaces': []},
        'artifacts': [{k: v[k] for k in ['stored_as', 'bytes', 'sha256']} for v in run['quarantine']]}
    receipt_raw = auth.canonical(receipt); auth.contract.validate_receipt(receipt_raw, request, auth.digest(raw))
    destination = auth.contract.EXPORT_ROOT/identifier
    with _export_parent() as parent:
        os.mkdir(identifier, mode=0o700, dir_fd=parent); os.fsync(parent)
    with auth.fs.root_directory(destination) as fd:
        auth.fs.exclusive(fd, 'request.json', raw); auth.fs.exclusive(fd, 'receipt.json', receipt_raw)
        for item in receipt['artifacts']:
            blob = read(output, run['job']['job_id']+'-quarantine/'+item['stored_as'], 1024)
            require(auth.digest(blob) == item['sha256'] and len(blob) == item['bytes'], 'representation_publish_opaque_digest')
            auth.fs.exclusive(fd, item['stored_as'], blob)
    publish_reader_tree(destination)
    return {'request_id': identifier, 'result': 'PASS', 'export': str(destination), 'receipt_sha256': auth.digest(receipt_raw)}


CLIENT_PYTHON = Path('/home/linux-dac/Documents/Codex/2026-10-23/riprendiamo-paw-sul-nuovo-pc-linux/work/s14-local/p3-installed/venv/bin/python')
CLIENTS = Path('/var/lib/paw-vm-clients')
READERS = Path('/var/lib/paw-vm-exports')
PHASES = {'prepare', 'request', 'import'}
SLOTS = {'positive', 'prefix', 'qp', 'paused-refusal', 'owner-loss', 'protocol-loss', 'smoke'}


def client_command(job, nonce, profile, mode, phase, *, slot=None):
    require(type(job) is str and re.fullmatch('[0-9a-f]{32}', job) and
            type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'owned_client_identifier')
    require(type(profile) is str and profile in {'python', 'html', 'shell', 'elf', 'javascript'} and type(mode) is str and mode in {'source', 'installed'} and
            type(phase) is str and phase in PHASES, 'owned_client_finite_phase')
    from representation_owned_inputs import NATIVE_CASES
    allowed_slots = (set(NATIVE_CASES[profile]) | {'smoke'} if profile in {'shell','elf'} else
                     {'smoke'} if profile == 'javascript' else SLOTS)
    require((phase == 'prepare' and slot is None) or (phase != 'prepare' and type(slot) is str and slot in allowed_slots),
            'owned_client_finite_slot')
    tag = profile+'-'+mode+'-'+phase+('' if slot is None else '-'+slot)
    unit = 'paw-vm-client-'+job+'-'+tag; parent = 'paw-vm-owned-'+job+'.service'
    reader = READERS/(job+'-client-source'); code = reader/'runtime-snapshot'; workspace = CLIENTS/job/(profile+'-'+mode)
    gate = reader/('go-'+tag+'.json')
    argv = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit,
        '--property=Type=exec', '--property=RuntimeMaxSec=180', '--property=TimeoutStopSec=5',
        '--property=KillMode=control-group', '--property=MemoryMax=256M', '--property=MemorySwapMax=0',
        '--property=TasksMax=32', '--property=CPUQuota=50%', '--property=LimitCORE=0',
        '--property=LimitFSIZE=8388608', '--property=UMask=0077', '--property=IPAddressDeny=any',
        '--property=Slice=machine-paws14.slice', '--property=BindsTo='+parent, '--property=After='+parent,
        '--property=PrivateNetwork=yes', '--property=PrivateTmp=yes', '--property=ProtectSystem=strict',
        '--property=ProtectHome=read-only', '--property=ProtectControlGroups=yes',
        '--property=ReadWritePaths='+str(CLIENTS/job),
        '--property=InaccessiblePaths=/run/user /run/libvirt /run/dbus /run/systemd/private',
        '--property=NoNewPrivileges=yes', '--property=WorkingDirectory='+str(CLIENTS/job),
        '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/nonexistent', 'LANG=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1',
        '/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups', '--inh-caps=-all',
        '--ambient-caps=-all', '--bounding-set=-all', '--no-new-privs',
        str(CLIENT_PYTHON), '-I', '-B', str(code/'lab/s14/representation_owned_inputs.py'),
        '--workspace', str(workspace), '--nonce', nonce, '--profile', profile, '--phase', phase,
        '--gate-file', str(gate), '--gate-tag', tag]
    if mode == 'source': argv += ['--source-tree', str(code)]
    if slot is not None: argv += ['--slot', slot]
    return {'unit': unit+'.service', 'parent_unit': parent, 'reader': reader, 'code': code, 'workspace': workspace,
            'gate': gate, 'tag': tag, 'argv': argv,
            'environment': {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
                            'PYTHONDONTWRITEBYTECODE': '1'}}


def stage_client(job, context):
    root_only(); spec = client_command(job, '0'*16, 'python', 'source', 'prepare')
    with auth.fs.root_directory(CLIENTS.parent) as parent:
        try: os.mkdir(CLIENTS.name, mode=0o751, dir_fd=parent)
        except FileExistsError: pass
    with auth.fs.root_directory(CLIENTS) as parent:
        require(os.fstat(parent).st_mode & 0o777 == 0o751, 'owned_client_parent_mode')
        os.mkdir(job, mode=0o700, dir_fd=parent)
        fd = os.open(job, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try: os.fchown(fd, 1000, 1000); os.fchmod(fd, 0o700)
        finally: os.close(fd)
        os.fsync(parent)
    with auth.fs.root_directory(READERS) as parent: os.mkdir(spec['reader'].name, mode=0o700, dir_fd=parent)
    copy_runtime(spec['reader'], context); verify_snapshot(spec['reader'], context)
    publish_reader_tree(spec['reader'])
    return spec['reader']


def client_properties(unit):
    result = subprocess.run(['/usr/bin/systemctl', 'show', unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,ExecMainStatus,Slice'],
        capture_output=True, text=True, timeout=10)
    require(len(result.stdout)+len(result.stderr) <= 65536, 'owned_client_unit_property_budget')
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(result.returncode == 0 or result.returncode == 1 and values.get('LoadState') == 'not-found',
            'owned_client_unit_properties')
    return values


def client_process(pid):
    from benign_guest_validation import process_identity
    identity = process_identity(pid); require(identity is not None, 'owned_client_missing_process')
    status = Path('/proc', str(pid), 'status').read_text()
    proof = client_identity(status)
    namespaces = {name: os.readlink('/proc/'+str(pid)+'/ns/'+name) for name in ['net', 'mnt']}
    require(all(re.fullmatch(name+':\\[[0-9]+\\]', value) and value != os.readlink('/proc/self/ns/'+name)
                for name, value in namespaces.items()), 'owned_client_private_namespaces')
    require(process_identity(pid) == identity, 'owned_client_process_changed')
    return {'pid': pid, 'pid_identity': identity, 'status_sha256': auth.digest(status.encode()), 'namespaces': namespaces, **proof}


def client_limits(spec, properties):
    path = '/machine.slice/machine-paws14.slice/'+spec['unit']
    require(properties.get('Slice') == 'machine-paws14.slice' and properties.get('ControlGroup') == path,
            'owned_client_effective_slice')
    group = Path('/sys/fs/cgroup'+path)
    limits = {name: (group/name).read_text().strip() for name in ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max']}
    require(limits == {'memory.max': str(256*1024**2), 'memory.swap.max': '0', 'pids.max': '32',
                       'cpu.max': '50000 100000'}, 'owned_client_effective_limits')
    return limits


def client_terminal(spec, process_proof):
    from benign_guest_validation import process_identity
    properties = client_properties(spec['unit'])
    require(properties.get('ActiveState') in {'inactive', 'failed'} and properties.get('MainPID') == '0',
            'owned_client_unit_not_terminal')
    group = Path('/sys/fs/cgroup/machine.slice/machine-paws14.slice')/spec['unit']
    require(not group.exists(), 'owned_client_cgroup_not_removed')
    if process_proof is not None:
        require(process_identity(process_proof['pid']) != process_proof['pid_identity'], 'owned_client_writer_alive')
    return {'unit': spec['unit'], 'load_state': properties.get('LoadState'), 'active_state': properties['ActiveState'],
            'main_pid': 0, 'cgroup_removed': True, 'writers_stopped': True}


def run_client(job, nonce, profile, mode, phase, context, *, slot=None, _capture=None):
    root_only(); spec = client_command(job, nonce, profile, mode, phase, slot=slot)
    verify_snapshot(spec['reader'], context)
    folder = STATE/'jobs'/job; frontend = None; process_proof = None; acknowledged = False
    with auth.fs.root_directory(folder) as fd:
        logfd = os.open('client-'+spec['tag']+'.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=fd)
    with os.fdopen(logfd, 'wb') as log:
        try:
            frontend = subprocess.Popen(spec['argv'], stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=spec['environment'])
            deadline = time.monotonic()+12
            while time.monotonic() < deadline and frontend.poll() is None:
                properties = client_properties(spec['unit']); pid = properties.get('MainPID', '')
                if pid.isdecimal() and int(pid) > 1:
                    try: observed = client_process(int(pid))
                    except (ValueError, FileNotFoundError, ProcessLookupError): time.sleep(.05); continue
                    limits = client_limits(spec, properties); process_proof = {**observed, 'limits': limits}
                    with auth.fs.root_directory(spec['reader']) as fd:
                        auth.fs.exclusive(fd, spec['gate'].name, auth.canonical({'schema': 'paw-s14-owned-client-go-v1',
                            'nonce': nonce, 'tag': spec['tag'], 'pid': observed['pid']}))
                        leaf = os.open(spec['gate'].name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                        try: os.fchown(leaf, 0, 1000); os.fchmod(leaf, 0o440)
                        finally: os.close(leaf)
                        os.fsync(fd)
                    acknowledged = True; break
                time.sleep(.05)
            require(acknowledged, 'owned_client_kernel_identity_not_acknowledged')
            result = frontend.wait(timeout=185)
        finally:
            # The child is also bound to the parent owned unit. Stop and verify
            # its whole dedicated cgroup before any guest/next client can start.
            stopped = subprocess.run(['/usr/bin/systemctl', 'stop', spec['unit']], capture_output=True, text=True, timeout=12)
            if frontend is not None:
                try: frontend.wait(timeout=10)
                except subprocess.TimeoutExpired: raise ValueError('owned_client_frontend_not_terminal')
            terminal = client_terminal(spec, process_proof)
    require(result == 0 and stopped.returncode in {0, 5} and terminal['writers_stopped'] is True,
            'owned_client_phase_failed')
    # Only reviewed immutable Root callers supply this internal context reader.
    actual_context = (auth.capture if _capture is None else _capture)(context['profile'])
    require(auth.canonical(actual_context) == auth.canonical(context), 'owned_client_context_changed')
    verify_snapshot(spec['reader'], context)
    return {'result': 'PASS', 'phase': phase, 'profile': profile, 'mode': mode, 'slot': slot,
            'process': process_proof, 'terminal': terminal, 'log': str(folder/('client-'+spec['tag']+'.log'))}


def owned_request(job, nonce, profile, mode, slot):
    spec = client_command(job, nonce, profile, mode, 'request', slot=slot)
    raw = read(spec['workspace'], 'slots/'+slot+'/request.json', auth.contract.REQUEST_LIMIT)
    name = profile+('-selected' if profile == 'python' else '-original') if slot == 'positive' else profile+('-qp' if slot == 'qp' else '-prefix')
    entry = javascript_fixture(nonce) if profile == 'javascript' else next(v for v in fixtures(nonce) if v['name'] == name)
    request = validate_owned(raw, entry, auth.contract); case = request['binding']['case_reference']['case_id']
    original = read(spec['workspace'], 'cases/'+case+'/source.bin', 8*1024**2)
    manifest = read(spec['workspace'], 'cases/'+case+'/manifest.json', 1024**2)
    ref = request['binding']['case_reference']
    require(original == entry['original'] and auth.digest(manifest) == ref['manifest_sha256'] and
            auth.digest(read(spec['workspace'], 'cases/'+case+'/evidence/merkle_index.json', 2*1024**2)) == ref['merkle_index_sha256'] and
            read(spec['workspace'], 'cases/'+case+'/evidence/merkle_root.bin', 1024).decode().strip() == ref['merkle_root_blake3'],
            'owned_representation_actual_parent_files')
    parent = spec['workspace']/'cases'/case
    return raw, parent, case_inventory(parent)


def case_inventory(case):
    from verify_representation import inventory
    return {name: auth.digest(read(case, name, 1024**2)) for name in inventory(case) if not name.endswith('/')}


def snapshot_proof():
    from vm_release_contract import release as validate_release, policy as validate_enrollment
    with auth.fs.root_directory(STATE) as fd:
        active = auth.decode(auth.fs.read(fd, 'active.json'))
        enrolled = auth.decode(auth.fs.read(fd, 'policy.json'))
    with auth.fs.root_directory(RELEASES) as parent:
        manifest, proof = auth.storage.verify(parent, active['release_sha'], active['manifest_sha256'])
    require(auth.HERE.parents[1] == RELEASES/active['release_sha'], 'owned_representation_active_snapshot')
    # The fixed promoter authenticated this complete proof against its then-
    # active predecessor. Enrollment policy retains the original native anchor.
    # Only storage.verify() of the Root active state/manifest above supplies this
    # historical anchor; no caller proof or arbitrary anchor is accepted here.
    validate_enrollment(enrolled)
    promoted_policy = dict(enrolled, anchor_sha=proof.get('anchor_sha'))
    validate_release(proof, promoted_policy, enrolled['owner_uid'])
    require(enrolled['owner_uid'] == 1000, 'owned_representation_fixed_client_owner')
    return manifest, proof


def new_readiness(context, matrix_raw):
    manifest, proof = snapshot_proof(); review = proof['review']
    runs = [row for row in proof['ci'] if row['event'] == 'pull_request']
    require(review['decision'] == 'no_findings' and review['open_threads'] == 0 and review['resolved_head_sha'] == manifest['head_sha'] and
            len(runs) == 2 and all(row['status'] == 'completed' and row['conclusion'] == 'success' and
            row['head_sha'] == manifest['head_sha'] for row in runs) and sum(len(row['jobs']) for row in runs) == 7,
            'owned_representation_review_and_ci')
    now = int(time.time()); raw = auth.canonical({'schema': 'paw-s14-representation-i08-v1', 'scope': auth.SCOPE,
        'decision': 'ready-for-explicit-single-representation-no-nic', 'context_sha256': auth.digest(auth.canonical(context)),
        'matrix_sha256': auth.digest(matrix_raw), 'reviewed_head': manifest['head_sha'],
        'review_url': 'https://github.com/'+auth.storage.REPOSITORY+'/pull/'+str(proof['pull_request']['number'])+'#issuecomment-'+str(review['receipt_id']),
        'ci_runs': [row['run_id'] for row in runs], 'ci_successful_jobs': 7, 'created_at': now, 'expires_at': now+86400})
    auth.validate_readiness(raw, context); return raw


def accepted(profile, context, *, readiness=False):
    prefix = 'acceptance-'+profile+'-'+auth.digest(auth.canonical(context))+'-'
    with auth.store() as fd:
        names = os.listdir(fd); require(len(names) <= 4096, 'owned_representation_acceptance_inventory')
        for name in names:
            if not re.fullmatch(re.escape(prefix)+'[0-9a-f]{64}\\.json', name): continue
            value = auth.decode(auth.fs.read(fd, name, 65536))
            try: ready = auth.fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json', 65536)
            except FileNotFoundError: continue  # A revoked readiness never authorizes reuse.
            parsed = auth.decode(ready); auth.validate_readiness(ready, context, now=parsed['created_at'])
            require(name == prefix+auth.digest(ready)+'.json' and value['context_sha256'] == auth.digest(auth.canonical(context)) and
                    value['profile'] == context['profile'] and value['result'] == 'PASS', 'owned_representation_acceptance_binding')
            if parsed['expires_at'] <= time.time(): continue
            matrix = CONTROL/('representation-owned-'+value['job'])
            require(re.fullmatch('[0-9a-f]{32}', value['job']) and
                    auth.digest(read(matrix, 'validation.json', 1024**2)) == parsed['matrix_sha256'] == value['matrix_sha256'] and
                    auth.digest(read(matrix, 'acceptance.json', 1024**2)) == value['acceptance_sha256'],
                    'owned_representation_acceptance_files')
            return ready if readiness else True
    return None if readiness else False


def javascript_accepted(context):
    """A separate owned handoff proof, subordinate to current HTML readiness.

    This marker issues no I08 and cannot keep expired or revoked HTML authority
    alive. Both proof files are Root generated; a caller's JSON is never read.
    """
    ready = accepted('html', context, readiness=True)
    if ready is None: return False
    context_sha = auth.digest(auth.canonical(context)); ready_sha = auth.digest(ready)
    name = 'javascript-acceptance-'+context_sha+'-'+ready_sha+'.json'
    with auth.store() as fd:
        try: raw = auth.fs.read(fd, name, 65536)
        except FileNotFoundError: return False
    value = auth.decode(raw)
    require(value['schema'] == 'paw-s14-owned-javascript-pointer-v1' and value['result'] == 'PASS' and
            value['context_sha256'] == context_sha and value['readiness_sha256'] == ready_sha and
            re.fullmatch('[0-9a-f]{32}', value['job']), 'owned_javascript_acceptance_binding')
    matrix = CONTROL/('representation-js-owned-'+value['job'])
    proof_raw = read(matrix, 'acceptance.json', 1024**2)
    require(auth.digest(proof_raw) == value['acceptance_sha256'], 'owned_javascript_acceptance_digest')
    proof = auth.decode(proof_raw, 1024**2); entry = javascript_fixture(proof['nonce'])
    require(proof['schema'] == 'paw-s14-owned-javascript-handoff-v1' and proof['result'] == 'PASS' and
            proof['job'] == value['job'] and proof['context'] == context and proof['profile'] == adapter.HTML and
            proof['readiness_sha256'] == ready_sha and proof['source_sha256'] == auth.digest(entry['original']) and
            proof['source_bytes'] == len(entry['original']) and proof['browser_sha256'] == auth.digest(entry['selected']) and
            proof['browser_bytes'] == len(entry['selected']) and proof['real_source_grants_issued'] == 0 and
            [row['mode'] for row in proof['smokes']] == ['source', 'installed'] and
            all(row['original_unchanged'] is True and row['replay_refused'] is True for row in proof['smokes']),
            'owned_javascript_acceptance_proof')
    return True


def run_owned_javascript(job, context):
    """Two fixed maximum-size owned JS→HTML smokes in their own bounded call.

    No new profile, readiness installation or caller-controlled source. The
    ordinary client must select the exact explicit browser representation and
    Root independently regenerates its bytes and derivation before each grant.
    """
    root_only(); require(type(job) is str and re.fullmatch('[0-9a-f]{32}', job) and
                         context['profile'] == adapter.HTML, 'owned_javascript_job_context')
    ready_raw = accepted('html', context, readiness=True)
    require(ready_raw is not None, 'owned_javascript_current_html_required')
    nonce = uuid.uuid4().hex[:16]; entry = javascript_fixture(nonce)
    matrix = CONTROL/('representation-js-owned-'+job)
    with auth.fs.root_directory(CONTROL) as fd: os.mkdir(matrix.name, mode=0o700, dir_fd=fd)
    stage_client(job, context); clients = []; smokes = []
    for mode in ['source', 'installed']:
        clients.append(run_client(job, nonce, 'javascript', mode, 'prepare', context))
        clients.append(run_client(job, nonce, 'javascript', mode, 'request', context, slot='smoke'))
        raw, parent, original = owned_request(job, nonce, 'javascript', mode, 'smoke')
        policy_raw = auth.make_policy(context, [raw], mode='explicit-source-analysis', ready=ready_raw)
        auth.install_policy(policy_raw, context); auth.issue(raw, policy_raw, context)
        report, audit = execute(raw, policy_raw)
        require(report['result'] == 'PASS', 'owned_representation_smoke_execution')
        owned_success(report, 'html', nonce)
        exported = publish(raw)  # Independently verifies the protected VM audit.
        client = run_client(job, nonce, 'javascript', mode, 'import', context, slot='smoke'); clients.append(client)
        require(case_inventory(parent) == original, 'owned_representation_smoke_parent_changed')
        sidecar = client_command(job, nonce, 'javascript', mode, 'import', slot='smoke')['workspace']/'sidecar-smoke/result'
        receipt_raw = read(sidecar, 'receipt.json', auth.contract.RECEIPT_LIMIT)
        require(read(sidecar, 'request.json', auth.contract.REQUEST_LIMIT) == raw and
                auth.digest(receipt_raw) == exported['receipt_sha256'], 'owned_representation_smoke_sidecar_binding')
        receipt = auth.contract.validate_receipt(receipt_raw,
            auth.contract.validate_request(raw, auth.decode(raw, auth.contract.REQUEST_LIMIT)['candidate']['created_at']), auth.digest(raw))
        for item in receipt['artifacts']:
            require(auth.digest(read(sidecar, item['stored_as'], 1024)) == item['sha256'], 'owned_representation_smoke_sidecar_output')
        try: auth.consume(raw, policy_raw, context)
        except FileExistsError: pass
        else: raise ValueError('owned_representation_smoke_replay_accepted')
        smokes.append({'mode': mode, 'request_id': exported['request_id'], 'export': exported, 'client': client,
                       'original_unchanged': True, 'replay_refused': True})
    require(auth.canonical(auth.capture(adapter.HTML)) == auth.canonical(context) and
            accepted('html', context, readiness=True) == ready_raw, 'owned_javascript_final_context')
    proof = auth.canonical({'schema': 'paw-s14-owned-javascript-handoff-v1', 'result': 'PASS', 'job': job,
        'profile': adapter.HTML, 'context': context, 'nonce': nonce, 'readiness_sha256': auth.digest(ready_raw),
        'source_bytes': len(entry['original']), 'source_sha256': auth.digest(entry['original']),
        'browser_bytes': len(entry['selected']), 'browser_sha256': auth.digest(entry['selected']),
        'clients': clients, 'smokes': smokes, 'real_source_grants_issued': 0})
    with auth.fs.root_directory(matrix) as fd: auth.fs.exclusive(fd, 'acceptance.json', proof)
    publish_reader_tree(matrix)
    context_sha = auth.digest(auth.canonical(context)); ready_sha = auth.digest(ready_raw)
    with auth.store() as fd:
        auth.fs.exclusive(fd, 'javascript-acceptance-'+context_sha+'-'+ready_sha+'.json', auth.canonical({
            'schema': 'paw-s14-owned-javascript-pointer-v1', 'result': 'PASS', 'job': job,
            'context_sha256': context_sha, 'readiness_sha256': ready_sha, 'acceptance_sha256': auth.digest(proof)}))
    return {'result': 'PASS', 'profile': 'javascript', 'engine_profile': adapter.HTML, 'cases': 2,
            'vm_started': True, 'i08_installed': False, 'matrix': str(matrix),
            'readiness_sha256': ready_sha, 'acceptance_sha256': auth.digest(proof)}


def owned_success(report, profile, nonce):
    require(report['result'] == 'PASS' and len(report['runs']) == 1, 'owned_representation_execution_failed')
    outcome = report['runs'][0]['outcome']
    require(outcome['status'] == 'completed' and type(outcome['returncode']) is int and outcome['returncode'] == 0,
            'owned_representation_expected_completion')
    blob = bytes.fromhex(outcome['records'][0]['bytes_hex'])
    if profile == 'python': require(blob.decode().splitlines() == ['OWNED-REPRESENTATION-'+nonce], 'owned_representation_python_oracle')
    else: require(profile == 'html' and auth.decode(blob, 1024)['title'] == ('OWNED-REPRESENTATION-'+nonce)[:32],
                  'owned_representation_html_oracle')


def browser_outcome_metadata(report):
    """Typed outcome/counters only, never guest text, markup or console bytes."""
    from browser_offline_adapter import validate_outcome
    from browser_policy import MAX_DOM
    require(report.get('result') == 'PASS' and len(report['runs']) == 1, 'owned_browser_outcome_report')
    outcome = validate_outcome(report['runs'][0]['outcome'])
    result = {key: outcome[key] for key in ['status', 'returncode', 'writers_stopped', 'output_truncated', 'sandbox']}
    result['observations_available'] = False
    if outcome['records']:
        try: observations = auth.decode(bytes.fromhex(outcome['records'][0]['bytes_hex']), 1024)
        except ValueError: observations = None
        if type(observations) is dict and type(observations.get('dom_bytes')) is int and \
                0 <= observations['dom_bytes'] <= MAX_DOM and auth.contract.shared._hex(observations.get('dom_sha256')):
            result.update(observations_available=True, dom_bytes=observations['dom_bytes'], dom_sha256=observations['dom_sha256'])
    return result


def previous_owned_javascript_failure():
    """One pinned historical JS smoke, through the existing no-VM recipe only.

    No caller selects a path/job, raw logs are not exported and the complete
    protected VM audit must verify before its bounded outcome is summarized.
    Historical success of custody is distinct from acceptance of this smoke.
    """
    import base64
    root_only(); job = 'ca8b61fc0c7b4d4f8288fe9ff63f131b'
    rid = '212c0b19513e4fe8a31fdf114c2d6ec1'; nonce = 'ee4fa4ca23784bd3'
    release = 'd0a9dbd78f0170b85e3a5516337908ec5809e3cc'
    with auth.fs.root_directory(STATE/'jobs'/job) as fd: outer = auth.decode(auth.fs.read(fd, 'result.json', 256*1024))
    require(outer.get('result') == 'FAIL' and outer.get('job') == job and outer.get('recipe') == 'python-owned-v2' and
            outer.get('release_sha') == release and outer.get('profile') is None and
            outer.get('error') == 'owned_representation_expected_completion' and outer.get('real_samples_executed') == 0,
            'owned_javascript_historical_outer')
    root = audit_path(rid)
    with auth.fs.root_directory(root): pass
    header = read(root, 'runtime-snapshot/release.json', auth.storage.MAX_MANIFEST)
    require(auth.digest(header) == HISTORICAL_JS_MANIFEST_SHA256,
            'owned_javascript_historical_manifest')
    auth.storage.manifest(header, release)
    policy_raw = read(root, 'policy.json', 256*1024); policy = auth.decode(policy_raw); context = policy['context']
    require(context['profile'] == adapter.HTML and policy['mode'] == 'explicit-source-analysis', 'owned_javascript_historical_policy')
    verify_snapshot(root, context); verified = verify_single(root, production=True)
    raw = read(root, 'authority-copy/'+rid+'/request.json', auth.contract.REQUEST_LIMIT)
    require(auth.digest(raw) == HISTORICAL_JS_REQUEST_SHA256,
            'owned_javascript_historical_request')
    request = auth.contract.validate_request(raw, auth.decode(raw, auth.contract.REQUEST_LIMIT)['candidate']['created_at'])
    # Reconstruct the old immutable fixture, not the newly corrected one.
    prefix = ('document.title="OWNED-REPRESENTATION-'+nonce+'";\n/*').encode('ascii')
    original = prefix+b'x'*(256*1024-len(prefix)-3)+b'*/\n'
    source = (b'<!doctype html><meta charset="utf-8"><title>PAW explicit JavaScript view</title>\n'
              b'<script src="data:text/javascript;charset=utf-8;base64,'+base64.b64encode(original)+b'"></script>\n')
    require(request['candidate']['request_id'] == rid and request['candidate']['profile'] == adapter.HTML and
            bytes.fromhex(request['candidate']['source']['data_hex']) == source and
            request['binding']['original_source'] == {'bytes': len(original), 'sha256': auth.digest(original)} and
            verified['result'] == 'PASS' and verified['request_sha256'] == auth.digest(raw),
            'owned_javascript_historical_fixture')
    report_raw = read(root, 'results.json', 2*1024**2); report = auth.decode(report_raw, 2*1024**2)
    return {'scope': 'fixed historical owned JS smoke diagnostic; no acceptance or authority',
        'job': job, 'request_id': rid, 'release_sha': release, 'request_sha256': auth.digest(raw),
        'report_sha256': auth.digest(report_raw), 'custody_verification': 'PASS', 'smoke_accepted': False,
        'source_bytes': len(original), 'browser_bytes': len(source), 'outcome': browser_outcome_metadata(report),
        'external_stop_under_12_seconds': True, 'vm_started': False, 'i08_installed': False, 'real_source_grants_issued': 0}


DIAGNOSTIC_CODES = frozenset({
    'operator_release_history', 'operator_policy_lease', 'operator_exact_head_clear_review',
    'operator_exact_head_successful_ci', 'operator_completed_successful_job', 'operator_required_workflow_runs',
    'operator_head_and_main_workflows', 'snapshot_manifest_digest', 'snapshot_proof_digest',
    'snapshot_proof_identity', 'snapshot_source_digest', 'owned_representation_active_snapshot',
    'owned_representation_fixed_client_owner', 'owned_representation_execution_failed',
    'owned_representation_smoke_execution', 'owned_representation_expected_completion', 'owned_client_kernel_identity_not_acknowledged',
    'owned_client_phase_failed', 'owned_client_effective_limits', 'owned_client_unit_not_terminal',
    'owned_client_cgroup_not_removed', 'owned_client_context_changed',
    'representation_current_protected_maintenance_required', 'representation_producer_context_changed',
    'representation_producer_host_not_restored', 'runtime_root_PID1_only', 'runtime_foreign_work_or_autostart',
    'runtime_host_network_changed', 'runtime_final_state_changed', 'runtime_unit_state',
    'runtime_fixed_unit_not_active', 'runtime_unreviewed_daemon_command', 'runtime_guard_dependency_changed',
    'hash_context_shape', 'maintenance_binding', 'qemu_maintenance_baseline',
    'guest_channel_deadline', 'guest_channel_failed', 'unexpected_readiness',
    'missing_readiness', 'host_job_deadline', 'guest_admission_binding', 'reset_marker_survived'})


def failure_diagnostic(error):
    """Bounded public codes/locations; private error text stays in Root state."""
    code = str(error).split(':', 1)[0]
    if code not in DIAGNOSTIC_CODES: code = 'non_code_failure'
    number = getattr(error, 'errno', None)
    if type(number) is not int or not 0 <= number <= 4096: number = None
    locations = []
    for frame in traceback.extract_tb(error.__traceback__)[-6:]:
        name = Path(frame.filename).name
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,96}\.py', name) and type(frame.lineno) is int and 0 < frame.lineno <= 1000000:
            locations.append({'module': name, 'line': frame.lineno})
    kind = type(error).__name__
    if kind not in {'ValueError', 'TypeError', 'KeyError', 'AssertionError', 'FileNotFoundError', 'PermissionError',
                    'OSError', 'TimeoutExpired', 'TimeoutError', 'ProcessLookupError', 'CalledProcessError'}: kind = 'Exception'
    causes = [part for part in str(error).split(':', 8)[1:8] if part in DIAGNOSTIC_CODES][:4]
    return {'error_type': kind, 'error_code': code, 'errno': number, 'locations': locations, 'causes': causes}


def stored_failure_diagnostic(report, modules):
    """Read data, never evaluate a traceback or publish raw error/guest bytes."""
    require(type(report) is dict and report.get('result') == 'FAIL' and report.get('scope') == auth.SCOPE and
            type(report.get('real_connections')) is int and report['real_connections'] == 0,
            'owned_historical_failure_scope')
    diagnostics = {}
    for field in ['error', 'verification_error', 'cleanup_error']:
        text = report.get(field)
        if text is None: continue
        require(type(text) is str and len(text) <= 65536, 'owned_historical_error_budget')
        diagnostics[field] = failure_diagnostic(ValueError(text))
    trace = report.get('traceback', '')
    require(type(trace) is str and len(trace) <= 65536, 'owned_historical_trace_budget')
    locations = []
    for filename, line in re.findall(r'  File "([^"\n]{1,4096})", line ([0-9]{1,7})', trace):
        name = Path(filename).name
        if name in modules and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}\.py', name) and 0 < int(line) <= 1000000:
            locations.append({'module': name, 'line': int(line)})
    kinds = {'ValueError', 'TypeError', 'KeyError', 'AssertionError', 'FileNotFoundError', 'PermissionError',
             'OSError', 'TimeoutExpired', 'TimeoutError', 'ProcessLookupError', 'CalledProcessError'}
    kind = trace.splitlines()[-1].split(':', 1)[0] if trace.splitlines() else ''
    return {'source_result': 'FAIL', 'diagnostics': diagnostics, 'error_type': kind if kind in kinds else 'Exception',
            'locations': locations[-6:], 'writers_stopped_attested': report.get('writers_stopped') is True,
            'host_restored_attested': report.get('host_restored') is True}


def previous_owned_failure():
    """One fixed historical owned attempt, exposed only as bounded diagnostics.

    No caller supplies a job, path, source, traceback or output selector. This
    function neither executes a guest nor issues/consumes/restores authority.
    """
    root_only()
    release = '9877cdd9eaedbd5d6ade1c85c2769747ff7fedc0'
    identifier = 'fe3d0adb0130410eb510f8143451a036'; nonce = '5cce69249b3e4fb6'
    folder = audit_path(identifier)
    with auth.fs.root_directory(folder) as fd:
        policy_raw = auth.fs.read(fd, 'policy.json', 256*1024)
        report_raw = auth.fs.read(fd, 'results.json', 2*1024**2)
        serial = auth.fs.read(fd, 'rep-python-'+identifier+'-serial.log', 1024**2)
    policy = auth.decode(policy_raw); context = policy['context']
    # The preserved pre-guest snapshot is a separate Root-private copy. Verify
    # its exact fixed manifest, protected inventory, proof and every source byte.
    # Never relax deployment verification or delete evidence from the old tree.
    with auth.fs.root_directory(folder/'runtime-snapshot') as fd:
        raw_manifest = auth.fs.read(fd, 'release.json', auth.storage.MAX_MANIFEST)
        require(auth.digest(raw_manifest) == HISTORICAL_MANIFEST_SHA256, 'owned_historical_manifest_digest')
        manifest = auth.storage.manifest(raw_manifest, release)
        parents = {'/'.join(auth.storage.source_path(name)[:n])+'/' for name in manifest['files']
                   for n in range(1, len(auth.storage.source_path(name)))}
        expected = set(manifest['files']) | parents | {'release.json', 'proof.json'}
        require(auth.storage.inventory(fd) == expected, 'owned_historical_copy_inventory')
    verify_snapshot(folder, context)
    require(context['profile'] == adapter.PYTHON and context['runtime_sources_sha256'] ==
            auth.digest(auth.storage.canonical(manifest['files'])), 'owned_historical_snapshot_binding')
    with auth.fs.root_directory(folder/'authority-copy'/identifier) as fd:
        raw = auth.fs.read(fd, 'request.json', auth.contract.REQUEST_LIMIT)
    request = auth.contract.validate_request(raw, auth.decode(raw, auth.contract.REQUEST_LIMIT)['candidate']['created_at'])
    candidate = request['candidate']
    require(candidate['request_id'] == identifier and candidate['profile'] == adapter.PYTHON and
            bytes.fromhex(candidate['source']['data_hex']) == next(v['selected'] for v in fixtures(nonce)
                if v['name'] == 'python-selected'), 'owned_historical_fixture_binding')
    require(policy['mode'] == 'owned-validation' and policy['readiness_sha256'] is None and
            policy['approved_requests'] == [{'request_sha256': auth.digest(raw), 'source_sha256': candidate['source']['sha256']}] and
            policy['owned_manifest_sha256'] == auth.digest(auth.canonical({'nonce': nonce, 'slot': 'positive',
                'profile': adapter.PYTHON, 'request_sha256': auth.digest(raw)})), 'owned_historical_validation_policy')
    report = auth.decode(report_raw, 2*1024**2)
    modules = {Path(name).name for name in manifest['files'] if name.endswith('.py')}
    result = stored_failure_diagnostic(report, modules)
    # Metadata only: a dirty historical deployment is still inadmissible. This
    # comparison is not a verification exception, rollback or execution grant.
    with auth.fs.root_directory(RELEASES/release) as fd: deployed = auth.storage.inventory(fd)
    extras = deployed-expected
    def bytecode(name):
        parts = name.rstrip('/').split('/')
        if name.endswith('/') and parts[-1] == '__pycache__': return '/'.join(parts[:-1])+'/' in parents
        if len(parts) < 2 or parts[-2] != '__pycache__': return False
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\.cpython-[0-9]{2,3}(?:\.opt-[0-9])?\.pyc', parts[-1])
        return match is not None and '/'.join(parts[:-2]+[match[1]+'.py']) in manifest['files']
    result['historical_deployment_inventory'] = {'matches_manifest': deployed == expected,
        'extra_entries': len(extras), 'missing_entries': len(expected-deployed),
        'extra_only_python_bytecode': bool(extras) and all(bytecode(name) for name in extras)}
    markers = {'linux_boot': b'Linux version', 'cloud_init': b'cloud-init', 'traceback': b'Traceback (most recent call last)',
               'service_failure': b'Failed to start', 'emergency': b'emergency mode',
               'kernel_panic': b'Kernel panic', 'oom': b'Out of memory'}
    result.update(scope='fixed historical owned failure diagnostic only; no acceptance or execution authority',
        request_id=identifier, release_sha=release, report_sha256=auth.digest(report_raw), serial_sha256=auth.digest(serial),
        serial_flags={key: marker in serial for key, marker in markers.items()},
        vm_started=False, i08_installed=False, real_source_grants_issued=0)
    return result


def run_owned(job, release):
    """One pending finite stage per call: Python, HTML, then owned JS handoff.

    The existing reserved recipe accepts no profile or source from its caller.
    All three current acceptances mean a subsequent call starts no VM.
    """
    root_only(); require(re.fullmatch('[0-9a-f]{32}', job) and re.fullmatch('[0-9a-f]{40}', release) and
                        auth.HERE.parents[1] == RELEASES/release, 'owned_representation_job_snapshot')
    from vm_operator_host import write_state
    from vm_runtime_revalidation import revalidate
    from gw_quarantine import publish as quarantine_publish
    folder = STATE/'jobs'/job; ready_raw = None; ready_installed = False; completed = False; selected = None
    record = {'result': 'FAIL', 'job': job, 'recipe': 'python-owned-v2', 'release_sha': release,
              'real_samples_executed': 0, 'real_source_grants_issued': 0}
    with auth.fs.root_directory(folder): pass
    try:
        snapshot_proof()  # Full merged review/head+main CI proof before any new work.
        runtime = revalidate(); auth.initialize()
        contexts = {key: auth.capture(auth.contract.PROFILES[key][0]) for key in ['python', 'html']}
        selected = next((key for key in ['python', 'html'] if not accepted(key, contexts[key])), None)
        if selected is None:
            if javascript_accepted(contexts['html']):
                record.update(result='PASS', already_accepted=True, cases=0, vm_started=False)
            else:
                selected = 'javascript'; record.update(run_owned_javascript(job, contexts['html']))
        else:
            context = contexts[selected]; nonce = uuid.uuid4().hex[:16]
            matrix = CONTROL/('representation-owned-'+job)
            with auth.fs.root_directory(CONTROL) as fd: os.mkdir(matrix.name, mode=0o700, dir_fd=fd)
            stage_client(job, context)
            summary = {'schema': 'paw-s14-representation-owned-matrix-v1', 'profile': context['profile'],
                'context': context, 'nonce': nonce, 'validations': [], 'clients': [], 'real_samples_executed': 0}
            for mode in ['source', 'installed']:
                summary['clients'].append(run_client(job, nonce, selected, mode, 'prepare', context))
            for slot in ['positive', 'prefix', 'qp', 'paused-refusal', 'owner-loss', 'protocol-loss']:
                summary['clients'].append(run_client(job, nonce, selected, 'source', 'request', context, slot=slot))
                raw, parent, original = owned_request(job, nonce, selected, 'source', slot)
                policy_raw = auth.make_policy(context, [raw], owned_manifest_sha256=auth.digest(auth.canonical({
                    'nonce': nonce, 'slot': slot, 'profile': context['profile'], 'request_sha256': auth.digest(raw)})))
                auth.install_policy(policy_raw, context); auth.issue(raw, policy_raw, context)
                for field in ['selection_binding_sha256', 'source']:
                    changed = auth.decode(raw, auth.contract.REQUEST_LIMIT)
                    if field == 'source': changed['candidate']['source']['sha256'] = '0'*64
                    else: changed['candidate'][field] = '0'*64
                    try: auth.inspect(auth.canonical(changed))
                    except ValueError: pass
                    else: raise ValueError('owned_representation_changed_request_admitted')
                witness = {}; report, audit = execute(raw, policy_raw, _owned_fault=slot if slot in FAULTS else None,
                    _witness=witness, _owned_probe=slot == 'positive')
                record['backend_diagnostics'] = {key: report[key] for key in
                    ['diagnostic', 'cleanup_diagnostic', 'verification_diagnostic'] if key in report}
                if slot in FAULTS: verified = verify_fault(audit, raw, slot, witness)
                else:
                    require(report['result'] == 'PASS', 'owned_representation_execution_failed:'+slot+':'+report.get('error', '')+report.get('verification_error', ''))
                    verified = verify_single(audit); owned_success(report, selected, nonce)
                    if slot == 'positive': require(witness.get('live_busy_lock_refused') is True, 'owned_representation_live_busy_witness')
                require(verified['result'] == 'PASS', 'owned_representation_independent_verification_failed')
                require(case_inventory(parent) == original, 'owned_representation_parent_changed')
                try: auth.consume(raw, policy_raw, context)
                except FileExistsError: pass
                else: raise ValueError('owned_representation_replay_accepted')
                summary['validations'].append({'slot': slot, 'request_id': auth.decode(raw, auth.contract.REQUEST_LIMIT)['candidate']['request_id'],
                    'audit': str(audit), 'verification': verified, 'witness': witness, 'replay_refused': True,
                    'wrong_parent_and_digest_refused': True, 'parent_unchanged': True})
            refused = matrix/'unknown-stop-must-not-publish'
            try: quarantine_publish(refused, [], stopped=None)
            except ValueError: require(not refused.exists(), 'owned_representation_unknown_stop_output')
            else: raise ValueError('owned_representation_unknown_stop_published')
            require(auth.canonical(auth.capture(context['profile'])) == auth.canonical(context), 'owned_representation_final_context')
            summary.update(result='PASS', unknown_stop_publication_refused=True)
            validation_raw = auth.canonical(summary)
            with auth.fs.root_directory(matrix) as fd: auth.fs.exclusive(fd, 'validation.json', validation_raw)
            ready_raw = new_readiness(context, validation_raw); auth.install_readiness(ready_raw, context); ready_installed = True
            smokes = []
            for mode in ['source', 'installed']:
                run_client(job, nonce, selected, mode, 'request', context, slot='smoke')
                raw, parent, original = owned_request(job, nonce, selected, mode, 'smoke')
                policy_raw = auth.make_policy(context, [raw], mode='explicit-source-analysis', ready=ready_raw)
                auth.install_policy(policy_raw, context); auth.issue(raw, policy_raw, context)
                report, audit = execute(raw, policy_raw); require(report['result'] == 'PASS', 'owned_representation_smoke_execution')
                owned_success(report, selected, nonce)
                exported = publish(raw)
                client = run_client(job, nonce, selected, mode, 'import', context, slot='smoke')
                require(case_inventory(parent) == original, 'owned_representation_smoke_parent_changed')
                sidecar = client_command(job, nonce, selected, mode, 'import', slot='smoke')['workspace']/'sidecar-smoke/result'
                require(read(sidecar, 'request.json', auth.contract.REQUEST_LIMIT) == raw and
                        auth.digest(read(sidecar, 'receipt.json', auth.contract.RECEIPT_LIMIT)) == exported['receipt_sha256'],
                        'owned_representation_smoke_sidecar_binding')
                receipt = auth.contract.validate_receipt(read(sidecar, 'receipt.json', auth.contract.RECEIPT_LIMIT),
                    auth.contract.validate_request(raw, auth.decode(raw, auth.contract.REQUEST_LIMIT)['candidate']['created_at']), auth.digest(raw))
                for item in receipt['artifacts']:
                    require(auth.digest(read(sidecar, item['stored_as'], 1024)) == item['sha256'], 'owned_representation_smoke_sidecar_output')
                try: auth.consume(raw, policy_raw, context)
                except FileExistsError: pass
                else: raise ValueError('owned_representation_smoke_replay_accepted')
                smokes.append({'mode': mode, 'request_id': exported['request_id'], 'export': exported, 'client': client,
                               'original_unchanged': True, 'replay_refused': True})
            acceptance = auth.canonical({'result': 'PASS', 'job': job, 'profile': context['profile'],
                'matrix_sha256': auth.digest(validation_raw), 'readiness_sha256': auth.digest(ready_raw),
                'smokes': smokes, 'real_source_grants_issued': 0})
            with auth.fs.root_directory(matrix) as fd: auth.fs.exclusive(fd, 'acceptance.json', acceptance)
            value = {'schema': 'paw-s14-representation-owned-acceptance-v1', 'result': 'PASS', 'job': job,
                'profile': context['profile'], 'context_sha256': auth.digest(auth.canonical(context)),
                'readiness_sha256': auth.digest(ready_raw), 'matrix_sha256': auth.digest(validation_raw),
                'acceptance_sha256': auth.digest(acceptance)}
            publish_reader_tree(matrix)
            with auth.store() as fd:
                auth.fs.exclusive(fd, 'acceptance-'+selected+'-'+value['context_sha256']+'-'+value['readiness_sha256']+'.json', auth.canonical(value))
            record.update(result='PASS', profile=selected, cases=8, vm_started=True, matrix=str(matrix),
                          readiness_sha256=auth.digest(ready_raw), matrix_sha256=auth.digest(validation_raw))
            completed = True
        record['runtime_sha256'] = auth.digest(auth.canonical(runtime))
    except Exception as error:
        record.update(result='FAIL', error=str(error), traceback=traceback.format_exc(), diagnostic=failure_diagnostic(error))
    finally:
        if ready_installed and not completed:
            with auth.store() as fd:
                try: os.unlink('readiness-'+auth.digest(ready_raw)+'.json', dir_fd=fd)
                except FileNotFoundError: pass
                os.fsync(fd)
            record['new_readiness_revoked'] = True
        with auth.fs.root_directory(folder) as fd: write_state(fd, 'result.json', record)
    print(json.dumps({'result': record['result'], 'job': job, 'profile': selected,
                      'diagnostic': record.get('diagnostic'), 'backend_diagnostics': record.get('backend_diagnostics'),
                      'real_samples_executed': 0}), flush=True)
    require(record['result'] == 'PASS', 'owned_representation_recipe_failed')
