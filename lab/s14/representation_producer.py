"""Root representation execution/publication library; no CLI or recipe.

Existing installed grants only; no issuance/readiness installation or ordinary
user-selected Root command. Actual owned recipe/I08 acceptance is separate.
"""
import argparse
import os
from pathlib import Path
import subprocess
import time
import traceback

import representation_authorization as auth
import representation_adapter as adapter
from browser_vm import BROWSER_META
from browser_offline_adapter import input_media
from benign_guest_validation import BASE, digest
from verify_representation import read, verify_single
from reader_export import publish_reader_tree

CONTROL = Path('/var/lib/paw-s14/control')
STATE = Path('/var/lib/paw-vm')
RELEASES = Path('/opt/paw-vm/releases')
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


def execute(raw, policy_raw, *, cancel=False):
    root_only(); summary = auth.inspect(raw); profile = summary['profile']; identifier = summary['request_id']
    context = auth.capture(profile); _, checked, request, source = auth.load_bound(raw, policy_raw, context)
    require(checked == summary, 'representation_producer_request_changed')
    policy, ready = auth.installed(policy_raw, context)
    output = audit_path(identifier)
    with auth.fs.root_directory(CONTROL): pass
    current = adapter.job(request); job_sha = auth.digest(auth.canonical(current))
    image = None
    if profile == adapter.HTML:
        image = input_media(source, identifier)
        gate = adapter.BrowserVM(argparse.Namespace(output=output), phase='job', media=image,
            seed_config={'source_sha256': summary['source_sha256'], 'source_bytes': len(source),
                         'job_sha256': job_sha, 'request_id': identifier})
    else:
        require(profile == adapter.PYTHON, 'representation_producer_profile')
        gate = adapter.HashGate(argparse.Namespace(output=output)); gate.active_vm = None
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
        gate.report.update(result='FAIL', error=str(error), traceback=traceback.format_exc())
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
        except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error))
        gate.connection.close(); save_results(output, gate.report)
    if gate.report['result'] == 'PASS':
        try:
            verified = verify_single(output, production=policy['mode'] == 'explicit-source-analysis')
            with auth.fs.root_directory(output) as fd:
                auth.fs.exclusive(fd, 'independent-verification.json', auth.canonical(verified))
        except Exception as error:
            gate.report.update(result='FAIL', verification_error=str(error)); save_results(output, gate.report)
    return gate.report, output


def publish(raw):
    """Only a current protected analysis-mode audit may enter the client export."""
    root_only(); request = auth.contract.validate_request(raw, auth.decode(raw)['candidate']['created_at'])
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
    with auth.fs.root_directory(auth.contract.EXPORT_ROOT) as parent:
        os.mkdir(identifier, mode=0o700, dir_fd=parent); os.fsync(parent)
    with auth.fs.root_directory(destination) as fd:
        auth.fs.exclusive(fd, 'request.json', raw); auth.fs.exclusive(fd, 'receipt.json', receipt_raw)
        for item in receipt['artifacts']:
            blob = read(output, run['job']['job_id']+'-quarantine/'+item['stored_as'], 1024)
            require(auth.digest(blob) == item['sha256'] and len(blob) == item['bytes'], 'representation_publish_opaque_digest')
            auth.fs.exclusive(fd, item['stored_as'], blob)
    publish_reader_tree(destination)
    return {'request_id': identifier, 'result': 'PASS', 'export': str(destination), 'receipt_sha256': auth.digest(receipt_raw)}
