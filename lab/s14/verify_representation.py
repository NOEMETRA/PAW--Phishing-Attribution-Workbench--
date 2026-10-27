"""Independent opaque representation execution custody verifier.

No publication/authority installation; offline copies are custody observations,
not Root provenance, remote attestation or payload classification.
"""
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import xml.etree.ElementTree as ET

import representation_authorization as auth
from representation_adapter import job, PYTHON, HTML
from verify_hash_offline import vm_evidence as python_vm_evidence
from browser_vm import validate_xml, LIMITS
from browser_offline_adapter import validate_outcome
from verify_synthetic_gate import REQUIRED_SOURCES
from gw_quarantine import validate_records

require = auth.require


def read(root, relative, maximum):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and path.as_posix() == relative and
            all(re.fullmatch('[A-Za-z0-9_.-]{1,128}', p) and p not in {'.', '..'} for p in path.parts),
            'representation_audit_relative_path')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return auth.contract.shared._read_regular(path.name, maximum, directory_fd=fd)
    finally: os.close(fd)


def inventory(root):
    result = set(); budget = [0]
    def walk(fd, prefix='', depth=0):
        require(depth <= 12, 'representation_snapshot_depth')
        names = os.listdir(fd); budget[0] += len(names)
        require(budget[0] <= 4096, 'representation_snapshot_entries')
        for name in names:
            require(re.fullmatch('[A-Za-z0-9_.-]{1,128}', name) and name not in {'.', '..'}, 'representation_snapshot_name')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False); relative = prefix+name
            if stat.S_ISDIR(info.st_mode):
                result.add(relative+'/')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try: walk(child, relative+'/', depth+1)
                finally: os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'representation_snapshot_regular_unlinked')
                result.add(relative)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: walk(fd)
    finally: os.close(fd)
    return result


def verify_snapshot(root, context):
    snapshot = Path(root)/'runtime-snapshot'
    raw = read(snapshot, 'release.json', auth.storage.MAX_MANIFEST)
    value = auth.decode(raw, auth.storage.MAX_MANIFEST)
    manifest = auth.storage.manifest(raw, value['release_sha'])
    require(context['runtime_sources_sha256'] == auth.digest(auth.storage.canonical(manifest['files'])),
            'representation_runtime_source_context')
    proof = read(snapshot, 'proof.json', 128*1024)
    require(auth.digest(proof) == manifest['proof_sha256'], 'representation_snapshot_proof_digest')
    parsed = auth.decode(proof)
    require(parsed.get('repository') == auth.storage.REPOSITORY and parsed.get('head_sha') == manifest['head_sha'] and
            parsed.get('merge_sha') == manifest['release_sha'], 'representation_snapshot_proof_identity')
    parents = {'/'.join(auth.storage.source_path(name)[:n])+'/' for name in manifest['files']
               for n in range(1, len(auth.storage.source_path(name)))}
    require(inventory(snapshot) == set(manifest['files']) | parents | {'release.json', 'proof.json'}, 'representation_snapshot_inventory')
    for name, metadata in manifest['files'].items():
        raw = read(snapshot, name, auth.storage.MAX_FILE)
        require(len(raw) == metadata['bytes'] and auth.digest(raw) == metadata['sha256'], 'representation_snapshot_source_changed')
    return {name.rsplit('/', 1)[1]: row['sha256'] for name, row in manifest['files'].items() if name.startswith('lab/s14/')}


def _html_vm(root, vm, context):
    backend = context['backend']; actual = vm['actual']; uid = vm['uuid']
    require(type(uid) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', uid) and
            actual['uuid'] == uid and type(actual['pid']) is int and actual['pid'] > 1 and
            type(actual['pid_identity']) is str and actual['pid_identity'].isdecimal(), 'representation_html_vm_identity')
    require(actual['limits'] == LIMITS and actual['apparmor'].startswith('libvirt-') and '(enforce)' in actual['apparmor'] and
            'Seccomp:\t2' in vm['host_status'] and actual['qemu_binary_sha256'] == backend['platform']['qemu_binary_sha256'] and
            actual['memory_merge_disabled'] is True and vm['fsize_limit'] == 256*1024**2 and
            vm['overlay_bytes'] <= vm['fsize_limit'], 'representation_html_effective_controls')
    status = dict(line.split(':', 1) for line in vm['host_status'].splitlines() if ':' in line)
    require(all(int(v) > 0 for v in status['Uid'].split()), 'representation_html_nonroot')
    xml = ET.fromstring(read(root, vm['label']+'-domain.xml', 65536)); validate_xml(xml)
    require(xml.findtext('uuid') == uid and xml.find('defaultiothread').get('thread_pool_max') == '8', 'representation_html_xml_identity')
    dac = (xml.findtext('seclabel[@model="dac"]/label') or '').split(':')
    require(len(dac) == 2 and all(v.startswith('+') and v[1:].isdecimal() and int(v[1:]) > 0 for v in dac),
            'representation_html_dac')
    certificate_raw = read(root, 'browser-image-certificate.json', 1024**2)
    certificate = auth.html_backend.certificate(certificate_raw)
    require(auth.digest(certificate_raw) == backend['image_certificate_sha256'] and
            certificate['image_sha256'] == backend['image_sha256'] and
            certificate['guest']['chrome_binary_sha256'] == backend['chrome_binary_sha256'] and
            certificate['guest']['chrome_version'] == backend['chrome_version'], 'representation_html_image_provenance')


def job_inventory(root, rid, label, profile, mode):
    authority = {rid+'/', *(rid+'/'+name for name in ['request.json', 'grant.json', 'consumed.json'])}
    require(inventory(root/'authority-copy') == authority, 'representation_complete_authority_inventory')
    require(inventory(root/'admissions') == {label+'.json'}, 'representation_complete_admission_inventory')
    # Both existing VM backends write one descriptor, supervisor/serial files
    # and the runtime XML. Every job-scoped name belongs to the reported job;
    # unrelated evidence cannot be silently omitted from a single-run audit.
    files = {label+suffix for suffix in ['-control.json', '-ready.json', '-owner.json',
        '-owner-result.json', '-owner.log', '-domain.xml', '-serial.log', '-quarantine']}
    files.add(('authorized-' if profile == PYTHON else 'authorized-browser-')+label+'-extractor.xml')
    files |= {'results.json', 'policy.json', 'maintenance.json', 'host-owned-canary.bin',
        'independent-verification.json', 'authority-copy', 'admissions', 'sources', 'runtime-snapshot'}
    if profile == HTML: files.add('browser-image-certificate.json')
    if mode == 'explicit-source-analysis': files.add('readiness.json')
    require(set(os.listdir(root)) <= files, 'representation_complete_job_inventory')


def verify_single(root, *, production=False):
    root = Path(root)
    report = auth.decode(read(root, 'results.json', 2*1024**2), 2*1024**2)
    policy_raw = read(root, 'policy.json', 256*1024); policy = auth.decode(policy_raw); context = policy['context']
    require(report.get('result') == 'PASS' and not report.get('cleanup_error') and
            all(report.get(k) is True for k in ['host_restored', 'base_unchanged', 'host_canary_unchanged',
                'writers_stopped', 'source_freeze_unchanged']) and report['host_before'] == report['host_after'] and
            type(report['real_connections']) is int and report['real_connections'] == 0, 'representation_host_lifecycle')
    require(len(report['runs']) == len(report['vms']) == 1, 'representation_single_run')
    run, vm = report['runs'][0], report['vms'][0]; rid = run['request_id']
    require(type(rid) is str and re.fullmatch('[0-9a-f]{32}', rid), 'representation_audit_request_id')
    copied = 'authority-copy/'+rid
    require(inventory(root/copied) == {'request.json', 'grant.json', 'consumed.json'}, 'representation_authority_inventory')
    raw = read(root, copied+'/request.json', auth.contract.REQUEST_LIMIT)
    grant_raw = read(root, copied+'/grant.json', 8192); grant = auth.decode(grant_raw, 8192)
    ledger_raw = read(root, copied+'/consumed.json', 8192); ledger = auth.decode(ledger_raw, 8192)
    require(grant_raw == auth.canonical(grant) and ledger_raw == auth.canonical(ledger), 'representation_authority_canonical')
    when = run['admitted_at']; require(type(when) is int, 'representation_actual_admission_clock')
    ready = read(root, 'readiness.json', 65536) if policy['mode'] == 'explicit-source-analysis' else None
    if production: require(ready is not None and policy['mode'] == 'explicit-source-analysis', 'representation_analysis_readiness')
    summary, request, source = auth.validate_binding(raw, grant, policy_raw, context, ready, now=when)
    require(ledger == {'schema': 'paw-s14-representation-consumed-v1', 'request_id': rid,
        'request_sha256': auth.digest(raw), 'grant_sha256': auth.digest(grant_raw), 'policy_sha256': auth.digest(policy_raw),
        'context_sha256': auth.digest(auth.canonical(context)), 'consumed_at': ledger['consumed_at']} and
        type(ledger['consumed_at']) is int and request['candidate']['created_at'] <= ledger['consumed_at'] <= when < grant['expires_at'],
        'representation_actual_consumption')
    require(summary['request_id'] == rid and run['consumption'] == ledger and
            run['request_sha256'] == summary['request_sha256'] and run['candidate_sha256'] == summary['candidate_sha256'] and
            run['selection_binding_sha256'] == summary['selection_binding_sha256'] and
            run['grant_sha256'] == auth.digest(grant_raw) and run['policy_sha256'] == auth.digest(policy_raw) and
            run['context_sha256'] == auth.digest(auth.canonical(context)), 'representation_run_authority')
    expected = job(request); label = expected['job_id']; job_sha = auth.digest(auth.canonical(expected))
    job_inventory(root, rid, label, context['profile'], policy['mode'])
    require(run['job'] == expected and run['job_sha256'] == job_sha and
            auth.decode(read(root, 'admissions/'+label+'.json', 65536), 65536) == expected and
            vm['label'] == label and run['vm_uuid'] == vm['uuid'], 'representation_guest_job_binding')
    seconds = vm['stop_seconds']
    require(vm['stopped'] is True and run['writers_stopped'] is True and run['stop_seconds'] == seconds and
            type(seconds) in {int, float} and math.isfinite(seconds) and 0 <= seconds < 12, 'representation_external_stop')
    backend = context['backend']; profile = context['profile']
    require(report['source_hashes'] == verify_snapshot(root, context), 'representation_snapshot_lab_inventory')
    host = backend['host'] if profile == PYTHON else backend['platform']['host']
    require(report['source_hashes'] == host['source_hashes'], 'representation_backend_source_context')
    required = REQUIRED_SOURCES | {'representation_authorization.py', 'representation_adapter.py', 'verify_representation.py'}
    require(required <= report['source_hashes'].keys() and
            inventory(root/'sources') == set(report['source_hashes']), 'representation_source_copy_inventory')
    for name, digest in report['source_hashes'].items():
        require(auth.digest(read(root, 'sources/'+name, auth.storage.MAX_FILE)) == digest,
                'representation_source_copy_changed')
    maintenance = read(root, 'maintenance.json', 65536)
    require(auth.digest(maintenance) == context['maintenance_sha256'], 'representation_maintenance_copy')
    auth.python_backend.validate_maintenance(maintenance, backend if profile == PYTHON else backend['platform'])
    owner = auth.decode(read(root, label+'-owner-result.json', 65536), 65536)
    require(owner == run['owner_result'] and owner.get('reason') == 'requested_stop' and
            owner.get('connection_closed') is True, 'representation_owner_stop')
    admission = run['guest_admission']
    require(admission['job_sha256'] == job_sha and admission['source_sha256'] == summary['source_sha256'] and
            admission['prior_marker_absent'] is True, 'representation_guest_admission')
    outcome = run['outcome']; status = outcome['status']; records = outcome['records']
    if profile == PYTHON:
        python_vm_evidence(root, vm, backend)
        ready_vm = auth.decode(read(root, label+'-ready.json', 65536), 65536)
        require(ready_vm['uuid'] == vm['uuid'] and ready_vm['pid'] == vm['actual']['pid'] and
                ready_vm['pid_identity'] == vm['actual']['pid_identity'], 'representation_python_owner_identity')
        require(type(status) is str and status in {'completed', 'failed', 'timeout', 'cancelled', 'output_budget'},
                'representation_python_outcome_status')
        if status != 'cancelled': require(outcome['done'] is True and outcome['writers_stopped'] is True and
                outcome['events']['pids.current'] == '0' and type(outcome['returncode']) is int, 'representation_python_guest_stop')
        require([v['name'] for v in records] == ([] if status == 'cancelled' else ['stdout.bin', 'stderr.bin']),
                'representation_python_output_inventory')
    else:
        require(profile == HTML, 'representation_audit_profile'); _html_vm(root, vm, context)
        require(owner.get('vm_uuid') == vm['uuid'] and report.get('browser_image_unchanged') is True,
                'representation_html_owner_or_image')
        require(run['guest_inspection'] == {'chrome_version': backend['chrome_version'],
            'chrome_binary_sha256': backend['chrome_binary_sha256'], 'kernel_release': '6.8.0-147-generic',
            'network_interfaces': ['lo'], 'prior_marker_absent': True} and admission['started'] is True and
            admission['job_limits'] == {'memory.max': str(512*1024**2), 'memory.swap.max': '0', 'pids.max': '256'},
            'representation_html_inspection_or_limits')
        validate_outcome(outcome)
    validate_records(records); quarantine = root/(label+'-quarantine'); manifest = run['quarantine']
    require(type(manifest) is list and len(manifest) == len(records) and
            inventory(quarantine) == {v['stored_as'] for v in manifest}, 'representation_quarantine_inventory')
    for index, item in enumerate(manifest):
        require(item['stored_as'] == f'artifact-{index:02d}.bin' and item['source_name'] == records[index]['name'],
                'representation_output_ordinal')
        blob = read(quarantine, item['stored_as'], 1024)
        require(blob == bytes.fromhex(records[index]['bytes_hex']) and len(blob) == item['bytes'] and
                auth.digest(blob) == item['sha256'], 'representation_output_digest')
    return {'result': 'PASS', 'jobs': 1, 'profile': profile, 'mode': policy['mode'], 'sources': len(report['source_hashes']),
            'request_sha256': auth.digest(raw), 'meaning': 'opaque execution/custody only; no origin, risk or attribution verdict'}
