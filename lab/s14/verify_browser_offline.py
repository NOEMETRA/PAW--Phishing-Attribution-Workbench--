"""Read-only browser custody reconciliation; opaque outputs are never rendered."""
import json
import math
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import browser_authorization as auth
from browser_vm import validate_xml, LIMITS
from verify_granted_offline import regular
from verify_synthetic_gate import verify_sources, REQUIRED_SOURCES
from gw_quarantine import validate_records

require = auth.require


def load(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_browser_audit_key'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def verify_single(root, *, production=True):
    root = Path(root); require(root.is_dir() and not root.is_symlink(), 'browser_audit_root')
    result_raw = regular(root/'results.json', 2*1024**2); report = load(result_raw)
    policy_raw = regular(root/'policy.json', 1024**2); policy = load(policy_raw); context = policy['context']
    require(report['result'] == 'PASS' and not report.get('cleanup_error') and
            all(report.get(k) is True for k in ['host_restored', 'base_unchanged', 'host_canary_unchanged',
                'writers_stopped', 'source_freeze_unchanged', 'browser_image_unchanged']) and
            report['host_before'] == report['host_after'] and report['real_connections'] == 0,
            'browser_host_lifecycle')
    require(report['source_hashes'] == context['platform']['host']['source_hashes'], 'browser_source_context')
    verify_sources(root, report['source_hashes'], REQUIRED_SOURCES | {'browser_vm.py', 'browser_guest.py',
        'browser_policy.py', 'browser_authorization.py', 'browser_offline_adapter.py', 'verify_browser_offline.py'})
    certificate_raw = regular(root/'browser-image-certificate.json', 1024**2); certificate = auth.certificate(certificate_raw)
    require(auth.digest(certificate_raw) == context['image_certificate_sha256'] and
            certificate['image_sha256'] == context['image_sha256'] and
            certificate['guest']['chrome_binary_sha256'] == context['chrome_binary_sha256'] and
            certificate['guest']['chrome_version'] == context['chrome_version'], 'browser_image_provenance')
    ready = regular(root/'readiness.json', 65536) if policy['mode'] == 'sample-analysis' else None
    if production: require(policy['mode'] == 'sample-analysis' and ready is not None, 'browser_production_readiness')
    require(len(report['runs']) == len(report['vms']) == 1, 'browser_single_job')
    run = report['runs'][0]; vm = report['vms'][0]; rid = run['request_id']
    require(type(rid) is str and re.fullmatch('[0-9a-f]{32}', rid), 'browser_request_id')
    copied = root/'authority-copy'/rid
    require(copied.is_dir() and not copied.is_symlink() and
            {p.name for p in copied.iterdir()} == {'candidate.json', 'grant.json', 'consumed.json'}, 'browser_authority_copy')
    raw = regular(copied/'candidate.json', auth.MAX_FRAME); grant_raw = regular(copied/'grant.json', 4096)
    consumed_raw = regular(copied/'consumed.json', 4096); grant = load(grant_raw); ledger = load(consumed_raw)
    require(grant_raw == auth.canonical(grant) and consumed_raw == auth.canonical(ledger), 'browser_canonical_authority')
    when = run['admitted_at']; require(type(when) is int, 'browser_admission_clock')
    summary, frame, source = auth.validate_binding(raw, grant, policy_raw, context, ready, now=when)
    require(summary['request_id'] == rid and run['candidate_frame_sha256'] == auth.digest(raw) and
            run['grant_sha256'] == auth.digest(grant_raw) and run['policy_sha256'] == auth.digest(policy_raw) and
            run['execution_purpose'] == policy['mode'] and run['consumption'] == ledger and
            ledger == {'schema': 'paw-s14-browser-consumed-v1', 'request_id': rid, 'frame_sha256': auth.digest(raw),
                'grant_sha256': auth.digest(grant_raw), 'policy_sha256': auth.digest(policy_raw), 'consumed_at': ledger['consumed_at']} and
            type(ledger['consumed_at']) is int and frame['created_at'] <= ledger['consumed_at'] <= when < grant['expires_at'],
            'browser_execution_authority')
    expected = {'profile': frame['profile'], 'job_id': 'html-'+rid, 'parent_sha256': frame['case_reference_sha256'],
                'source_sha256': frame['source']['sha256'], 'source_bytes': len(source),
                'operator_authorization': 'root-browser-hash-grant-v1',
                'created_at': frame['created_at'], 'expires_at': frame['expires_at']}
    require(run['job'] == expected and run['job_sha256'] == auth.digest(auth.canonical(expected)) and
            load(regular(root/'admissions'/('html-'+rid+'.json'), 4096)) == expected, 'browser_job_binding')
    actual = vm['actual']; uid = vm['uuid']
    require(run['vm_uuid'] == uid == actual['uuid'] and vm['label'] == 'html-'+rid and
            type(actual['pid']) is int and actual['pid'] > 1 and type(actual['pid_identity']) is str and
            actual['pid_identity'].isdecimal(), 'browser_vm_identity')
    require(vm['stopped'] is True and run['writers_stopped'] is True and
            run['stop_seconds'] == vm['stop_seconds'] and type(vm['stop_seconds']) in {int, float} and
            math.isfinite(vm['stop_seconds']) and 0 <= vm['stop_seconds'] < 12, 'browser_known_stop')
    require(actual['limits'] == LIMITS and actual['apparmor'].startswith('libvirt-') and '(enforce)' in actual['apparmor'] and
            'Seccomp:\t2' in vm['host_status'] and
            actual['qemu_binary_sha256'] == context['platform']['qemu_binary_sha256'] and
            actual['memory_merge_disabled'] is True and vm['fsize_limit'] == 256*1024**2 and
            vm['overlay_bytes'] <= vm['fsize_limit'], 'browser_qemu_controls')
    status = dict(line.split(':', 1) for line in vm['host_status'].splitlines() if ':' in line)
    require(all(int(v) > 0 for v in status['Uid'].split()), 'browser_qemu_nonroot')
    xml = ET.fromstring(regular(root/('html-'+rid+'-domain.xml'), 65536)); validate_xml(xml)
    require(xml.findtext('uuid') == uid and xml.find('defaultiothread').get('thread_pool_max') == '8', 'browser_xml_identity')
    dac = xml.findtext('seclabel[@model="dac"]/label') or ''
    require(len(dac.split(':')) == 2 and all(v.startswith('+') and v[1:].isdigit() and int(v[1:]) > 0 for v in dac.split(':')),
            'browser_xml_nonroot_dac')
    owner = load(regular(root/('html-'+rid+'-owner-result.json'), 65536))
    require(run['owner_result'] == owner and owner['vm_uuid'] == uid and owner['reason'] == 'requested_stop' and
            owner['connection_closed'] is True, 'browser_owner_stop')
    inspection = run['guest_inspection']; admission = run['guest_admission']
    require(inspection == {'chrome_version': context['chrome_version'], 'chrome_binary_sha256': context['chrome_binary_sha256'],
            'kernel_release': '6.8.0-147-generic', 'network_interfaces': ['lo'], 'prior_marker_absent': True} and
            admission['started'] is True and admission['prior_marker_absent'] is True and
            admission['source_sha256'] == frame['source']['sha256'] and admission['job_sha256'] == run['job_sha256'] and
            admission['job_limits'] == {'memory.max': str(512*1024**2), 'memory.swap.max': '0', 'pids.max': '256'},
            'browser_guest_image_or_admission')
    outcome = run['outcome']; require(outcome['done'] is True and outcome['writers_stopped'] is True and
            type(outcome['status']) is str and outcome['status'] in auth.contract.STATUSES and
            outcome['events']['pids.current'] == '0' and type(outcome['returncode']) is int, 'browser_guest_outcome')
    sandbox = outcome['sandbox']
    require(type(sandbox) is dict and set(sandbox) == {'renderer_seen', 'renderer_nnp', 'renderer_seccomp',
            'renderer_pid_namespace', 'all_uids_nonroot'} and all(type(v) is bool for v in sandbox.values()), 'browser_sandbox_evidence')
    if outcome['status'] == 'completed': require(all(sandbox.values()), 'browser_completed_without_sandbox')
    records = outcome['records']; validate_records(records)
    quarantine = root/('html-'+rid+'-quarantine'); manifest = run['quarantine']
    require(quarantine.is_dir() and not quarantine.is_symlink() and
            len(records) == len(manifest) == (0 if outcome['status'] == 'cancelled' else 1) and
            {p.name for p in quarantine.iterdir()} == {v['stored_as'] for v in manifest}, 'browser_quarantine_inventory')
    for index, item in enumerate(manifest):
        require(item['stored_as'] == f'artifact-{index:02d}.bin' and records[index]['name'] == 'observations.json' and
                item['source_name'] == records[index]['name'], 'browser_ordinal_output')
        data = regular(quarantine/item['stored_as'], 1024)
        require(data == bytes.fromhex(records[index]['bytes_hex']) and len(data) == item['bytes'] and
                auth.digest(data) == item['sha256'], 'browser_output_digest')
    return {'result': 'PASS', 'jobs': 1, 'sources': len(report['source_hashes']), 'mode': policy['mode'],
            'meaning': 'local execution/custody; no malware or attribution verdict', 'real_connections': 0}
