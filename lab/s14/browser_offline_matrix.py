"""Explicit root acceptance of finite fresh owned HTML; never real input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[1]))
import browser_authorization as auth
import browser_offline_operator as operator
from browser_vm import BrowserVM, validate_xml, LIMITS
from browser_validation_inputs import parse, frame, CASES
from verify_browser_offline import verify_single
from verify_granted_offline import regular
from verify_synthetic_gate import verify_sources, REQUIRED_SOURCES
from gw_quarantine import publish

require = auth.require
FAULTS = {'paused-refusal', 'owner-loss', 'protocol-loss'}


def fault_verification(output, raw, policy_raw, context, case, witness):
    """Reconcile failed execution, durable consumption and absent publication."""
    report = json.loads(regular(output/'results.json', 2*1024**2)); policy = json.loads(policy_raw)
    require(report['result'] == 'FAIL' and not report.get('cleanup_error') and
            all(report.get(k) is True for k in ['host_restored', 'base_unchanged', 'browser_image_unchanged',
                'host_canary_unchanged', 'source_freeze_unchanged', 'writers_stopped']) and
            report['host_before'] == report['host_after'] and report['real_connections'] == 0, 'browser_fault_host_integrity')
    require(report['source_hashes'] == context['platform']['host']['source_hashes'], 'browser_fault_sources')
    verify_sources(output, report['source_hashes'], REQUIRED_SOURCES | {'browser_vm.py', 'browser_offline_matrix.py', 'browser_guest.py'})
    summary = auth.inspect(raw, json.loads(raw)['created_at']); rid = summary['request_id']
    copied = output/'authority-copy'/rid
    require(regular(copied/'candidate.json', auth.MAX_FRAME) == raw and regular(output/'policy.json', 1024**2) == policy_raw,
            'browser_fault_frame_or_policy')
    grant_raw = regular(copied/'grant.json', 4096); grant = json.loads(grant_raw)
    ledger = json.loads(regular(copied/'consumed.json', 4096)); when = ledger['consumed_at']
    checked, candidate, source = auth.validate_binding(raw, grant, policy_raw, context, now=when)
    require(checked == summary and policy['mode'] == 'validation' and ledger == {
        'schema': 'paw-s14-browser-consumed-v1', 'request_id': rid, 'frame_sha256': auth.digest(raw),
        'grant_sha256': auth.digest(grant_raw), 'policy_sha256': auth.digest(policy_raw), 'consumed_at': when}, 'browser_fault_consumption')
    require(len(report['vms']) == 1 and not report['runs'], 'browser_fault_vm_count')
    vm = report['vms'][0]; actual = vm['actual']
    require(vm['label'] == 'html-'+rid and vm['uuid'] == actual['uuid'] == witness['vm_uuid'] and
            vm['stopped'] is True and type(vm['stop_seconds']) in {int, float} and 0 <= vm['stop_seconds'] < 12 and
            0 <= witness['fault_stop_seconds'] < 12, 'browser_fault_known_stop')
    require(actual['limits'] == LIMITS and actual['qemu_binary_sha256'] == context['platform']['qemu_binary_sha256'] and
            actual['memory_merge_disabled'] is True and actual['apparmor'].startswith('libvirt-') and
            '(enforce)' in actual['apparmor'] and 'Seccomp:\t2' in vm['host_status'] and
            vm['fsize_limit'] == 256*1024**2 and vm['overlay_bytes'] <= vm['fsize_limit'], 'browser_fault_controls')
    xml = ET.fromstring(regular(output/('html-'+rid+'-domain.xml'), 65536)); validate_xml(xml)
    require(xml.findtext('uuid') == vm['uuid'] and not (output/('html-'+rid+'-quarantine')).exists(), 'browser_fault_no_publication')
    require({'paused-refusal': 'owned_browser_paused_refusal', 'owner-loss': 'owned_browser_owner_loss',
             'protocol-loss': 'owned_browser_protocol_closed'}[case] in report['error'], 'browser_fault_reason')
    if case == 'paused-refusal': require(witness['paused_before_refusal'] is True, 'browser_paused_witness')
    else:
        admission = witness['guest_admission']; job = json.loads(regular(output/'admissions'/('html-'+rid+'.json'), 4096))
        require(admission['started'] is True and admission['source_sha256'] == summary['source_sha256'] and
                job['parent_sha256'] == summary['case_reference_sha256'] and job['source_sha256'] == auth.digest(source) and
                admission['job_sha256'] == auth.digest(auth.canonical(job)), 'browser_fault_after_start')
        if case == 'owner-loss': require(witness['owner_returncode'] == -9 and witness['owner_pid'] > 1, 'browser_owner_loss_witness')
        else: require(witness['serial_closed'] is True, 'browser_protocol_loss_witness')
    return {'result': 'PASS', 'scope': 'failed owned browser execution; known stop and no output', 'case': case}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True); parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--export', type=Path, required=True); args = parser.parse_args()
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined', 'root_PID1_browser_acceptance')
    raw_manifest = regular(args.manifest, 1024**2)
    require(auth.digest(raw_manifest) == args.expected_sha256, 'approved_owned_browser_manifest')
    inputs = parse(raw_manifest); context = auth.capture(); auth.validate_context(context); auth.initialize()
    policy_raw = auth.make_policy(context, sorted({v['source_sha256'] for v in inputs['inputs']}),
                                  validation_manifest_sha256=auth.digest(raw_manifest))
    auth.install_policy(policy_raw, context)
    output = Path('/var/lib/paw-s14/control')/('browser-acceptance-'+uuid.uuid4().hex)
    with auth.fs.root_directory(output.parent): pass
    output.mkdir(mode=0o700); (output/'approved-inputs.json').write_bytes(raw_manifest); (output/'policy.json').write_bytes(policy_raw)
    summary = {'result': 'FAIL', 'scope': 'owned HTML acceptance only; not production I08', 'context': context,
               'runs': [], 'actual_real_samples_executed': 0, 'i08_accepted': False, 'production_grants_enabled': False}
    try:
        for entry in inputs['inputs']:
            case = entry['case']; raw = frame(entry, inputs['nonce']); candidate = json.loads(raw)
            grant = auth.issue(raw, policy_raw, context); witness = {}; original = operator.BrowserVM
            class AcceptanceVM(BrowserVM):
                def start(self, label, boot=True):
                    vm = super().start(label, boot=case != 'paused-refusal'); witness['vm_uuid'] = vm['node']['uuid']
                    if case == 'positive':
                        try:
                            with auth.fs.execution_lock(): raise ValueError('live_execution_lock_not_exclusive')
                        except BlockingIOError: summary['live_busy_lock_refused'] = True
                    if case == 'paused-refusal':
                        witness['paused_before_refusal'] = self.connection.lookupByUUIDString(vm['node']['uuid']).state()[0] == self.libvirt.VIR_DOMAIN_PAUSED
                        witness['fault_at'] = time.monotonic(); raise ValueError('owned_browser_paused_refusal')
                    call = vm['channel'].call
                    def observed(operation, seconds=8):
                        if operation == 'poll' and case in {'owner-loss', 'protocol-loss'}:
                            witness['fault_at'] = time.monotonic()
                            if case == 'owner-loss':
                                witness['owner_pid'] = vm['owner'].pid; vm['owner'].kill(); vm['owner'].wait(timeout=3)
                                witness['owner_returncode'] = vm['owner'].returncode
                                raise ValueError('owned_browser_owner_loss')
                            channel = vm['channel']; channel.done = True; channel.thread.join(timeout=2)
                            require(not channel.thread.is_alive(), 'owned_protocol_reader_did_not_stop')
                            os.close(channel.serial.fd); channel.serial.fd = -1
                            channel.serial.close = channel.serial.log.close
                            witness['serial_closed'] = True; raise ValueError('owned_browser_protocol_closed')
                        value = call(operation, seconds=seconds)
                        if operation == 'start': witness['guest_admission'] = value
                        return value
                    vm['channel'].call = observed
                    return vm
                def stop(self, vm, kill=False):
                    value = super().stop(vm, kill=kill)
                    if 'fault_at' in witness: witness['fault_stop_seconds'] = time.monotonic()-witness['fault_at']
                    return value
            try:
                operator.BrowserVM = AcceptanceVM
                report, audit = operator.execute(raw, policy_raw, cancel=case == 'cancel')
            finally: operator.BrowserVM = original
            if case in FAULTS: verification = fault_verification(audit, raw, policy_raw, context, case, witness)
            else:
                require(report['result'] == 'PASS', 'owned_browser_execution_failed:'+case+':'+report.get('error', '')+report.get('verification_error', ''))
                verification = verify_single(audit, production=False); run = report['runs'][0]
                expected = {'positive': 'completed', 'script-error': 'completed', 'timeout': 'timeout', 'cancel': 'cancelled',
                            'overflow': 'output_budget', 'memory': 'memory_budget'}[case]
                require(run['outcome']['status'] == expected, 'owned_browser_outcome:'+case)
                if case in {'positive', 'script-error'}:
                    observations = json.loads(bytes.fromhex(run['outcome']['records'][0]['bytes_hex']))
                    require(observations['title'] == 'PAW-'+inputs['nonce'], 'owned_executed_DOM_title')
            try: auth.consume(raw, policy_raw, context)
            except FileExistsError: pass
            else: raise ValueError('owned_browser_global_replay_accepted')
            summary['runs'].append({'case': case, 'request_id': candidate['request_id'], 'audit': str(audit),
                                    'verification': verification, 'witness': witness, 'global_replay_refused': True})
            print('PASS owned browser / '+case, flush=True)
        refused = output/'unknown-stop-must-not-publish'
        try: publish(refused, [], stopped=None)
        except ValueError: require(not refused.exists(), 'unknown_stop_created_output')
        else: raise ValueError('unknown_stop_published')
        require(len(summary['runs']) == len(CASES) and summary.get('live_busy_lock_refused') is True and
                auth.capture() == context, 'owned_browser_final_context_or_inventory')
        summary.update(result='PASS', unknown_stop_publication_refused=True)
    except Exception as error: summary.update(result='FAIL', error=str(error), traceback=traceback.format_exc())
    finally:
        (output/'results.json').write_bytes(auth.canonical(summary))
        args.export.mkdir(parents=True, mode=0o700, exist_ok=False)
        shutil.copytree(output, args.export/'matrix')
        for run in summary['runs']: shutil.copytree(run['audit'], args.export/run['case'])
        for path in [args.export, *args.export.rglob('*')]: os.chown(path, 1000, 1000)
    print(json.dumps({'result': summary['result'], 'export': str(args.export), 'actual_real_samples_executed': 0}), flush=True)
    require(summary['result'] == 'PASS', 'owned_browser_acceptance_failed')


if __name__ == '__main__': main()
