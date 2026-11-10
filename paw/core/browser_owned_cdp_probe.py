"""Fixed Root-owned no-NIC CDP probe from an immutable reviewed release.

Not an online launcher. Only generated owned fixture bytes enter a disposable
guest. No real source, DNS, public routing, permission or grant is accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid


def require(value,reason):
    if not value:raise ValueError(reason)


# Fixed, already stopped synthetic run. The operator never supplies a selector.
_PRIOR_JOB = '018f2a1ed09f44ffa5b2ba37fb8f8138'
_PRIOR_RELEASE = '4ba02fd14699e7ee5f35bfdef36f6250f494f02f'
_PRIOR_MANIFEST = 'd61fe9562f32fb8686af1f462507901aea3bd83fcb39517da44bcb079691ba6a'
_PRIOR_AUDIT = 'owned-cdp-217ae4a04d44467585c511c8164b372e'
_PROGRAMS = ('browser_cdp.py', 'browser_owned_cdp_guest.py', 'browser_owned_cdp_probe.py')
_FAILURE_CODES = frozenset({
    'owned_cdp_probe_failed_no_publication', 'owned_cdp_external_poll_deadline',
    'owned_cdp_real_guest_probe_failed', 'owned_cdp_exact_browser', 'owned_cdp_guest_start',
    'owned_cdp_owner_result_path', 'owned_cdp_unexpected_owner_exit_blocks_publication',
    'owned_cdp_external_stop_or_host_restore', 'guest_channel_deadline', 'unexpected_readiness',
    'unexpected_response', 'frame_complexity', 'frame_nonfinite', 'owned_cdp_pipe_eof',
    'owned_whole_deadline', 'owned_actual_js_or_sandbox_missing', 'owned_guest_writers_alive',
    'owned_chrome_exited', 'owned_network_changed', 'owned_stderr_budget', 'owned_netlog_budget',
    'guest_navigation_failed', 'guest_browser_lost', 'guest_command_failed', 'cdp_pipe_truncated',
})


def _failure_code(value):
    if value is None:
        return None
    if type(value) is str:
        code = value.rsplit(':', 1)[-1]
        if code in _FAILURE_CODES:
            return code
    return 'unclassified'


def _serial_progress(raw):
    from gate_channel import validate_frame
    result = {'ready': False, 'started': False, 'last_poll': None, 'terminal': None,
              'traceback_seen': False, 'traceback_reason': None}
    for line in raw.split(b'\n'):
        line = line.removesuffix(b'\r')
        if line == b'Traceback (most recent call last):':
            result['traceback_seen'] = True
        elif result['traceback_seen'] and len(line) <= 256 and line.startswith((b'ValueError: ', b'TimeoutError: ')):
            code = _failure_code(line.decode('ascii', errors='replace').replace(': ', ':', 1))
            if code != 'unclassified':
                result['traceback_reason'] = code
        if not line.startswith(b'PAW14 ') or len(line) > 65536:
            continue
        try:
            frame = validate_frame(json.loads(line[6:]))
        except (ValueError, UnicodeError, RecursionError):
            continue
        if frame == {'ready': True, 'network_interfaces': ['lo']}:
            result['ready'] = True
        data = frame.get('data')
        if frame.get('ok') is not True or type(data) is not dict:
            continue
        if data.get('started') is True:
            result['started'] = True
        if data.get('done') is False:
            stage = data.get('stage')
            result['last_poll'] = stage if stage in ('configuring', 'running', 'snapshot', 'snapshot_ready') else 'other'
        if data.get('done') is True:
            status = data.get('status')
            result['terminal'] = {
                'status': status if status in ('completed', 'failed', 'cancelled') else 'other',
                'error': _failure_code(data.get('error')),
                'writers_stopped': data.get('writers_stopped') is True,
            }
    return result


def previous_owned_cdp_failure():
    """Publish finite observations from the fixed stopped synthetic job only."""
    from one_use_authorization import read, root_directory
    from vm_operator_host import private_json
    from vm_release_storage import verify

    require(os.geteuid() == 0, 'owned_cdp_historical_root_only')
    try:
        with root_directory(Path('/var/lib/paw-vm/jobs') / _PRIOR_JOB) as fd:
            worker = private_json(fd, 'result.json')
    except FileNotFoundError:
        return {'available': False, 'job': _PRIOR_JOB}

    capture = worker.get('owned_mail_capture')
    require(type(capture) is dict and capture.get('status') == 'completed' and
            worker.get('result') == 'FAIL' and worker.get('job') == _PRIOR_JOB and
            worker.get('release_sha') == _PRIOR_RELEASE and worker.get('recipe') == 'browser-owned-v1' and
            type(worker.get('real_samples_executed')) is int and worker['real_samples_executed'] == 0 and
            worker.get('plain_http_probe_result') == 'PASS' and 'owned_cdp_probe' not in worker and
            'returncode' not in worker, 'owned_cdp_historical_worker_binding')
    with root_directory(Path('/opt/paw-vm/releases')) as fd:
        manifest, _ = verify(fd, _PRIOR_RELEASE, _PRIOR_MANIFEST)
    programs = {name: manifest['files']['paw/core/' + name]['sha256'] for name in _PROGRAMS}
    with root_directory(Path('/var/lib/paw-s14/control') / _PRIOR_AUDIT) as fd:
        raw = read(fd, 'results.json', 256 * 1024)
        try:
            serial = read(fd, 'owned-cdp-probe-serial.log', 2 * 1024**2)
        except FileNotFoundError:
            serial = None
    report = json.loads(raw)
    require(report.get('schema') == 'paw-owned-cdp-probe-v1' and report.get('job') == _PRIOR_JOB and
            report.get('release_sha') == _PRIOR_RELEASE and report.get('programs') == programs and
            report.get('result') in ('FAIL', 'PASS') and type(report.get('real_connections')) is int and
            type(report.get('actual_real_samples')) is int and report['actual_real_samples'] == report['real_connections'] == 0,
            'owned_cdp_historical_audit_binding')
    return {'available': True, 'job': _PRIOR_JOB, 'release_sha': _PRIOR_RELEASE,
            'worker_error': _failure_code(worker.get('error')), 'audit_result': report['result'],
            'worker_cleanup_failed': worker.get('cleanup_failed') is True,
            'error': _failure_code(report.get('error')), 'cleanup_error': _failure_code(report.get('cleanup_error')),
            'writers_stopped_attested': report.get('writers_stopped') is True,
            'host_restored_attested': report.get('host_restored') is True,
            'audit_sha256': hashlib.sha256(raw).hexdigest(),
            'serial': None if serial is None else _serial_progress(serial)}


def run_owned(job,release):
    require(os.geteuid()==0 and Path('/proc/self/attr/current').read_text().strip()=='unconfined',
            'owned_cdp_root_PID1_worker_only')
    require(type(job) is str and re.fullmatch('[0-9a-f]{32}',job) and
            type(release) is str and re.fullmatch('[0-9a-f]{40}',release),'owned_cdp_fixed_job_identity')
    repo=Path(__file__).resolve().parents[2]
    require(repo==Path('/opt/paw-vm/releases')/release,'owned_cdp_immutable_release_only')
    sys.path.insert(0,str(repo/'lab/s14'))
    import browser_authorization as auth
    from browser_vm import BrowserVM,BROWSER_BASE,BROWSER_META,validate_xml,LIMITS
    from browser_offline_adapter import input_media,available_memory
    from benign_guest_validation import BASE,digest
    from reader_export import publish_reader_tree
    context=auth.capture();auth.validate_context(context)
    programs={name:hashlib.sha256((repo/'paw/core'/name).read_bytes()).hexdigest()
        for name in _PROGRAMS}
    out=Path('/var/lib/paw-s14/control')/('owned-cdp-'+uuid.uuid4().hex)
    identifier=uuid.uuid4().hex;gate=None;vm=None;record={'schema':'paw-owned-cdp-probe-v1','result':'FAIL',
        'job':job,'release_sha':release,'programs':programs,'actual_real_samples':0,'real_connections':0,
        'purpose':'actual owned Chrome JS and private CDP pipes only; no TLS/public-network acceptance'}
    with auth.fs.execution_lock():
        require(shutil.disk_usage(BROWSER_BASE.parent).free>=10*1024**3 and
                available_memory()>=2*1024**3,'owned_cdp_resources')
        media=input_media(b'PAW fixed owned CDP probe only',identifier)
        gate=BrowserVM(argparse.Namespace(output=out),phase='owned_cdp',media=media,
            seed_config={'kind':'owned-cdp-probe-v1','nonce':identifier})
        gate.canary=out/'host-owned-canary.bin';gate.canary.write_bytes(os.urandom(32));gate.canary.chmod(0o600)
        canary=digest(gate.canary);before=gate.snapshot_host();started=time.monotonic()
        try:
            vm=gate.start('owned-cdp-probe')
            inspected=vm['channel'].call('inspect',seconds=8)
            require(inspected['network_interfaces']==['lo'] and inspected['chrome_version']==context['chrome_version'] and
                inspected['chrome_binary_sha256']==context['chrome_binary_sha256'],'owned_cdp_exact_browser')
            admitted=vm['channel'].call('start',seconds=8);require(admitted.get('started') is True,'owned_cdp_guest_start')
            end=time.monotonic()+20
            while time.monotonic()<end:
                result=vm['channel'].call('poll',seconds=5)
                if result.get('done') is True:break
                time.sleep(.05)
            else:raise ValueError('owned_cdp_external_poll_deadline')
            require(result.get('status')=='completed' and result.get('writers_stopped') is True and
                result.get('network_interfaces')==['lo'] and type(result.get('requests')) is int and
                2<=result['requests']<=32 and type(result.get('cdp_frames')) is int and result['cdp_frames']>0 and
                type(result.get('sandbox')) is dict and
                set(result['sandbox'])=={'renderer_seen','renderer_nnp','renderer_seccomp','renderer_pid_namespace','all_uids_nonroot'} and
                all(value is True for value in result['sandbox'].values()),'owned_cdp_real_guest_probe_failed')
            record.update(guest=result,actual_vm=vm['actual'],result='PASS')
        except Exception as error:record.update(result='FAIL',error=type(error).__name__+':'+str(error)[:1024])
        finally:
            try:
                stop=time.monotonic()
                if gate.active_vm is not None:gate.stop(gate.active_vm)
                record['stop_seconds']=time.monotonic()-stop
                require(vm is not None and type(vm.get('owner_result_path')) is str and
                    Path(vm['owner_result_path']).parent==gate.output,'owned_cdp_owner_result_path')
                with auth.fs.root_directory(gate.output) as fd:
                    owner=json.loads(auth.fs.read(fd,Path(vm['owner_result_path']).name,65536))
                require(type(owner) is dict and owner.get('reason')=='requested_stop' and
                    owner.get('connection_closed') is True and owner.get('vm_uuid')==vm['node']['uuid'],
                    'owned_cdp_unexpected_owner_exit_blocks_publication')
                record['owner_result']=owner
                require(record['stop_seconds']<12 and not gate.connection.listAllDomains(0) and
                    before==gate.snapshot_host() and digest(BASE)==auth.fs.IMAGE_SHA256 and
                    digest(BROWSER_BASE)==context['image_sha256'] and digest(gate.canary)==canary and
                    auth.capture()==context,'owned_cdp_external_stop_or_host_restore')
                record.update(writers_stopped=True,host_restored=True,images_unchanged=True,source_freeze_unchanged=True)
            except Exception as error:record.update(result='FAIL',cleanup_error=str(error))
            gate.connection.close();record['elapsed_seconds']=time.monotonic()-started
            gate.report.update(record)
            (out/'results.json').write_bytes(auth.canonical(gate.report))
        require(record['result']=='PASS','owned_cdp_probe_failed_no_publication')
        # Raw VM audits remain Root-private. Only publish this protected
        # producer attestation after verified external stop and host restore.
        published=Path('/var/lib/paw-vm-exports')/('owned-cdp-'+job)
        with auth.fs.root_directory(published.parent):pass
        published.mkdir(mode=0o700)
        attestation={'schema':'paw-owned-cdp-attestation-v1','result':'PASS','job':job,'release_sha':release,
            'programs':programs,'context_sha256':hashlib.sha256(auth.canonical(context)).hexdigest(),
            'protected_audit_sha256':hashlib.sha256((out/'results.json').read_bytes()).hexdigest(),
            'vm_uuid':record['actual_vm']['uuid'],'qemu_limits':dict(LIMITS),'guest':record['guest'],
            'host_restored':True,'writers_stopped':True,'stop_seconds':record['stop_seconds'],
            'owner_disposition':{k:record['owner_result'][k] for k in ['reason','connection_closed','vm_uuid']},
            'real_samples':0,'real_connections':0,'meaning':record['purpose'],
            'trust':'Root producer verification; ordinary reader does not independently reread protected raw VM audits'}
        (published/'attestation.json').write_bytes(auth.canonical(attestation));publish_reader_tree(published)
        return {'result':'PASS','attestation':str(published/'attestation.json'),'scope':record['purpose']}
