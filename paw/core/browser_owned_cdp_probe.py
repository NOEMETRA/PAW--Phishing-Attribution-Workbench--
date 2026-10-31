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
        for name in ['browser_cdp.py','browser_owned_cdp_guest.py','browser_owned_cdp_probe.py']}
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
            'real_samples':0,'real_connections':0,'meaning':record['purpose'],
            'trust':'Root producer verification; ordinary reader does not independently reread protected raw VM audits'}
        (published/'attestation.json').write_bytes(auth.canonical(attestation));publish_reader_tree(published)
        return {'result':'PASS','attestation':str(published/'attestation.json'),'scope':record['purpose']}
