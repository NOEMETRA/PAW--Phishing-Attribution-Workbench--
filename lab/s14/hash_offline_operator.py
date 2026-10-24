"""Explicit root execution of one already granted hash, never automatic issuance."""
import argparse,json,os,shutil,sys,traceback
from pathlib import Path

HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import hash_authorization as auth
from hash_offline_adapter import HashGate,run_hash_granted
from offline_candidate import require,MAX_FRAME
from verify_granted_offline import regular
from verify_hash_offline import verify_single
from benign_guest_validation import BASE,digest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True);parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--policy-sha256',required=True);parser.add_argument('--export',type=Path)
    args=parser.parse_args()
    require(os.geteuid()==0 and Path('/proc/self/attr/current').read_text().strip()=='unconfined','explicit_root_PID1_operator_required')
    require(shutil.disk_usage(BASE.parent).free>=10*1024**3,'host_disk_admission')
    raw=regular(args.candidate,MAX_FRAME);require(auth.digest(raw)==args.expected_sha256,'approved_frame_digest')
    require(len(args.policy_sha256)==64 and all(c in '0123456789abcdef' for c in args.policy_sha256),'policy_digest')
    with auth.store() as fd:policy_raw=auth.fs.read(fd,'policy-'+args.policy_sha256+'.json')
    require(auth.digest(policy_raw)==args.policy_sha256,'policy_digest_binding')
    context=auth.capture();grant_raw,summary,_,_=auth.load_bound(raw,policy_raw,context)
    policy,maintenance,ready=auth.installed(policy_raw,context)
    require(policy['mode']=='sample-analysis' and ready is not None,'reviewed_sample_mode_required')
    output=Path('/var/lib/paw-s14/control')/('hash-job-'+summary['request_id'])
    with auth.fs.root_directory(output.parent):pass
    gate=HashGate(argparse.Namespace(output=output));gate.active_vm=None
    gate.canary=output/'host-owned-canary.bin';gate.canary.write_bytes(os.urandom(32));gate.canary.chmod(0o600)
    canary=digest(gate.canary);before=gate.snapshot_host();gate.report.update(runs=[],vms=[],real_connections=0,scope=auth.SCOPE)
    (output/'policy.json').write_bytes(policy_raw);(output/'maintenance.json').write_bytes(maintenance);(output/'readiness.json').write_bytes(ready)
    authority_copy=output/'authority-copy'/summary['request_id'];authority_copy.mkdir(parents=True,mode=0o700)
    (authority_copy/'candidate.json').write_bytes(raw);(authority_copy/'grant.json').write_bytes(grant_raw)
    try:
        result=run_hash_granted(gate,raw,policy_raw);result['request_id']=summary['request_id']
        gate.report.update(runs=[result],result='PASS') # Infrastructure/custody, not payload benignness.
    except Exception as error:
        gate.report.update(result='FAIL',error=str(error),traceback=traceback.format_exc())
    finally:
        try:
            if gate.active_vm:gate.stop(gate.active_vm)
            require(not gate.connection.listAllDomains(0) and before==gate.snapshot_host(),'host_not_restored')
            require(digest(BASE)==gate.root_image_sha and digest(gate.canary)==canary and auth.capture()==context,'context_or_immutable_bytes_changed')
            gate.report.update(host_before=before,host_after=gate.snapshot_host(),host_restored=True,base_unchanged=True,
                host_canary_unchanged=True,source_freeze_unchanged=True,writers_stopped=True)
            with auth.store() as fd:
                with auth.fs.subdirectory(fd,'consumed') as used:(authority_copy/'consumed.json').write_bytes(auth.fs.read(used,summary['request_id']+'.json',4096))
        except Exception as error:gate.report.update(result='FAIL',cleanup_error=str(error))
        gate.connection.close();(output/'results.json').write_text(json.dumps(gate.report,indent=2)+'\n')
    if gate.report['result']=='PASS':
        try:
            verification=verify_single(output);(output/'independent-verification.json').write_text(json.dumps(verification,indent=2)+'\n')
        except Exception as error:
            gate.report.update(result='FAIL',verification_error=str(error))
            (output/'results.json').write_text(json.dumps(gate.report,indent=2)+'\n')
    if args.export:
        args.export.mkdir(mode=0o700,parents=True,exist_ok=False)
        for path in output.iterdir():
            if path.is_file() and path.suffix in {'.json','.xml','.log'}:shutil.copyfile(path,args.export/path.name)
            elif path.is_dir() and (path.name in {'sources','authority-copy','admissions'} or path.name.endswith('-quarantine')):shutil.copytree(path,args.export/path.name)
        for path in [args.export,*args.export.rglob('*')]:os.chown(path,1000,1000)
    print(json.dumps({'result':gate.report['result'],'request_id':summary['request_id'],'raw_control':str(output),
                      'execution_status':gate.report['runs'][0]['outcome']['status'] if gate.report['runs'] else None,
                      'meaning':'execution/custody only; no risk or authenticity verdict'}),flush=True)
    if gate.report['result']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
