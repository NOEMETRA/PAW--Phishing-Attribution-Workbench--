"""Bounded root PID1 acceptance; only the explicit harmless grant fixture catalog."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback
import uuid

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from offline_candidate import canonical,require
import one_use_authorization as auth
from granted_offline_adapter import GrantedGate,run_granted
from i08_context import capture
from owned_grant_fixtures import SOURCES
from benign_guest_validation import BASE,digest
from gw_quarantine import publish
from verify_granted_offline import verify,NORMAL,FAULTS


def candidate(case):
    source=SOURCES[case if case in NORMAL else 'positive'];now=int(time.time())
    return canonical({'schema':'paw-s14-offline-candidate-v1','profile':'linux-python-offline-v1',
        'request_id':uuid.uuid4().hex,'case_reference_sha256':auth.digest(b'owned adapter fixture reference; not PAW authenticity'),
        'source':{'media_type':'text/x-python','encoding':'utf-8','bytes':len(source),'sha256':auth.digest(source),'data_hex':source.hex()},
        'provenance':{'kind':'operator-supplied','reference':'owned harmless acceptance fixture '+case},
        'created_at':now,'expires_at':now+900,'purpose':'offline-single-job-review'})


class FaultGate(GrantedGate):
    fault=None
    def start(self,label,boot=True):
        if self.fault=='paused-refusal':
            super().start(label,boot=False)
            raise RuntimeError('owned_paused_startup_refusal')
        vm=super().start(label,boot=boot)
        if self.fault=='owner-loss':
            vm['owner'].kill();vm['owner'].wait(timeout=12)
            self.report['fault_injections'].append({'case':self.fault,'vm_uuid':vm['node']['uuid'],
                'owner_pid':vm['owner'].pid,'owner_returncode':vm['owner'].returncode})
        elif self.fault=='protocol-loss':
            # Trusted host fault injection through the real serial controller.
            os.write(vm['channel'].serial.fd,b'{"id":-1,"op":"owned-invalid-operation"}\n')
            time.sleep(.3)
        return vm


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-acceptance',action='store_true',required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--export',type=Path,required=True)
    args=parser.parse_args()
    require(os.geteuid()==0 and Path('/proc/self/attr/current').read_text().strip()=='unconfined','explicit_root_PID1_operator_required')
    require(shutil.disk_usage('/var/lib/libvirt/images').free>=10*1024**3,'free_disk_admission')
    # Never repair or trust an existing unsafe path silently.
    try:auth.ROOT.mkdir(mode=0o700)
    except FileExistsError:pass
    ctx=capture();policy_raw=canonical(auth.make_policy(ctx))
    with auth.root_directory() as fd:auth.exclusive(fd,auth.policy_name(policy_raw),policy_raw)
    gate=FaultGate(args);gate.active_vm=None
    gate.canary=gate.output/'host-owned-canary.bin';gate.canary.write_bytes(os.urandom(32));gate.canary.chmod(0o600)
    canary=digest(gate.canary);before=gate.snapshot_host()
    (gate.output/'policy.json').write_bytes(policy_raw)
    gate.report.update(scope=auth.SCOPE,hostile_code_authorized=False,runs=[],vms=[],fault_injections=[],real_connections=0)
    authority_copy=gate.output/'authority-copy';authority_copy.mkdir(mode=0o700)
    try:
        for case in [*NORMAL,'paused-refusal','owner-loss','protocol-loss']:
            gate.fault=case if case in FAULTS else None
            raw=candidate(case);value=json.loads(raw);rid=value['request_id']
            auth.issue(raw,policy_raw,capture())
            folder=authority_copy/rid;folder.mkdir(mode=0o700);(folder/'candidate.json').write_bytes(raw)
            try:
                result=run_granted(gate,raw,policy_raw,cancel=case=='cancel')
                require(case in NORMAL and result['outcome']['status']==NORMAL[case],'unexpected_execution_outcome')
                result.update(case=case,request_id=rid)
                gate.report['runs'].append(result)
            except Exception as error:
                if case not in FAULTS:raise
                require(gate.active_vm is None,'fault_left_active_vm')
                require(any(v['label']=='grant-'+rid and v['stopped'] is True for v in gate.report['vms']),'fault_stop_unknown')
                gate.report['runs'].append({'case':case,'request_id':rid,'status':'refused-or-failed',
                                           'error':type(error).__name__+':'+str(error),'writers_stopped':True})
            with auth.root_directory() as fd:
                with auth.subdirectory(fd,'grants') as grants:(folder/'grant.json').write_bytes(auth.read(grants,rid+'.json',4096))
                with auth.subdirectory(fd,'consumed') as used:(folder/'consumed.json').write_bytes(auth.read(used,rid+'.json',4096))
            # Same input under a new output container cannot bypass the global ledger.
            previous=gate.output;other=previous/('replay-'+rid);other.mkdir(mode=0o700);gate.output=other
            try:
                try:run_granted(gate,raw,policy_raw)
                except FileExistsError:pass
                else:raise ValueError('global_replay_not_refused')
                require(not list(other.iterdir()),'replay_touched_output')
            finally:gate.output=previous
            print('PASS: granted adapter / '+case,flush=True)
        gate.report['global_replay_refused']=True
        try:publish(gate.output/'unknown-stop-must-not-publish',[],stopped=None)
        except ValueError:gate.report['unknown_stop_publication_refused']=not (gate.output/'unknown-stop-must-not-publish').exists()
        else:raise ValueError('unknown_stop_published')
        gate.report['result']='PASS'
    except Exception as error:
        gate.report.update(result='FAIL',error=str(error),traceback=traceback.format_exc());print(gate.report['traceback'],flush=True)
    finally:
        try:
            if gate.active_vm:gate.stop(gate.active_vm)
            require(not gate.connection.listAllDomains(0) and before==gate.snapshot_host(),'host_not_restored')
            require(digest(BASE)==gate.root_image_sha and digest(gate.canary)==canary,'immutable_base_or_canary_changed')
            require(capture()==ctx,'effective_context_changed')
            gate.report.update(host_before=before,host_after=gate.snapshot_host(),host_restored=True,base_unchanged=True,
                host_canary_unchanged=True,source_freeze_unchanged=True,writers_stopped=True)
        except Exception as error:gate.report.update(result='FAIL',cleanup_error=str(error))
        gate.connection.close()
        (gate.output/'results.json').write_text(json.dumps(gate.report,indent=2)+'\n')
        if gate.report['result']=='PASS':
            try:(gate.output/'independent-verification.json').write_text(json.dumps(verify(gate.output),indent=2)+'\n')
            except Exception as error:
                gate.report.update(result='FAIL',verification_error=str(error));(gate.output/'results.json').write_text(json.dumps(gate.report,indent=2)+'\n')
        # Explicit audit copy only; authoritative grants/consumed files stay root-owned.
        args.export.mkdir(mode=0o700,parents=True,exist_ok=False)
        for path in gate.output.iterdir():
            if path.is_file() and path.suffix in {'.json','.xml','.log'}:shutil.copyfile(path,args.export/path.name)
            elif path.is_dir() and (path.name in {'sources','authority-copy','admissions'} or path.name.endswith('-quarantine')):shutil.copytree(path,args.export/path.name)
        for path in [args.export,*args.export.rglob('*')]:os.chown(path,1000,1000)
        print('Granted offline acceptance: '+gate.report['result'],flush=True)
    if gate.report['result']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
