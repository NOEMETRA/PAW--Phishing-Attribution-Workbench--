"""Actual original-EML verification availability, known mismatch and CLI outcomes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from integration_legacy_origin_update_real import REPO, seal_case, verify_case, snapshot


def invoke(root,case,target,kind,entry):
    code="""import builtins,sys,threading
sys.path.insert(0,%r)
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
from unittest.mock import patch
entry=%r
if entry!='API':
    # Existing CLI bootstrap probes local socket support before guarded dispatch.
    from paw.__main__ import main
    sys.argv=['paw','monitor',entry]
threads=set(threading.enumerate())
try:
    with offline_policy():
        from test_sentinel_hash_failures import failing_open
        kind=%r
        target=%r
        if entry=='API':
            from paw.sentinel.file_monitor import FileMonitor
            monitor=FileMonitor(%r)
            with patch('builtins.open',failing_open(builtins.open,target,kind)):
                outcome,message=monitor.verify_merkle_integrity(%r)
                assert outcome is None and 'Explicit' in message,(outcome,message)
                report=monitor.generate_integrity_report()
            assert report['integrity_summary']=={'ok':1,'compromised':1,'unknown':1},report
            selected=next(c for c in report['cases'] if c['case_id']==%r)
            assert selected['integrity_status']=='unknown' and 'Explicit' in selected['integrity_message'],selected
            assert selected['file_count']>0 and monitor._baseline_hashes=={}
            assert monitor.verify_merkle_integrity(%r)[0] is True
            recovered=monitor.generate_integrity_report()
            assert recovered['integrity_summary']=={'ok':2,'compromised':1,'unknown':0},recovered
        elif kind:
            with patch('builtins.open',failing_open(builtins.open,target,kind)): main()
        else: main()
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('config','database','monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('VERIFICATION_AVAILABILITY_CHECK_OK',file=sys.stderr)
""" % (str(REPO),str(REPO/'tests'),entry,kind,str(target),str(root/'cases'),case.name,case.name,case.name)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        capture_output=True,timeout=45)
    output=result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
    assert 'VERIFICATION_AVAILABILITY_CHECK_OK' in output,output
    if entry=='files':
        assert result.returncode!=0 and '[file_monitor] Case ' not in output,output
    else:
        assert result.returncode==0,output
        if entry=='integrity':
            expected=(1,1,1) if kind else (2,1,0)
            for label,count in zip(('Integrity OK','Compromised','Unknown'),expected):
                assert f'{label}: {count}' in output,output
            if kind: assert 'Error verifying Merkle integrity:' in output and 'Explicit' in output,output
    return {'entry':entry,'fault':kind,'target':target.relative_to(case).as_posix(),'exit':result.returncode}


def main():
    with tempfile.TemporaryDirectory(prefix='paw-verify-errors-real-') as temporary:
        base=Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve()
        root=base/'work'; root.mkdir(parents=True)
        raw=next((REPO/'inbox').glob('*.eml')).read_bytes()
        (root/'input.eml').write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result=subprocess.run([sys.executable,'-X','utf8','-m','paw','full','input.eml','--no-egress',
            '--deadline','90','--stage-timeout','45'],cwd=root,env=env,capture_output=True,timeout=120)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode==0,result.stdout+result.stderr
        case,=(p for p in (root/'cases').glob('case-*') if p.is_dir())
        control,=(p for p in (root/'jobs').glob('analysis_*') if p.is_dir())
        assert json.loads((control/'supervisor.json').read_text(encoding='utf-8'))['tree_stopped']
        execution=json.loads((case/'execution.json').read_text(encoding='utf-8'))
        assert execution['no_egress'] and not execution['blocked_operations']
        assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
        for name in ('case-000-valid','case-001-mismatch'):
            neighbor=root/'cases'/name; neighbor.mkdir()
            (neighbor/'input.eml').write_bytes(b'Constructed stored fixture\n')
            seal_case(neighbor)
        mismatch=root/'cases/case-001-mismatch'
        (mismatch/'input.eml').write_bytes(b'Actual changed fixture bytes\n')
        before=snapshot(root)
        checks=[]
        for target,kind in ((case/'evidence/merkle_index.json','denied'),
                (case/'evidence/merkle_index.json','missing'),(case/'input.eml','stream')):
            for entry in ('API','integrity','files'):
                checks.append(invoke(root,case,target,kind,entry))
                assert snapshot(root)==before,(target,kind,entry)
        checks.append(invoke(root,case,case/'evidence/merkle_index.json',None,'integrity'))
        assert snapshot(root)==before
        result=subprocess.run([sys.executable,'-X','utf8','-m','paw','export','--case',str(case),
            '--format','zip'],cwd=root,env=env,capture_output=True,timeout=30)
        assert result.returncode==0,result.stdout+result.stderr
        with zipfile.ZipFile(str(case)+'.zip') as archive:
            for relative,data in before.items():
                if data is not None and relative.startswith(case.relative_to(root).as_posix()+'/'):
                    assert archive.read(case.name+'/'+Path(relative).relative_to(case.relative_to(root)).as_posix())==data
        assert verify_case(str(case)) and verify_case(str(root/'cases/case-000-valid'))
        assert verify_case(str(mismatch)) is False
    print(json.dumps({'status':'passed','checks':checks,'actual_full_original_eml_analyses':1,
        'actual_cli_zip_export':True,
        'scope':'Actual original bytes/seals and known changed storage fixtures. Three cold API/seven guarded CLI dispatch processes distinguish unavailable verification from true/false outcomes, retain diagnostics, recovery and hash-scan failures. Read faults explicitly injected, not OS ACL or live races. CLI bootstrap precedes guard; no authenticity, accuracy or OS-isolation claim.'},indent=2))


if __name__=='__main__':
    main()
