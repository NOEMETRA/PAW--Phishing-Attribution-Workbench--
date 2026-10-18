"""Actual stopped original-EML case; file/directory read failures and recovery."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from integration_legacy_origin_update_real import REPO, seal_case, verify_case, snapshot


def invoke(root,case,target,kind,cli=False,family='hash',action='files'):
    code="""import builtins,contextlib,io,os,sys,threading
sys.path.insert(0,%r)
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
from unittest.mock import patch
if %r:
    # Existing CLI bootstrap probes local IPv6 support before guarded dispatch.
    from paw.__main__ import main
    sys.argv=['paw','monitor',%r]
threads=set(threading.enumerate())
try:
    with offline_policy():
        from test_sentinel_hash_failures import failing_open
        from test_sentinel_walk_failures import failing_scandir
        kind=%r
        target=%r
        family=%r
        expected={'denied':PermissionError,'missing':FileNotFoundError,'stream':OSError,'iterator':OSError}
        def injected():
            if family=='walk': return patch('os.scandir',failing_scandir(os.scandir,target,kind))
            return patch('builtins.open',failing_open(builtins.open,target,kind))
        if %r:
            if kind:
                with injected(): main()
            else: main()
        else:
            from paw.sentinel.file_monitor import FileMonitor
            monitor=FileMonitor(%r)
            monitor.check_file_changes(%r)
            baseline=dict(monitor._baseline_hashes)
            with injected():
                try: monitor.check_file_changes(%r)
                except expected[kind]: pass
                else: raise AssertionError('Failed read became a case result')
            assert monitor._baseline_hashes==baseline,'Prior baseline changed'
            recovered=monitor.check_file_changes(%r)
            assert recovered['integrity_status']=='ok',recovered
            assert not any(recovered[k] for k in ('new_files','modified_files','deleted_files')),recovered
            fresh=FileMonitor(%r)
            printed=io.StringIO()
            with contextlib.redirect_stdout(printed),injected():
                try: fresh.monitor_all_cases()
                except expected[kind]: pass
                else: raise AssertionError('Failed all-case scan returned success')
            assert fresh._baseline_hashes=={},'Neighbor baseline committed'
            assert '[file_monitor] Case ' not in printed.getvalue(),'Partial check record emitted'
            results=fresh.monitor_all_cases()
            assert len(results)==2 and all(r['integrity_status']=='ok' for r in results),results
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('config','database','monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('HASH_FAILURE_SOURCE_AND_BASELINE_CHECK_OK',file=sys.stderr)
""" % (str(REPO),str(REPO/'tests'),cli,action,kind,str(target),family,cli,str(root/'cases'),case.name,
           case.name,case.name,str(root/'cases'))
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        capture_output=True,timeout=45)
    output=result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
    assert 'HASH_FAILURE_SOURCE_AND_BASELINE_CHECK_OK' in output,output
    if cli and kind:
        assert result.returncode!=0 and '[file_monitor] Case ' not in output,output
        assert 'File Integrity Report:' not in output,output
    else: assert result.returncode==0,output
    return {'entry':'CLI' if cli else 'API','family':family,'action':action,'fault':kind,
            'target':target.relative_to(case).as_posix(),'exit':result.returncode}


def main():
    with tempfile.TemporaryDirectory(prefix='paw-hash-failure-real-') as temporary:
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
        neighbor=root/'cases/case-000-neighbor'; neighbor.mkdir()
        (neighbor/'input.eml').write_bytes(b'Constructed neighboring stored file\n')
        seal_case(neighbor)
        before=snapshot(root)
        checks=[]
        for kind in ('denied','missing','stream'):
            for cli in (False,True):
                checks.append(invoke(root,case,case/'input.eml',kind,cli))
                assert snapshot(root)==before,(kind,cli)
        for target in (case,case/'graphs'):
            assert target.is_dir(),target
            for kind in ('denied','iterator'):
                for cli in (False,True):
                    checks.append(invoke(root,case,target,kind,cli,family='walk'))
                    assert snapshot(root)==before,(target,kind,cli)
                checks.append(invoke(root,case,target,kind,True,family='walk',action='integrity'))
                assert snapshot(root)==before,(target,kind,'integrity')
        checks.append(invoke(root,case,case/'input.eml',None,True))
        assert snapshot(root)==before
        result=subprocess.run([sys.executable,'-X','utf8','-m','paw','export','--case',str(case),
            '--format','zip'],cwd=root,env=env,capture_output=True,timeout=30)
        assert result.returncode==0,result.stdout+result.stderr
        with zipfile.ZipFile(str(case)+'.zip') as archive:
            for relative,data in before.items():
                if data is not None and relative.startswith(case.relative_to(root).as_posix()+'/'):
                    assert archive.read(case.name+'/'+Path(relative).relative_to(case.relative_to(root)).as_posix())==data
        assert verify_case(str(case)) and verify_case(str(neighbor))
    print(json.dumps({'status':'passed','checks':checks,
        'actual_full_original_eml_analyses':1,'actual_cli_zip_export':True,
        'scope':'Actual files, digests, directory inventories, saved seals and original ZIP bytes. File open/disappearance/mid-read and root/nested scandir open/iteration failures are explicitly injected, not OS ACL or live races. Seven cold API and twelve guarded CLI dispatch processes check failure/recovery, baseline preservation and failed integrity-report admission. CLI bootstrap precedes guard; not OS containment, concurrent-writer snapshot, authenticity or classifier accuracy.'},indent=2))


if __name__=='__main__':
    main()
