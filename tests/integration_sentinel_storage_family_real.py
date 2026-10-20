"""Local storage contracts through cold APIs/CLI and an actual stopped full EML case."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from integration_legacy_origin_update_real import REPO, verify_case, snapshot


def invoke(root, body, *, cli=None, limit=None, expected=0):
    code = '''import contextlib,io,json,os,sqlite3,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
cli=%r
if cli:
    from paw.__main__ import main
    sys.argv=['paw','monitor',cli]
threads=set(threading.enumerate())
try:
    with offline_policy():
        from paw.sentinel.file_monitor import FileMonitor
        if %r:
            original=FileMonitor.__init__
            def limited(self,*args,**kwargs):
                kwargs.update(%r); original(self,*args,**kwargs)
            FileMonitor.__init__=limited
        if cli: main()
        else:
%s
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread remains'
    assert 'requests' not in sys.modules or cli,'API loaded HTTP client'
    if cli:
        for name in ('config','database','monitor','ip_analyzer','intelligence_analyzer'):
            assert 'paw.sentinel.'+name not in sys.modules,name
    print('LOCAL_STORAGE_GUARD_OK',file=sys.stderr)
''' % (str(REPO),cli,bool(limit),limit or {},'\n'.join('            '+line for line in body.splitlines()) or '            pass')
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1'); env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,capture_output=True,timeout=45)
    output=(result.stdout+result.stderr).decode('utf-8')
    assert 'LOCAL_STORAGE_GUARD_OK' in output and result.returncode==expected,output
    if cli and expected:
        assert 'limit' in output and '[file_monitor] Case ' not in output,output
        assert 'File Integrity Report:' not in output,output
    return {'entry':'CLI' if cli else 'API','action':cli,'limits':limit,'exit':result.returncode}


def main():
    with tempfile.TemporaryDirectory(prefix='paw-sentinel-storage-real-') as temporary:
        base=Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve()
        root=base/'work'; root.mkdir(parents=True)
        raw=next((REPO/'inbox').glob('*.eml')).read_bytes(); (root/'input.eml').write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result=subprocess.run([sys.executable,'-X','utf8','-m','paw','full','input.eml',
            '--no-egress','--deadline','90','--stage-timeout','45'],cwd=root,env=env,capture_output=True,timeout=120)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode==0,result.stdout+result.stderr
        case,=(p for p in (root/'cases').glob('case-*') if p.is_dir())
        control,=(p for p in (root/'jobs').glob('analysis_*') if p.is_dir())
        assert json.loads((control/'supervisor.json').read_text(encoding='utf-8'))['tree_stopped']
        execution=json.loads((case/'execution.json').read_text(encoding='utf-8'))
        assert execution['no_egress'] and not execution['blocked_operations']
        assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
        before=snapshot(root); checks=[]
        prefix='case='+repr(case.name)+'\nmonitor=FileMonitor("cases")\n'
        bodies=[
            '''first=monitor.check_file_changes(case)
assert first['integrity_status']=='ok' and first['new_files'],first
second=monitor.check_file_changes(case)
assert not any(second[key] for key in ('new_files','modified_files','deleted_files')),second
report=monitor.generate_integrity_report()
assert report['integrity_summary']=={'ok':1,'compromised':0,'unknown':0},report
assert report['inventory']['atomic_snapshot'] is False
assert report['cases'][0]['file_count']==len(monitor.get_case_files(case))''',
            '''for name in ('../input.eml',os.path.abspath('input.eml'),'..',''):
    for method in (monitor.get_case_files,monitor.check_file_changes,monitor.verify_merkle_integrity):
        try: method(name)
        except ValueError: pass
        else: raise AssertionError('Outside case admitted')
assert monitor._baseline_hashes=={}''',
            '''monitor.check_file_changes(case); baseline=dict(monitor._baseline_hashes)
original=monitor.calculate_file_hash
extra=os.path.join('cases',case,'added-during-observation')
def changed(path):
    value=original(path)
    with open(extra,'wb') as output: output.write(b'declared mutation fixture')
    return value
monitor.calculate_file_hash=changed
try:
    try: monitor.check_file_changes(case)
    except OSError as error: assert 'changed' in str(error)
    else: raise AssertionError('Mixed inventory admitted')
    assert monitor._baseline_hashes==baseline
finally:
    if os.path.exists(extra): os.remove(extra)''',
            '''for limits in ({'max_files':1},{'max_bytes':1},{'max_file_bytes':1}):
    limited=FileMonitor('cases',**limits)
    for method in (lambda:limited.check_file_changes(case),limited.monitor_all_cases,limited.generate_integrity_report):
        try: method()
        except ValueError as error: assert 'limit' in str(error)
        else: raise AssertionError('Over-budget scan admitted')
        assert limited._baseline_hashes=={}''',
        ]
        for body in bodies:
            checks.append(invoke(root,prefix+body)); assert snapshot(root)==before
        for action in ('files','integrity'):
            for limit in (None,{'max_files':1},{'max_file_bytes':1}):
                checks.append(invoke(root,'',cli=action,limit=limit,expected=1 if limit else 0))
                assert snapshot(root)==before
        # Separate saved database; actual campaign rows never become case evidence.
        campaign_body='''from paw.sentinel.database import CampaignDatabase
from paw.sentinel.config import SentinelConfig
from paw.sentinel.monitor import SentinelMonitor
database=CampaignDatabase('campaign-fixture.db')
monitor=SentinelMonitor(config=SentinelConfig('missing-fixture-config.json'),database=database)
first=monitor.add_campaign('first','https://example.invalid/stored',{'literal':['Ω',False]})
second=monitor.add_campaign('second','literal',{'neighbor':True})
neighbor=database.get_campaign(second)
assert monitor.remove_campaign(first) is True
assert monitor.remove_campaign(first) is False
assert monitor.remove_campaign('missing') is False
assert database.get_campaign(second)==neighbor
assert database.get_campaign(first)['metadata']=={'literal':['Ω',False]}
for args in (('','literal',None),('third',' ',None),('third','literal',{'score':float('nan')})):
    try: monitor.add_campaign(*args)
    except ValueError: pass
    else: raise AssertionError('Invalid API add admitted')
assert len(database.get_active_campaigns())==1
assert not monitor.is_running()'''
        checks.append(invoke(root,campaign_body))
        after=snapshot(root)
        assert all(after[name]==data for name,data in before.items())
        assert set(after)-set(before)=={'campaign-fixture.db'}
        for command in ('verify','export'):
            args=[command,'--case',str(case)]+(['--format','zip'] if command=='export' else [])
            result=subprocess.run([sys.executable,'-X','utf8','-m','paw',*args],cwd=root,env=env,capture_output=True,timeout=30)
            assert result.returncode==0,result.stdout+result.stderr
        with zipfile.ZipFile(str(case)+'.zip') as archive:
            for relative,data in before.items():
                if data is not None and relative.startswith(case.relative_to(root).as_posix()+'/'):
                    assert archive.read(case.name+'/'+Path(relative).relative_to(case.relative_to(root)).as_posix())==data
        assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
    print(json.dumps({'status':'passed','checks':checks,'cold_api_processes':5,'guarded_cli_processes':6,
        'actual_full_original_eml_analyses':1,'actual_cli_verify_zip_bytes_preserved':True,
        'scope':'Actual stopped worker, cold local storage API/CLI and declared in-scan mutation/limit fixtures. Campaign changes confined to separate fixture storage; no active collection, OS containment, atomic cross-process snapshot, attribution or accuracy claim.'},indent=2))


if __name__=='__main__': main()
