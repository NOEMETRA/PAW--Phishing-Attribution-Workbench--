"""Whole offline Sentinel boundary: cold CLI/API and actual two-process SQLite views."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

from integration_sentinel_passive_real import REPO, snapshot, CampaignDatabase


def invoke(root, *, args=None, body='', expected=0):
    code='''import json,sys,threading,runpy
from pathlib import Path
sys.path.insert(0,%r)
args=%r
if args is not None:
    from paw.__main__ import main
    sys.argv=['paw']+args
from paw.core.network_policy import offline_policy,violations
threads=set(threading.enumerate())
try:
    with offline_policy():
        if args is not None: main()
        else:
%s
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread remains'
    if args is None:
        for name in ('requests','matplotlib','plotly'):
            assert name not in sys.modules,name
    print('SENTINEL_COMPLETION_GUARD_OK',file=sys.stderr)
''' % (str(REPO),args,'\n'.join('            '+line for line in body.splitlines()) or '            pass')
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1'); env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,capture_output=True,timeout=45)
    text=(result.stdout+result.stderr).decode('utf-8')
    assert result.returncode==expected and 'SENTINEL_COMPLETION_GUARD_OK' in text,text
    if expected: assert 'limit' in text.lower() or 'unavailable' in text.lower(),text
    return text


def two_process_view(root):
    # Spawn the owned, local SQL fixture before installing policy in the parent.
    # Each child installs no-egress before its own SQLite work. No target visits.
    code='''import json,sqlite3,sys,time
from pathlib import Path
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
def wait(name):
    end=time.monotonic()+10
    while not Path(name).exists():
        if time.monotonic()>end: raise TimeoutError(name)
        time.sleep(.01)
with offline_policy():
    wait('reader-ready')
    with sqlite3.connect('saved.db',timeout=.1) as conn:
        try:
            with conn: conn.execute("UPDATE campaigns SET status='other-process' WHERE case_id='selected'")
        except sqlite3.OperationalError as exc:
            assert 'locked' in str(exc),exc
        else: raise AssertionError('Writer committed through the read snapshot')
    Path('writer-blocked').write_text('blocked')
    wait('reader-closed')
    with sqlite3.connect('saved.db',timeout=1) as conn:
        conn.execute("UPDATE campaigns SET status='other-process' WHERE case_id='selected'")
assert not violations(),violations()
''' % str(REPO)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    process=subprocess.Popen([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    from paw.core.network_policy import offline_policy,violations
    try:
        with offline_policy():
            reader=CampaignDatabase(str(root/'saved.db'),read_only=True)
            with reader.connection() as conn:
                first=conn.execute("SELECT status FROM campaigns WHERE case_id='selected'").fetchone()
                (root/'reader-ready').write_text('ready')
                end=time.monotonic()+10
                while not (root/'writer-blocked').exists():
                    if time.monotonic()>end: raise TimeoutError('Writer did not reach lock')
                    time.sleep(.01)
                assert conn.execute("SELECT status FROM campaigns WHERE case_id='selected'").fetchone()==first
            (root/'reader-closed').write_text('closed')
        output,error=process.communicate(timeout=15)
        assert process.returncode==0,output+error
        assert not violations(),violations()
        with closing(sqlite3.connect(root/'saved.db')) as conn:
            assert conn.execute("SELECT status FROM campaigns WHERE case_id='selected'").fetchone()==('other-process',)
    finally:
        if process.poll() is None: process.kill(); process.communicate(timeout=5)


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-sentinel-completion-real-') as temporary:
        root=Path(temporary)
        empty=root/'empty'; empty.mkdir(); before=snapshot(empty)
        for action in ('start','stop','check'):
            invoke(empty,args=['monitor',action],expected=1); checks.append('offline-'+action)
            assert snapshot(empty)==before
        invoke(empty,body='''import inspect
from paw.sentinel import SentinelConfig,CampaignDatabase,FileMonitor,SentinelMonitor,IPAnalyzer,IntelligenceAnalyzer
from paw.sentinel.geographic_reports import GeographicReporter
config=SentinelConfig('missing.json')
db=CampaignDatabase('explicit.db')
monitor=SentinelMonitor(config=config,database=db)
analyzer=IntelligenceAnalyzer('explicit.db')
ip=IPAnalyzer()
groups=((monitor,('start','_perform_checks','_check_campaign','_take_screenshot','check_now')),
    (analyzer,('analyze_unanalyzed_victims','_analyze_single_victim','_update_attacker_correlations',
        'classify_interaction_type','_analyze_interaction_pattern','_analyze_geographic_risk','_analyze_user_agent_risk','_analyze_ip_reputation')),
    (ip,('analyze_ip','reverse_dns_lookup','geolocate_ip','_geolocate_ipapi','_geolocate_ipify','whois_lookup','analyze_risk_indicators','correlate_ips','batch_analyze_ips')),
    (db,('calculate_risk_score',)))
for owner,names in groups:
    for name in names:
        method=getattr(owner,name)
        kwargs={key:object() for key,param in inspect.signature(method).parameters.items() if param.default is inspect.Parameter.empty}
        try: method(**kwargs)
        except RuntimeError: pass
        else: raise AssertionError('Active entrypoint admitted: '+name)
assert monitor._thread is None and not monitor.is_running()
assert ip.get_network_info('192.0.2.1')['version']==4'''); checks.append('all-public-imports-and-23-active-guards')
        selected=root/'configured'; selected.mkdir(); path=selected/'saved.db'
        db=CampaignDatabase(str(path)); db.add_campaign('selected','literal'); db.add_campaign('neighbor','literal')
        ids=[db.add_victim_intelligence('192.0.2.'+str(i),None,'literal',case_id=case,
            metadata={'source':['Ω',False,None]}) for i,case in enumerate(('selected','selected','neighbor'),1)]
        config=selected/'sentinel_config.json'
        config.write_text(json.dumps({'storage':{'database_path':'saved.db','limits':{'max_rows':1}}}),encoding='utf-8')
        before=snapshot(selected)
        for args in (['monitor','list'],['geographic','stats','--case','selected']):
            invoke(selected,args=args,expected=1); checks.append(args); assert snapshot(selected)==before
        for script in ('check_victims.py','check_db_fields.py'):
            invoke(selected,body='sys.argv=[%r]\nrunpy.run_path(%r,run_name="__main__")' % (script,str(REPO/script)),expected=1)
            checks.append(script); assert snapshot(selected)==before
        for args in (['monitor','status'],['geographic','stats','--case','neighbor']):
            invoke(selected,args=args); checks.append(args); assert snapshot(selected)==before
        invoke(selected,body='''from paw.sentinel.config import SentinelConfig
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
config=SentinelConfig(); config.set('storage.limits',{'max_rows':100})
analyzer=IntelligenceAnalyzer(**config.get_database_options(),read_only=True)
data=analyzer.export_forensic_data()
assert data['total_records']==3
assert data['read_contract']['limits']['max_rows']==100
assert data['read_contract']['atomic_filesystem_snapshot'] is False
Path('forensic.json').write_text(json.dumps(data,allow_nan=False),encoding='utf-8')'''); checks.append('configured-API-profile-export')
        data=json.loads((selected/'forensic.json').read_text(encoding='utf-8'))
        assert sorted(row['id'] for row in data['victims'])==ids
        payload=json.dumps(data['victims'],sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')
        assert hashlib.sha256(payload).hexdigest()==data['data_integrity_hash']
        assert path.read_bytes()==before['saved.db'] and not (selected/'sentinel.db').exists()
        for action in ('stats','report'):
            invoke(selected,args=['geographic',action,'--case','neighbor']); checks.append('configured-geographic-'+action)
        outputs=list((selected/'reports/geographic').glob('*'))
        assert {p.suffix for p in outputs}=={'.json','.html'}
        for output in outputs:
            if output.suffix=='.json':
                body=json.loads(output.read_text(encoding='utf-8'))
                assert body['total_records']==1 and body['source_records'][0]['id']==3
                assert body['read_contract']['limits']['max_rows']==100
            else:
                html=output.read_text(encoding='utf-8')
                assert "default-src 'none'" in html and '<script' not in html.lower()
        assert path.read_bytes()==before['saved.db']
        two_process_view(selected); checks.append('actual-two-process-SQLite-snapshot')
    print(json.dumps({'status':'passed','cold_api_processes':2,'guarded_cli_processes':11,
        'legacy_cli_processes_included':2,'snapshot_sql_writer_processes':1,
        'checks':checks,'scope':'Actual local SQLite, cold imports, no-egress refusals, configured limits and a concurrent owned SQL process. Unverified stored claims; no external collector, OS containment or source authenticity claim.'},indent=2))


if __name__=='__main__': main()
