"""Cold SQLite writers, passive report/digest consumers and configured CLI dispatch."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, snapshot
from integration_sentinel_admission_real import invoke as cli


def api(root, body):
    code = '''import json,sqlite3,sys,threading
from pathlib import Path
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
threads=set(threading.enumerate())
try:
    with offline_policy():
        from paw.sentinel.database import CampaignDatabase
%s
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread remains'
    for name in ('requests','paw.sentinel.monitor','paw.sentinel.ip_analyzer','paw.sentinel.geographic_reports'):
        assert name not in sys.modules,name
    print('RECORD_WRITERS_GUARD_OK',file=sys.stderr)
''' % (str(REPO), '\n'.join('        '+line for line in body.splitlines()))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1'); env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
                            env=env, capture_output=True, timeout=45)
    output = (result.stdout+result.stderr).decode('utf-8')
    assert result.returncode == 0 and 'RECORD_WRITERS_GUARD_OK' in output, output


def main():
    with tempfile.TemporaryDirectory(prefix='paw-writers-real-') as temporary:
        root = Path(temporary)
        path = root/'saved # Ω %.db'
        (root/'sentinel_config.json').write_text(json.dumps({'storage': {'database_path': path.name}}), encoding='utf-8')
        api(root, '''db=CampaignDatabase('saved # Ω %.db')
campaign=db.add_campaign('selected','https://example.invalid/never-visit',{'source':['Ω',False,None]})
db.add_campaign('neighbor','literal neighbor',{'retained':True})
db.record_check(campaign,'literal status',response_time=0.0,http_status=418,metadata={'source':['Ω',False,None]})
db.record_alert(campaign,'literal type','literal message Ω',metadata={'source':['Ω',False,None]})
identifier=db.add_victim_intelligence('192.0.2.1',None,'literal URL',case_id='selected',metadata={'source':['Ω',False,None]})
db.add_victim_intelligence('192.0.2.2','unchanged UA','neighbor URL',case_id='neighbor',metadata={'retained':True})
assert identifier==1
assert db.update_victim_analysis(identifier,geolocation_data={'country':'SuppliedCountry'},whois_data={'raw':'supplied'},
    attacker_correlation={'claim':'unverified'},related_ips=['192.0.2.3'],interaction_indicators=['supplied'],
    interaction_confidence=0.5,interaction_type='literal label',risk_score=6,analyzed_status='analyzed')''')
        with closing(sqlite3.connect(path)) as conn:
            selected = conn.execute('SELECT victim_ip,victim_ua,case_id,metadata,risk_score FROM victim_intelligence WHERE id=1').fetchone()
            assert selected[:3] == ('192.0.2.1', None, 'selected') and selected[4] == 6
            assert json.loads(selected[3]) == {'source': ['Ω', False, None]}
            neighbor = conn.execute('SELECT * FROM victim_intelligence WHERE id=2').fetchone()
            assert conn.execute('SELECT last_check FROM campaigns WHERE case_id="selected"').fetchone() == conn.execute('SELECT check_time FROM checks').fetchone()
        before = snapshot(root)
        api(root, '''db=CampaignDatabase('saved # Ω %.db')
campaign=db.get_active_campaigns()[0]['id']
for value in (False,0,'',[],{'n':float('nan')},{1:'numeric','1':'text'},{'tuple':()}, {'text':'x'*(1024**2)}):
    operations=(lambda:db.add_campaign('invalid','literal',value),
        lambda:db.record_check(campaign,'literal',metadata=value),
        lambda:db.record_alert(campaign,'literal','message',metadata=value),
        lambda:db.add_victim_intelligence('192.0.2.9',None,'literal',metadata=value))
    for operation in operations:
        try: operation()
        except (ValueError,TypeError): pass
        else: raise AssertionError('Invalid metadata persisted')
for field,value in (('geolocation_data',[]),('related_ips',[1]),('whois_data',{'n':float('inf')}),
        ('interaction_confidence',float('nan')),('risk_score',float('inf'))):
    try: db.update_victim_analysis(1,**{field:value})
    except (ValueError,TypeError): pass
    else: raise AssertionError('Invalid analysis persisted')''')
        assert snapshot(root) == before
        api(root, '''db=CampaignDatabase('saved # Ω %.db')
before=Path(db.db_path).read_bytes()
assert db.update_victim_analysis(99999,risk_score=7) is False
assert db.update_victim_analysis(1) is False
assert Path(db.db_path).read_bytes()==before
for table in ('checks','alerts','victim_intelligence'):
    with db.connection() as conn:
        conn.execute('CREATE TRIGGER ignored BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END')
    before=Path(db.db_path).read_bytes()
    campaign=db.get_active_campaigns()[0]['id']
    try:
        if table=='checks': db.record_check(campaign,'literal')
        elif table=='alerts': db.record_alert(campaign,'literal','message')
        else: db.add_victim_intelligence('192.0.2.9',None,'literal')
    except RuntimeError: pass
    else: raise AssertionError('Ignored insert acknowledged')
    assert Path(db.db_path).read_bytes()==before
    with db.connection() as conn: conn.execute('DROP TRIGGER ignored')
with db.connection() as conn:
    conn.execute('CREATE TRIGGER reverted AFTER UPDATE OF risk_score ON victim_intelligence BEGIN UPDATE victim_intelligence SET risk_score=OLD.risk_score WHERE id=NEW.id; END')
before=Path(db.db_path).read_bytes()
try: db.update_victim_analysis(1,risk_score=7)
except RuntimeError: pass
else: raise AssertionError('Reverted update acknowledged')
assert Path(db.db_path).read_bytes()==before
with db.connection() as conn: conn.execute('DROP TRIGGER reverted')''')
        api(root, '''db=CampaignDatabase('saved # Ω %.db')
assert db.update_victim_analysis(1,geolocation_data={},related_ips=[],interaction_indicators=[],
    risk_score=0,interaction_confidence=0.0)
row=db.get_victim_intelligence(victim_id=1)[0]
assert row['geolocation_data']=={} and row['related_ips']==[] and row['interaction_indicators']==[]
assert row['risk_score']==0 and row['interaction_confidence']==0.0
assert row['whois_data']=={'raw':'supplied'} and row['attacker_correlation']=={'claim':'unverified'}
assert row['analyzed_status']=='analyzed' and row['interaction_type']=='literal label'
assert row['victim_ua'] is None and row['metadata']=={'source':['Ω',False,None]}''')
        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute('SELECT * FROM victim_intelligence WHERE id=2').fetchone() == neighbor
        before = snapshot(root)
        api(root, '''db=CampaignDatabase('saved # Ω %.db',read_only=True)
for operation in (lambda:db.record_check(db.get_active_campaigns()[0]['id'],'stored'),
        lambda:db.record_alert(db.get_active_campaigns()[0]['id'],'stored','message'),
        lambda:db.add_victim_intelligence('192.0.2.1',None,'literal'),lambda:db.update_victim_analysis(1,geolocation_data={})):
    try: operation()
    except sqlite3.OperationalError: pass
    else: raise AssertionError('Read-only storage mutated')''')
        assert snapshot(root) == before
        api(root, '''from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
reader=IntelligenceAnalyzer('saved # Ω %.db',read_only=True)
export=reader.export_forensic_data('selected')
report=reader.generate_intelligence_report('selected')
assert export['total_records']==report['summary']['total_victims']==1
assert export['evidence_scope']==report['evidence_scope']=='stored_rows_unverified'
assert export['victims'][0]['stored_record']==report['source_records'][0]
for evidence in report['source_records'][0]['json_evidence']['fields'].values():
    assert evidence['status']=='decoded' and evidence['verified'] is False
Path('forensic.json').write_text(json.dumps(export,allow_nan=False),encoding='utf-8')
Path('intelligence.json').write_text(json.dumps(report,allow_nan=False),encoding='utf-8')''')
        export = json.loads((root/'forensic.json').read_text(encoding='utf-8'))
        payload = json.dumps(export['victims'], sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        assert hashlib.sha256(payload).hexdigest() == export['data_integrity_hash']
        assert export['victims'][0]['stored_record']['id'] == 1
        after = snapshot(root)
        assert {name: value for name, value in after.items() if name not in ('forensic.json', 'intelligence.json')} == before
        for action in ('list', 'status'):
            cli(root, arguments=[action]); assert snapshot(root) == after
        assert not (root/'sentinel.db').exists()
    print(json.dumps({'status': 'passed', 'cold_api_processes': 6, 'guarded_cli_processes': 2,
        'actual_sqlite_and_json_digest_verified': True, 'neighbor_and_passive_source_bytes_preserved': True,
        'scope': 'Constructed local storage, literal supplied claims and declared trigger faults. No active collection, arbitrary-trigger classifier, cross-process snapshot, authenticity, attribution or accuracy evidence.'}, indent=2))


if __name__ == '__main__': main()
