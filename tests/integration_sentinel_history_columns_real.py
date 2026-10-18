"""Cold guarded history readers on actual saved SQLite layouts; no collection."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, snapshot, invoke as status_cli
from test_sentinel_history_columns import history_database, seed_history, COLUMNS, LAYOUTS


def api(root, missing):
    code = """import sys,threading,json,sqlite3
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
threads=set(threading.enumerate())
try:
    with offline_policy():
        from paw.sentinel.database import CampaignDatabase
        reader=CampaignDatabase('saved # Ω %%.db',read_only=True)
        columns=%r
        missing=%r
        for table in ('checks','alerts'):
            def read():
                return reader.get_recent_checks('saved-campaign') if table=='checks' else reader.get_unacknowledged_alerts()
            if table==missing:
                try: read()
                except sqlite3.OperationalError as exc: assert 'no such column: metadata' in str(exc),exc
                else: raise AssertionError('Missing required column admitted')
                continue
            rows=read()
            assert [r['id'] for r in rows]==([2,1] if table=='checks' else [3,1]),rows
            with reader.connection() as connection:
                connection.row_factory=sqlite3.Row
                stored={r['id']:dict(r) for r in connection.execute('SELECT * FROM '+table)}
            for row in rows:
                named=stored[row['id']]
                assert {n:row[n] for n in columns[table] if n!='metadata'}=={n:named[n] for n in columns[table] if n!='metadata'},row
                evidence=row['json_evidence']['fields']['metadata']
                assert evidence['raw_storage']=={'type':'text','value':named['metadata']},evidence
                assert evidence['verified'] is False
                if table=='checks' and row['id']==2:
                    assert evidence['status']=='invalid_json' and row['metadata']=={},row
                else:
                    assert evidence['status']=='decoded' and row['metadata']==json.loads(named['metadata']),row
                if table=='alerts': assert row['acknowledged'] is False,row
            json.dumps(rows,allow_nan=False)
            if table=='checks':
                assert [r['id'] for r in reader.get_recent_checks('saved-campaign',1)]==[2]
                assert reader.get_recent_checks('saved-campaign',0)==[]
                assert reader.get_recent_checks('absent')==[]
        assert reader.get_monitor_statistics()=={'total_campaigns':2,'active_campaigns':2,'unacknowledged_alerts':2}
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('config','monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('HISTORY_COLUMNS_API_CHECK_OK',file=sys.stderr)
""" % (str(REPO), COLUMNS, missing)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
                            env=env, capture_output=True, timeout=30)
    output = (result.stdout+result.stderr).decode('utf-8')
    assert result.returncode == 0 and 'HISTORY_COLUMNS_API_CHECK_OK' in output, output


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-history-columns-real-') as temporary:
        for mode in (*LAYOUTS, 'missing-checks', 'missing-alerts'):
            root = Path(temporary)/mode; root.mkdir()
            database = root/'saved # Ω %.db'
            (root/'sentinel_config.json').write_text(json.dumps(
                {'storage': {'database_path': database.name}}), encoding='utf-8')
            missing = mode.removeprefix('missing-') if mode.startswith('missing-') else None
            writer = history_database(database, 'extra-first' if missing else mode)
            with writer.connection() as connection:
                for identifier in ('saved-campaign', 'neighbor'):
                    connection.execute('INSERT INTO campaigns (id,case_id,created_at,url) VALUES (?,?,?,?)',
                        (identifier, identifier+'-case', 'stored creation', 'https://example.invalid/never-visit'))
            seed_history(writer, 'checks')
            seed_history(writer, 'checks', id=2, check_time='2026-01-02', metadata='{broken')
            seed_history(writer, 'checks', id=3, campaign_id='neighbor', check_time='2099-01-01')
            seed_history(writer, 'alerts')
            seed_history(writer, 'alerts', id=2, acknowledged=1, alert_time='2099-01-01')
            seed_history(writer, 'alerts', id=3, campaign_id='neighbor', alert_time='2026-01-02')
            if missing:
                with writer.connection() as connection:
                    connection.execute('ALTER TABLE '+missing+' DROP COLUMN metadata')
            before = snapshot(root)
            api(root, missing)
            assert snapshot(root) == before, mode
            # Status counts are a separate unaffected consumer, not a history CLI.
            exit_code, text = status_cli(root, 'status')
            assert exit_code == 0, text
            for field in ('Total campaigns: 2', 'Active campaigns: 2', 'Unacknowledged alerts: 2'):
                assert field in text, text
            assert snapshot(root) == before, mode
            checks.append({'layout': mode, 'cold_api': 1, 'guarded_status_cli': 1,
                           'all_source_bytes_preserved': True})
    print(json.dumps({'status': 'passed', 'cold_api_processes': 6, 'guarded_status_cli_processes': 6,
        'checks': checks, 'scope': 'Actual declared SQLite storage fixtures and cold API history reads. Separate CLI status regression retains counts. Imports guarded for API; ordinary CLI bootstrap precedes policy. No active collection, private-layout prevalence, OS containment, live concurrency, authenticity or accuracy claim.'}, indent=2))


if __name__ == '__main__':
    main()
