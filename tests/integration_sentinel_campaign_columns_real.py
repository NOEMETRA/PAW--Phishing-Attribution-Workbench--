"""Actual stored campaign layouts, cold API/list aliases and CLI row mutations."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, snapshot
from integration_legacy_campaign_list_real import invoke as listing
from integration_sentinel_campaign_real import invoke as mutation, records
from test_sentinel_campaign_columns import campaign_database, seed_campaign, SOURCE, LAYOUTS, COLUMNS


def api(root, missing=False):
    code = """import sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
from unittest.mock import patch
threads=set(threading.enumerate())
try:
    # Path admission helpers may import config; a database reader must never
    # construct/load a configuration or select its default storage.
    with offline_policy(), patch('paw.sentinel.config.SentinelConfig.__init__',
            side_effect=AssertionError('Configuration constructed by database reader')):
        from paw.sentinel.database import CampaignDatabase
        reader=CampaignDatabase('stored # Ω %%.db',read_only=True)
        row=reader.get_campaign('saved-id')
        assert row['id']=='saved-id' and row['case_id']=='saved-case',row
        assert row['status']=='active' and row['url']=='https://example.invalid/never-visit',row
        assert row['metadata']=={'Ω':[1,False],'claim':'stored'},row
        assert row['json_evidence']['fields']['metadata']['raw_storage']['value']==%r,row
        assert sorted(r['id'] for r in reader.get_active_campaigns())==['neighbor-id','saved-id']
        assert reader.get_campaign('removed-id')['status']=='removed'
        assert reader.get_campaign('missing') is None
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('CAMPAIGN_COLUMNS_API_CHECK_OK',file=sys.stderr)
""" % (str(REPO), SOURCE['metadata'])
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
        env=env, capture_output=True, timeout=30)
    output = (result.stdout+result.stderr).decode('utf-8')
    assert 'CAMPAIGN_COLUMNS_API_CHECK_OK' in output, output
    if missing:
        assert result.returncode != 0 and 'no such column: metadata' in output, output
    else:
        assert result.returncode == 0, output


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-campaign-columns-real-') as temporary:
        for layout in (*LAYOUTS, 'missing-column'):
            root = Path(temporary)/layout; root.mkdir()
            database = root/'stored # Ω %.db'
            (root/'sentinel_config.json').write_text(json.dumps(
                {'storage': {'database_path': database.name}}), encoding='utf-8')
            writer = campaign_database(database, 'extra-first' if layout == 'missing-column' else layout)
            seed_campaign(writer)
            seed_campaign(writer, id='neighbor-id', case_id='neighbor-case', url='https://example.invalid/neighbor')
            seed_campaign(writer, id='removed-id', case_id='removed-case', status='removed')
            if layout == 'missing-column':
                with writer.connection() as connection:
                    connection.execute('ALTER TABLE campaigns DROP COLUMN metadata')
            before = snapshot(root)
            api(root, missing=layout == 'missing-column')
            assert snapshot(root) == before, layout
            for legacy in (False, True):
                exit_code, text = listing(root, legacy)
                if layout == 'missing-column':
                    assert exit_code == 1 and 'no such column: metadata' in text, text
                else:
                    assert exit_code == 0, text
                    assert 'saved-id: https://example.invalid/never-visit (active)' in text, text
                    assert 'neighbor-id: https://example.invalid/neighbor (active)' in text, text
                    assert 'removed-id:' not in text, text
                assert snapshot(root) == before, (layout, legacy)
            if layout == 'missing-column':
                exit_code, text = mutation(root, ['remove', '--case', 'saved-case'])
                assert exit_code == 1 and 'no such column: metadata' in text, text
                assert 'Campaign removed:' not in text and snapshot(root) == before, text
                checks.append({'layout': layout, 'cold_api': 1, 'guarded_cli': 3,
                               'missing_column_fails_before_mutation': True})
                continue
            stored = records(database)
            exit_code, text = mutation(root, ['add', '--case', 'new-case', '--url', 'https://example.invalid/new'])
            assert exit_code == 0 and 'Campaign added:' in text, text
            after_add = records(database)
            assert len(after_add['campaigns']) == len(stored['campaigns'])+1
            # Compare physical tuples without assuming the table's column order.
            for table, rows in stored.items():
                assert all(row in after_add[table] for row in rows), (layout, table)
                if table != 'campaigns': assert after_add[table] == rows
            with closing(sqlite3.connect(database)) as connection:
                named_before = connection.execute('SELECT '+', '.join(COLUMNS)+' FROM campaigns ORDER BY id').fetchall()
                schema_before = connection.execute('SELECT sql FROM sqlite_master ORDER BY name').fetchall()
            exit_code, text = mutation(root, ['remove', '--case', 'saved-case'])
            assert exit_code == 0 and 'Campaign removed: saved-id' in text, text
            with closing(sqlite3.connect(database)) as connection:
                named_after = connection.execute('SELECT '+', '.join(COLUMNS)+' FROM campaigns ORDER BY id').fetchall()
                assert connection.execute('SELECT sql FROM sqlite_master ORDER BY name').fetchall() == schema_before
            expected = [tuple('removed' if index == 4 and row[0] == 'saved-id' else value
                              for index, value in enumerate(row)) for row in named_before]
            assert named_after == expected, (layout, named_before, named_after)
            for table in ('checks', 'alerts', 'victim_intelligence'):
                assert records(database)[table] == stored[table]
            preserved = snapshot(root)
            exit_code, text = mutation(root, ['remove', '--case', 'saved-case'])
            assert exit_code == 1 and 'Campaign removed:' not in text, text
            assert snapshot(root) == preserved
            checks.append({'layout': layout, 'cold_api': 1, 'guarded_cli': 5,
                           'passive_bytes_preserved': True, 'only_selected_status_removed': True})
    print(json.dumps({'status': 'passed', 'cold_api_processes': 5, 'guarded_cli_processes': 23,
        'checks': checks, 'scope': 'Actual declared SQLite layout fixtures and cold API/canonical/legacy CLI. Existing add/remove row effects are checked without visiting stored URLs. API imports guarded; ordinary CLI bootstrap precedes policy. Not private-corpus schema prevalence, live concurrency, OS isolation, authenticity or accuracy.'}, indent=2))


if __name__ == '__main__':
    main()
