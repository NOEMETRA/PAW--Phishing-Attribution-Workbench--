"""Actual offline CLI campaign admission and SQLite mutations; no target visits."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, CampaignDatabase, snapshot


def invoke(root, arguments, *, invalid=False, race=None):
    # Normal CLI bootstrap precedes the Python guard (urllib3's local IPv6 probe).
    code = """import sys,threading,sqlite3
sys.path.insert(0,%r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy,violations
sys.argv=['paw','monitor']+%r
race=%r
if race:
    from paw.sentinel.database import CampaignDatabase
    original=CampaignDatabase.__init__
    def changed_source(self,db_path='sentinel.db',*,read_only=False,limits=None):
        if not read_only:
            with sqlite3.connect(db_path) as c:
                if race=='removed':
                    c.execute("UPDATE campaigns SET status='removed' WHERE case_id='target'")
                else:
                    c.execute("DELETE FROM campaigns WHERE case_id='target'")
        original(self,db_path,read_only=read_only,limits=limits)
    CampaignDatabase.__init__=changed_source
threads=set(threading.enumerate())
try:
    with offline_policy():
        main()
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    if %r:
        assert 'paw.sentinel' not in sys.modules,'Invalid arguments accessed Sentinel'
    print('CAMPAIGN_NO_COLLECTION_OR_BLOCKED_OPERATIONS')
""" % (str(REPO), arguments, race, invalid)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'CAMPAIGN_NO_COLLECTION_OR_BLOCKED_OPERATIONS' in text, text
    return result.returncode, text


def records(database):
    with closing(sqlite3.connect(database)) as conn:
        return {table: conn.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()
                for table in ('campaigns','checks','alerts','victim_intelligence')}


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-campaign-cli-') as temporary:
        root = Path(temporary)
        for mode in ('missing','invalid-config','corrupt','legacy'):
            work = root / mode
            work.mkdir()
            if mode == 'invalid-config':
                (work/'sentinel_config.json').write_bytes(b'{original malformed config')
            elif mode == 'corrupt':
                (work/'sentinel.db').write_bytes(b'original corrupt storage')
            elif mode == 'legacy':
                CampaignDatabase(str(work/'sentinel.db'))
                with closing(sqlite3.connect(work/'sentinel.db')) as conn, conn:
                    conn.execute('DROP TABLE victim_intelligence')
            before = snapshot(work)
            for arguments in (['add'],['add','--case','target'],
                              ['add','--case',' ','--url','https://example.invalid/never-visit'],
                              ['add','--case','target','--url','\t'],['remove'],
                              ['remove','--case','\t']):
                exit_code, text = invoke(work, arguments, invalid=True)
                assert exit_code == 1 and 'nonblank' in text, text
                assert snapshot(work) == before, (mode, arguments)
                checks.append({'mode': mode, 'arguments': arguments, 'source_preserved': True})

        for mode in ('absent','configured-absent','saved','legacy','removed','corrupt','journal','wal','ambiguous'):
            work = root / ('remove-'+mode)
            work.mkdir()
            database = work/'saved # Ω %.db'
            (work/'sentinel_config.json').write_text(json.dumps(
                {'storage': {'database_path': database.name}}), encoding='utf-8')
            if mode == 'configured-absent':
                (work/'sentinel_config.json').write_text(json.dumps(
                    {'storage': {'database_path': 'absent/target.db'}}), encoding='utf-8')
            elif mode == 'corrupt':
                database.write_bytes(b'original corrupt storage')
            elif mode != 'absent':
                writer = CampaignDatabase(str(database))
                campaign = writer.add_campaign('target' if mode in ('removed','ambiguous') else 'neighbor',
                                               'https://example.invalid/never-visit')
                if mode == 'removed':
                    writer.update_campaign_status(campaign, 'removed')
                elif mode == 'legacy':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE victim_intelligence')
                elif mode == 'journal':
                    Path(str(database)+'-journal').write_bytes(b'original pending journal')
                elif mode == 'wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                elif mode == 'ambiguous':
                    # Actual legacy SQLite table without today's unique-case constraint.
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('CREATE TABLE old_campaigns AS SELECT * FROM campaigns')
                        conn.execute('DROP TABLE campaigns')
                        conn.execute('ALTER TABLE old_campaigns RENAME TO campaigns')
                        conn.execute("INSERT INTO campaigns SELECT 'other-id',case_id,created_at,last_check,status,url,domain,title,description,risk_level,metadata FROM campaigns")
            before = snapshot(work)
            exit_code, text = invoke(work, ['remove','--case','target'])
            assert exit_code == 1 and 'Campaign removed:' not in text, text
            assert snapshot(work) == before, mode
            checks.append({'mode': mode, 'action': 'remove', 'source_preserved': True})

        work = root/'mutations'
        work.mkdir()
        database = work/'sentinel.db'
        for case in ('target','neighbor'):
            exit_code, text = invoke(work, ['add','--case',case,'--url','https://example.invalid/'+case])
            assert exit_code == 0 and 'Campaign added:' in text, text
        before = records(database)
        exit_code, text = invoke(work, ['add','--case','target','--url','https://example.invalid/replacement'])
        assert exit_code == 1 and records(database) == before, text
        exit_code, text = invoke(work, ['remove','--case','target'])
        assert exit_code == 0 and 'Campaign removed:' in text, text
        after = records(database)
        expected = dict(before)
        expected['campaigns'] = [tuple('removed' if index==4 and row[1]=='target' else value
                                     for index,value in enumerate(row)) for row in before['campaigns']]
        assert after == expected, (before, after)
        preserved = snapshot(work)
        exit_code, text = invoke(work, ['remove','--case','target'])
        assert exit_code == 1 and snapshot(work) == preserved, text
        checks.append({'mode': 'mutations', 'processes': 5, 'only_selected_status_changed': True,
                       'duplicate_add_preserved_rows': True, 'repeat_remove_preserved_source': True})

        for race in ('removed','deleted'):
            work = root/race
            work.mkdir()
            CampaignDatabase(str(work/'sentinel.db')).add_campaign('target','https://example.invalid/stored')
            exit_code, text = invoke(work, ['remove','--case','target'], race=race)
            assert exit_code == 1 and 'Campaign changed before removal' in text, text
            assert 'Campaign removed:' not in text, text
            checks.append({'mode': race, 'fault_injection': 'actual SQLite change after preflight',
                           'false_removal_success': False})
    print(json.dumps({'status':'passed', 'cold_cli_processes':40, 'checks':checks,
        'scope':'Actual SQLite and offline CLI dispatch after normal bootstrap. Successful mutations retain default writer initialization. Fault injections are race regression fixtures, not live concurrent-writer proof or OS isolation.'}, indent=2))


if __name__ == '__main__':
    main()
