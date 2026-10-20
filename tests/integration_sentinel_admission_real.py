"""Cold configured storage consumers preserve failed sources and actual SQLite effects."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, CampaignDatabase, snapshot


def invoke(root, *, arguments=None, body='', expected=0):
    code='''import json,os,sqlite3,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
arguments=%r
if arguments is not None:
    from paw.__main__ import main
    sys.argv=['paw','monitor']+arguments
threads=set(threading.enumerate())
try:
    with offline_policy():
        if arguments is not None: main()
        else:
%s
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread remains'
    for name in ('monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('STORAGE_ADMISSION_NO_COLLECTION',file=sys.stderr)
''' % (str(REPO),arguments,'\n'.join('            '+line for line in body.splitlines()) or '            pass')
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1'); env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,capture_output=True,timeout=30)
    output=(result.stdout+result.stderr).decode('utf-8')
    assert result.returncode==expected and 'STORAGE_ADMISSION_NO_COLLECTION' in output,output
    if arguments is not None and expected:
        assert 'Campaign added:' not in output and 'Campaign removed:' not in output,output
    return {'entry':'CLI' if arguments is not None else 'API','arguments':arguments,'exit':result.returncode}


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-sentinel-admission-real-') as temporary:
        base=Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve(); base.mkdir(parents=True,exist_ok=True)
        commands=(['list'],['status'],['add','--case','selected','--url','https://example.invalid/never-visit'],['remove','--case','selected'])
        invalid=('null','false','[]','{"storage":1}','{"storage":{"database_path":""}}',
                 '{"storage":{"database_path":"one.db","database_path":"two.db"}}',
                 '{"number":NaN}','{"storage":{"database_path":":memory:"}}')
        for index,source in enumerate(invalid):
            root=base/('invalid-'+str(index)); root.mkdir()
            (root/'sentinel_config.json').write_text(source,encoding='utf-8')
            before=snapshot(root)
            for args in commands:
                checks.append(invoke(root,arguments=args,expected=1)); assert snapshot(root)==before
        for mode in ('view','unrelated','corrupt','journal','wal'):
            root=base/mode; root.mkdir(); path=root/'saved # Ω %.db'
            (root/'sentinel_config.json').write_text(json.dumps({'storage':{'database_path':path.name}}),encoding='utf-8')
            if mode in ('view','unrelated'):
                with closing(sqlite3.connect(path)) as conn,conn:
                    conn.execute('CREATE TABLE original (value TEXT)'); conn.execute("INSERT INTO original VALUES ('original')")
                    if mode=='view': conn.execute('CREATE VIEW victim_intelligence AS SELECT * FROM original')
            elif mode=='corrupt': path.write_bytes(b'original non-SQLite bytes')
            else:
                CampaignDatabase(str(path)).add_campaign('retained','literal',{'source':'retained'})
                if mode=='journal': Path(str(path)+'-journal').write_bytes(b'declared pending journal')
                else:
                    with closing(sqlite3.connect(path)) as conn: conn.execute('PRAGMA journal_mode=WAL')
            before=snapshot(root)
            for args in (commands[0],commands[2]):
                checks.append(invoke(root,arguments=args,expected=1)); assert snapshot(root)==before
        root=base/'success'; root.mkdir()
        path=root/'selected # Ω %.db'
        (root/'sentinel_config.json').write_text(json.dumps({'storage':{'database_path':path.name}}),encoding='utf-8')
        checks.append(invoke(root,arguments=commands[2]))
        with closing(sqlite3.connect(path)) as conn:
            row=conn.execute('SELECT case_id,url,status FROM campaigns').fetchone()
            assert row==('selected','https://example.invalid/never-visit','active'),row
        before=snapshot(root)
        for args in commands[:2]:
            checks.append(invoke(root,arguments=args)); assert snapshot(root)==before
        checks.append(invoke(root,arguments=commands[3]))
        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute('SELECT status FROM campaigns').fetchone()==('removed',)
        assert not (root/'sentinel.db').exists()
        api_bodies=[
'''from pathlib import Path
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.config import SentinelConfig
first=Path('first'); first.mkdir(); other=Path('other'); other.mkdir()
previous=Path.cwd()
try:
    os.chdir(first)
    config=SentinelConfig(); db=CampaignDatabase(config.get('storage.database_path'))
    identifier=db.add_campaign('original','literal',{'source':'original'})
    chosen=Path(db.db_path)
    os.chdir(previous/other)
    assert config.get('storage.database_path')==str(chosen)
    assert db.get_campaign(identifier)['metadata']=={'source':'original'}
    config.set('storage.retention_days',7)
    assert not Path('sentinel.db').exists() and not Path('sentinel_config.json').exists()
finally: os.chdir(previous)''',
'''from pathlib import Path
from paw.sentinel.database import CampaignDatabase
path=Path('source.db'); database=CampaignDatabase(str(path))
identifier=database.add_campaign('original','literal')
path.rename('retained.db')
CampaignDatabase(str(path)).add_campaign('replacement','literal')
before=path.read_bytes()
try: database.get_active_campaigns()
except ValueError: pass
else: raise AssertionError('Replacement source silently adopted')
assert path.read_bytes()==before
path.unlink()
try: database.get_campaign(identifier)
except FileNotFoundError: pass
else: raise AssertionError('Missing source recreated')
assert not path.exists()''',
'''from pathlib import Path
from unittest.mock import patch
from paw.sentinel.database import CampaignDatabase
path=Path('source.db')
with sqlite3.connect(path) as conn:
    conn.execute('CREATE TABLE victim_intelligence (id INTEGER, original TEXT)')
    conn.execute("INSERT INTO victim_intelligence VALUES (1,'retained')")
before=path.read_bytes()
def failed(self,conn):
    conn.execute('ALTER TABLE victim_intelligence ADD COLUMN partially_added TEXT')
    raise OSError('declared failed migration')
with patch.object(CampaignDatabase,'_migrate_database',failed):
    try: CampaignDatabase(str(path))
    except OSError: pass
    else: raise AssertionError('Failed migration acknowledged')
assert path.read_bytes()==before''',
'''from pathlib import Path
from unittest.mock import patch
from paw.sentinel.config import SentinelConfig
path=Path('source.json'); path.write_text('{"storage":{"database_path":"selected.db"}}')
config=SentinelConfig(str(path)); before=path.read_bytes()
with patch('os.replace',side_effect=OSError('declared failed publication')):
    try: config.set('new_field',True)
    except OSError: pass
    else: raise AssertionError('Failed publication acknowledged')
assert path.read_bytes()==before and config.get('new_field') is None
assert not list(Path('.').glob('.sentinel-config-*'))''',
        ]
        for index,body in enumerate(api_bodies):
            root=base/('api-'+str(index)); root.mkdir(); checks.append(invoke(root,body=body))
    print(json.dumps({'status':'passed','checks':checks,'cold_cli_processes':46,'cold_api_processes':4,
        'scope':'Actual cold configured CLI/API, SQLite transactions and source byte preservation; malformed sources, migration and publication faults are declared fixtures. No remote collection, filesystem isolation, cross-process snapshot, authenticity or accuracy claim.'},indent=2))


if __name__=='__main__': main()
