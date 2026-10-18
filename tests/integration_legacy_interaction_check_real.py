"""Cold passive legacy diagnostic: complete actual SQLite sources and explicit errors."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, CampaignDatabase, snapshot
from test_sentinel_database_rows import LEGACY_FIELDS

SCRIPT = REPO / 'check_victims.py'


def invoke(root, arguments=(), *, import_only=False, deny_config_read=False, script=SCRIPT):
    # This diagnostic does not bootstrap the CLI or optional network libraries.
    code = """import builtins,io,os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
before=list(sys.argv)
cwd=os.getcwd()
threads=set(threading.enumerate())
if %r:
    # Explicit read-failure injection; source bytes and SQLite remain real.
    def denied_open(original):
        def opening(path,*args,**kwargs):
            if isinstance(path,(str,os.PathLike)) and os.path.abspath(path)==os.path.join(cwd,'sentinel_config.json'):
                raise PermissionError('Explicit configuration read-denial regression fixture')
            return original(path,*args,**kwargs)
        return opening
    builtins.open=denied_open(builtins.open)
    io.open=denied_open(io.open)
try:
    with offline_policy():
        runpy.run_path(%r,run_name=%r)
finally:
    assert not violations(),violations()
    assert os.getcwd()==cwd,'Diagnostic changed the working directory'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('requests','paw.__main__','paw.sentinel.monitor','paw.sentinel.ip_analyzer',
                 'paw.sentinel.intelligence_analyzer','paw.sentinel.geographic_reports','plotly','pandas'):
        assert name not in sys.modules,name
    if %r:
        assert sys.argv==before,'Import changed arguments'
        assert 'paw.sentinel' not in sys.modules,'Argument/import path accessed Sentinel'
    print('LEGACY_INTERACTIONS_PASSIVE_OK',file=sys.stderr)
""" % (str(REPO), str(script), list(arguments), deny_config_read, str(script),
           'legacy_import' if import_only else '__main__', import_only or bool(arguments))
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    assert b'LEGACY_INTERACTIONS_PASSIVE_OK' in result.stderr,result.stderr.decode('utf-8')
    return result.returncode,result.stdout.decode('utf-8'),result.stderr.decode('utf-8')


def main(script=SCRIPT):
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-legacy-interactions-') as temporary:
        root=Path(temporary)
        for mode in ('saved-default','saved-configured','empty','legacy','missing-default','configured-missing',
                     'corrupt','incomplete','journal','wal','native-blob','native-nonfinite',
                     'invalid-config','config-directory'):
            work=root/mode
            work.mkdir()
            database=work/'sentinel.db'
            config=work/'sentinel_config.json'
            if mode not in ('saved-default','missing-default'):
                database=work/'stored # Ω %.db'
                config.write_text(json.dumps({'storage':{'database_path':database.name}}),encoding='utf-8')
                if mode!='config-directory':
                    (work/'sentinel.db').write_bytes(b'unrelated default storage; must not open')
            if mode=='configured-missing':
                config.write_text(json.dumps({'storage':{'database_path':'absent/target.db'}}),encoding='utf-8')
            elif mode=='corrupt':
                database.write_bytes(b'original corrupt database')
            elif mode=='incomplete':
                with closing(sqlite3.connect(database)) as conn,conn:
                    conn.execute('CREATE TABLE unrelated (id INTEGER)')
            elif mode=='invalid-config':
                config.write_bytes(b'{original malformed configuration')
            elif mode=='config-directory':
                config.unlink()
                config.mkdir()
                (config/'original.txt').write_bytes(b'original source')
                # A valid unrelated fallback must not mask configuration failure.
                fallback=CampaignDatabase(str(work/'sentinel.db'))
                fallback.add_victim_intelligence('192.0.2.2','Unrelated fallback row',
                                                'https://example.invalid/fallback')
            elif mode=='legacy':
                with closing(sqlite3.connect(database)) as conn,conn:
                    conn.execute('CREATE TABLE victim_intelligence ('+', '.join(k+' '+sql for k,sql in LEGACY_FIELDS)+')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip,victim_ua,click_time,phishing_url,metadata) VALUES (?,?,?,?,CAST(? AS TEXT))',
                                 ('192.0.2.1','Stored UA Ω','not-a-time','https://example.invalid/never-visit',b'\x80'))
            elif mode not in ('missing-default','configured-missing'):
                writer=CampaignDatabase(str(database))
                if mode!='empty':
                    with writer.connection() as conn:
                        for index in range(210):
                            metadata=(b'\x80' if index==0 else b'{"a":1,"a":2}' if index==1 else b'{"stored":true}')
                            conn.execute('INSERT INTO victim_intelligence (victim_ip,victim_ua,click_time,phishing_url,case_id,risk_score,metadata) VALUES (?,?,?,?,?,?,CAST(? AS TEXT))',
                                ('192.0.2.1',None if index==2 else 'Stored UA Ω '+str(index),f'raw-{index:04}',
                                 'https://example.invalid/never-visit',None if index==3 else str(index),7,metadata))
                        if mode=='native-blob':
                            conn.execute('UPDATE victim_intelligence SET victim_ua=? WHERE id=1',(b'original native blob',))
                        elif mode=='native-nonfinite':
                            conn.execute('UPDATE victim_intelligence SET risk_score=? WHERE id=1',(float('inf'),))
                    if mode=='journal':
                        Path(str(database)+'-journal').write_bytes(b'original pending journal')
                    elif mode=='wal':
                        with closing(sqlite3.connect(database)) as conn:
                            conn.execute('PRAGMA journal_mode=WAL')
            expected=None
            if mode in ('saved-default','saved-configured','empty','legacy'):
                expected=CampaignDatabase(str(database),read_only=True).get_victim_statistics()
            before=snapshot(work)
            exit_code,output,error=invoke(work,script=script)
            assert snapshot(work)==before,mode
            if expected is None:
                assert exit_code==1 and output=='' and 'error:' in error,(mode,exit_code,output,error)
                checks.append({'mode':mode,'explicit_error_without_report':True,'sources_preserved':True})
                continue
            assert exit_code==0,(mode,error)
            report=json.loads(output)
            assert report==expected,mode
            assert report['evidence_scope']=='stored_rows_unverified'
            assert report['total_victims']==len(report['source_records'])
            assert report['recent_victims_24h'] is None and report['unavailable']['identity']
            if mode.startswith('saved-'):
                records=report['source_records']
                assert [r['id'] for r in records]==list(range(210,0,-1))
                assert records[0]['victim_ua']=='Stored UA Ω 209'
                assert records[-1]['victim_ip']=='192.0.2.1' and records[-1]['click_time']=='raw-0000'
                assert records[-1]['json_evidence']['fields']['metadata']['raw_storage']=={
                    'type':'text','encoding':'base64','value':'gA=='}
                assert records[-2]['json_evidence']['fields']['metadata']['status']=='duplicate_keys'
                assert records[-3]['victim_ua'] is None and records[-4]['case_id'] is None
            if mode=='empty':
                assert report['total_victims']==0 and report['source_records']==[]
            checks.append({'mode':mode,'source_records':len(report['source_records']),
                           'complete_api_parity':True,'sources_preserved':True})
            if mode=='saved-configured':
                env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
                env.pop('PYTHONPATH',None)
                direct=subprocess.run([sys.executable,'-X','utf8',str(script)],cwd=work,env=env,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
                assert direct.returncode==0 and json.loads(direct.stdout)==report,direct.stderr
                assert snapshot(work)==before
        for mode,config_text in (
                ('empty-object','{}'),('null','null'),
                ('duplicate-path','{"storage":{"database_path":"missing.db","database_path":"sentinel.db"}}'),
                ('denied-read','{"storage":{"database_path":"configured.db"}}')):
            work=root/('config-'+mode)
            work.mkdir()
            (work/'sentinel_config.json').write_text(config_text,encoding='utf-8')
            fallback=CampaignDatabase(str(work/'sentinel.db'))
            fallback.add_victim_intelligence('192.0.2.2','Unrelated fallback row',
                                            'https://example.invalid/fallback')
            before=snapshot(work)
            exit_code,output,error=invoke(work,deny_config_read=mode=='denied-read',script=script)
            assert exit_code==1 and output=='' and 'error:' in error,(mode,exit_code,output,error)
            if mode=='denied-read':
                assert 'read-denial regression fixture' in error,error
            assert snapshot(work)==before,mode
            checks.append({'mode':'config-'+mode,'explicit_error_without_report':True,
                           'valid_unrelated_default_not_reported':True,'sources_preserved':True})
        work=root/'arguments-and-import'
        work.mkdir()
        (work/'sentinel_config.json').write_bytes(b'{must not access')
        before=snapshot(work)
        for arguments,expected_code in ((['--help'],0),(['--unsupported'],2)):
            exit_code,output,error=invoke(work,arguments,script=script)
            assert exit_code==expected_code,(arguments,error)
            assert snapshot(work)==before
        exit_code,output,error=invoke(work,import_only=True,script=script)
        assert exit_code==0 and output=='' and snapshot(work)==before,error
    print(json.dumps({'status':'passed','script':script.name,'processes':22,'checks':checks,
        'scope':'21 actual cold guarded diagnostic/import/argument processes, plus one direct saved-source execution outside checkout without PYTHONPATH. Configuration read denial is explicitly injected, not an OS ACL proof. No collector/CLI bootstrap, new thread, blocked operation or source mutation in guarded processes. Not OS containment, live-writer snapshot, authentication or identity/accuracy evidence.'},indent=2))


if __name__=='__main__':
    for script in (SCRIPT, REPO/'check_db_fields.py'):
        main(script)
