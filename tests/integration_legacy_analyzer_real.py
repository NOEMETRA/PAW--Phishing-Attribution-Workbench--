"""Legacy active launcher rejects; actual saved SQLite remains passively readable."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_intelligence_real import REPO, CampaignDatabase, snapshot, invoke as passive_report

SCRIPT = REPO/'run_analyzer.py'
REASON = 'Legacy standalone IP analysis unavailable'


def invoke(root, outside, arguments=(), entry='execute', expected=1):
    code = """import os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
argv=list(sys.argv); path=list(sys.path); cwd=os.getcwd()
threads=set(threading.enumerate())
protected=[os.path.normcase(os.path.abspath(p)) for p in %r]
attempts=[]
def forbid_source_io(event,args):
    if event=='sqlite3.connect':
        attempts.append(event)
        raise AssertionError('Legacy launcher attempted SQLite access')
    if event in ('os.rename','os.link','os.symlink'): paths=args[:2]
    elif event in ('open','os.chdir','os.listdir','os.scandir','os.mkdir','os.remove',
                   'os.rmdir','os.chmod','os.utime','os.truncate'): paths=args[:1]
    else: return
    for value in paths:
        if not isinstance(value,(str,os.PathLike)): continue
        absolute=os.path.normcase(os.path.abspath(value))
        if any(absolute==p or absolute.startswith(p+os.sep) for p in protected):
            attempts.append(event)
            raise AssertionError('Legacy launcher attempted source I/O: '+event)
sys.addaudithook(forbid_source_io)
try:
    with offline_policy():
        entry=%r
        namespace=runpy.run_path(%r,run_name='__main__' if entry=='execute' else 'legacy_import')
        if entry=='main': namespace['main'](%r)
finally:
    assert not attempts and not violations(),(attempts,violations())
    assert os.getcwd()==cwd and sys.argv==argv and sys.path==path,'Process state changed'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('requests','sqlite3','paw.sentinel','paw.sentinel.ip_analyzer',
                 'paw.sentinel.intelligence_analyzer','paw.__main__'):
        assert name not in sys.modules,name
    print('LEGACY_ANALYZER_NO_SOURCE_OR_NETWORK_ACCESS',file=sys.stderr)
""" % (str(REPO),str(SCRIPT),list(arguments),[str(root),str(outside)],entry,str(SCRIPT),list(arguments))
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        capture_output=True,timeout=30)
    output=result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
    assert 'LEGACY_ANALYZER_NO_SOURCE_OR_NETWORK_ACCESS' in output,output
    assert result.returncode==expected,output
    if expected==1: assert REASON in output and result.stdout==b'',output
    if arguments==['--help']: assert 'unavailable' in output and 'check_victims.py' in output,output
    if entry=='import': assert result.stdout==b'',output


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-legacy-analyzer-') as temporary:
        base=Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve()
        base.mkdir(parents=True,exist_ok=True)
        outside=base/'outside'; outside.mkdir()
        (outside/'sentinel.db').write_bytes(b'Outside source must remain unchanged')
        passive_sources=[]
        modes=('missing','saved-default','saved-configured','corrupt','incomplete',
               'pending-journal','wal','invalid-config','config-directory')
        for mode in modes:
            root=base/mode; root.mkdir()
            database=root/'sentinel.db'
            config=root/'sentinel_config.json'
            if mode=='saved-configured':
                database=root/'stored # Ω %.db'
                config.write_text(json.dumps({'storage':{'database_path':database.name}}),encoding='utf-8')
                (root/'sentinel.db').write_bytes(b'Unrelated default must not open')
            elif mode=='invalid-config':
                config.write_bytes(b'{original malformed configuration')
            elif mode=='config-directory':
                config.mkdir(); (config/'original.txt').write_bytes(b'Original source')
            if mode in ('saved-default','saved-configured','pending-journal','wal'):
                writer=CampaignDatabase(str(database))
                with writer.connection() as conn:
                    for case in ('case-2025-11-05T212057Z-88b5','other-case'):
                        conn.execute('INSERT INTO victim_intelligence '
                            '(victim_ip,victim_ua,click_time,phishing_url,case_id,analyzed_status,'
                            'metadata,attacker_correlation) VALUES (?,?,?,?,?,?,CAST(? AS TEXT),?)',
                            ('invalid-ip-fixture','Retained UA Ω','uninterpreted-time',
                             'https://example.invalid/never-visit',case,'captured',b'\x80',
                             '{"operator":"unverified","operator":"duplicate"}'))
                if mode=='pending-journal':
                    Path(str(database)+'-journal').write_bytes(b'Original pending journal')
                elif mode=='wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                else:
                    reader=CampaignDatabase(str(database),read_only=True)
                    source=[reader.get_victim_intelligence(victim_id=i)[0] for i in (2,1)]
                    passive_sources.append((root,database,source))
            elif mode=='corrupt': database.write_bytes(b'Original corrupt database')
            elif mode=='incomplete':
                with closing(sqlite3.connect(database)) as conn,conn:
                    conn.execute('CREATE TABLE unrelated (id INTEGER)')
            before=snapshot(root),snapshot(outside)
            for arguments,expected in (([],1),(['--help'],0)):
                invoke(root,outside,arguments,expected=expected)
                assert (snapshot(root),snapshot(outside))==before,mode
            checks.append({'mode':mode,'execute_and_help_preserve_sources':True})
        root=base/'invalid-config'
        before=snapshot(root),snapshot(outside)
        for arguments,entry,expected in (([],'import',0),([],'main',1),(['--help'],'main',0),
                (['--unsupported'],'main',2),(['--unsupported'],'execute',2),
                (['--case',str(outside)],'execute',2),(['--no-egress'],'execute',2)):
            invoke(root,outside,arguments,entry,expected)
            assert (snapshot(root),snapshot(outside))==before
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        env.pop('PYTHONPATH',None)
        for arguments,expected in (([],1),(['--help'],0)):
            direct=subprocess.run([sys.executable,'-X','utf8',str(SCRIPT),*arguments],cwd=root,
                env=env,capture_output=True,timeout=30)
            assert direct.returncode==expected and b'unavailable' in direct.stdout+direct.stderr
            assert (snapshot(root),snapshot(outside))==before
        for root,database,source in passive_sources:
            before=snapshot(root)
            output=base/(root.name+'-passive.json')
            passive_report(database,output,'saved',None)
            report=json.loads(output.read_text(encoding='utf-8'))
            assert report['source_records']==source
            assert [r['id'] for r in source]==[2,1]
            assert all(r['analyzed_status']=='captured' for r in source)
            assert report['summary']['total_victims']==2 and report['summary']['analyzed_victims']==0
            assert report['evidence_scope']=='stored_rows_unverified'
            assert report['attacker_infrastructure']==[] and report['recommendations']==[]
            assert report['summary']['high_risk_victims'] is None
            assert snapshot(root)==before
    print(json.dumps({'status':'passed','checks':checks,'cold_guarded_legacy_processes':25,
        'direct_stdlib_processes':2,'actual_cold_passive_reports':2,
        'scope':'Actual saved SQLite/configuration/source preservation. Active launcher unavailable before Sentinel imports or observed file/SQLite operations. Existing passive reports retain original rows and typed JSON. Source-file hook is not an OS sandbox; no active collection, accuracy or underlying IP-analyzer validation claim.'},indent=2))


if __name__=='__main__':
    main()
