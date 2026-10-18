"""Actual legacy/canonical geographic report parity and immutable saved SQLite."""
from contextlib import closing
from html import unescape
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_geographic_real import REPO, CampaignDatabase, snapshot
from test_sentinel_database_rows import LEGACY_FIELDS

SCRIPT = REPO/'generate_geo_report.py'


def invoke(root, legacy, arguments):
    # Known CLI bootstrap probes local IPv6 support before application policy.
    code = """import runpy,sys,threading
sys.path.insert(0,%r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy,violations
sys.argv=%r
threads=set(threading.enumerate())
try:
    with offline_policy():
        if %r: runpy.run_path(%r,run_name='__main__')
        else: main()
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('paw.sentinel.monitor','paw.sentinel.ip_analyzer','plotly','pandas'):
        assert name not in sys.modules,name
    if %r:
        assert 'paw.sentinel.intelligence_analyzer' not in sys.modules
        assert 'paw.sentinel.geographic_reports' not in sys.modules
    print('LEGACY_GEOGRAPHIC_PASSIVE_OK')
""" % (str(REPO), ([str(SCRIPT)] if legacy else ['paw','geographic','report'])+arguments,
           legacy, str(SCRIPT), arguments in (['--help'], ['--unsupported']))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'LEGACY_GEOGRAPHIC_PASSIVE_OK' in text,text
    return result.returncode, text


def reports_after(work, before, expected_suffixes):
    after = snapshot(work)
    assert all(after[key] == value for key,value in before.items())
    files = [work/key for key in set(after)-set(before) if after[key] is not None]
    assert len(files) == len(expected_suffixes) and {path.suffix for path in files} == expected_suffixes
    reports = []
    for path in files:
        assert path.parent == work/'reports/geographic'
        text = path.read_text(encoding='utf-8')
        if path.suffix == '.html':
            assert "default-src 'none'" in text and '<script' not in text
            text = unescape(text.split('<pre>',1)[1].split('</pre>',1)[0])
        report = json.loads(text)
        assert report['evidence_scope'] == 'stored_rows_unverified'
        assert report['summary']['risk_assessment']['status'] == 'unavailable'
        assert report['unavailable']['identity']
        report.pop('generated_at')  # Actual invocation time; no other field is excluded.
        reports.append(report)
    assert all(report == reports[0] for report in reports)
    return reports[0]


def main():
    scenarios = [
        ('help',['--help'],0,set(),None), ('unsupported',['--unsupported'],2,set(),None),
        ('missing',[],1,set(),None), ('configured-missing',[],1,set(),None),
        ('all',[],0,{'.json','.html'},103), ('case',['--case','older','--output','json'],0,{'.json'},101),
        ('empty-case',['--case','','--output','json'],0,{'.json'},1),
        ('threshold',['--min-confidence','1','--output','json'],0,{'.json'},103),
        ('html',['--output','html'],0,{'.html'},103), ('legacy',['--output','json'],0,{'.json'},1),
        ('corrupt',[],1,set(),None), ('bad-config',[],1,set(),None),
        ('duplicate-config',[],1,set(),None), ('config-directory',[],1,set(),None),
        ('wal',[],1,set(),None), ('journal',[],1,set(),None), ('output-blocked',[],1,set(),None)]
    with tempfile.TemporaryDirectory(prefix='paw-legacy-geographic-') as temporary:
        root = Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve()
        root.mkdir(parents=True,exist_ok=True)
        for mode,arguments,expected_code,suffixes,total in scenarios:
            work = root/mode; work.mkdir()
            database = work/'stored # Ω %.db'
            config = work/'sentinel_config.json'
            config.write_text(json.dumps({'storage':{'database_path':database.name}}),encoding='utf-8')
            if mode in ('all','case','empty-case','threshold','html','wal','journal','output-blocked'):
                writer = CampaignDatabase(str(database))
                with writer.connection() as conn:
                    for index,case in enumerate(['older']*101+['newer','']):
                        conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,'
                            'case_id,interaction_confidence,interaction_type,geolocation_data) VALUES (?,?,?,?,?,?,?)',
                            ('192.0.2.1',str(index),'https://example.invalid/',case,0.8,'stored-label',
                             json.dumps({'country':'Stored Ω','lat':0,'lon':0})))
                if mode == 'wal':
                    with closing(sqlite3.connect(database)) as conn: conn.execute('PRAGMA journal_mode=WAL')
                if mode == 'journal': Path(str(database)+'-journal').write_bytes(b'preserved pending journal')
                if mode == 'output-blocked': (work/'reports').write_bytes(b'preserved output blocker')
            elif mode == 'legacy':
                with closing(sqlite3.connect(database)) as conn, conn:
                    conn.execute('CREATE TABLE victim_intelligence ('+', '.join(key+' '+sql for key,sql in LEGACY_FIELDS)+')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,geolocation_data) VALUES (?,?,?,?)',
                        ('192.0.2.1','stored','https://example.invalid/','{"lat":0,"lon":0}'))
            elif mode == 'corrupt': database.write_bytes(b'preserved corrupt source')
            elif mode == 'missing': config.unlink()
            elif mode == 'configured-missing':
                config.write_text(json.dumps({'storage':{'database_path':'absent/source.db'}}),encoding='utf-8')
            elif mode == 'bad-config': config.write_bytes(b'{preserved malformed config')
            elif mode == 'duplicate-config':
                config.write_text('{"storage":{"database_path":"stored.db"},"storage":{"database_path":"sentinel.db"}}',encoding='utf-8')
            elif mode == 'config-directory': config.unlink(); config.mkdir()
            outputs, texts = [], []
            for legacy in (True,False):
                before = snapshot(work)
                code,text = invoke(work,legacy,arguments)
                assert code == expected_code,(mode,legacy,code,text)
                texts.append('\n'.join(line for line in text.splitlines() if not line.startswith('Written: ')))
                if total is None:
                    assert snapshot(work) == before,(mode,legacy)
                    if expected_code: assert 'Selected stored rows:' not in text
                else:
                    report = reports_after(work,before,suffixes)
                    assert report['total_records'] == len(report['source_records']) == total
                    assert report['case_id'] == ('older' if mode == 'case' else '' if mode == 'empty-case' else None)
                    if mode == 'threshold': assert report['selection']['included_ids'] == []
                    else: assert len(report['selection']['included_ids']) == total
                    outputs.append(report)
            assert texts[0] == texts[1],(mode,texts)
            if outputs: assert outputs[0] == outputs[1],mode
        work = root/'import'; work.mkdir()
        env = dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        env.pop('PYTHONPATH',None)
        imported = subprocess.run([sys.executable,'-X','utf8','-c',
            "import runpy,sys; before=list(sys.argv); runpy.run_path(%r,run_name='legacy_import'); assert sys.argv==before; assert 'paw' not in sys.modules" % str(SCRIPT)],
            cwd=work,env=env,capture_output=True,timeout=30)
        assert imported.returncode == 0,imported.stderr
        direct = subprocess.run([sys.executable,'-X','utf8',str(SCRIPT),'--help'],cwd=work,
            env=env,capture_output=True,timeout=30)
        assert direct.returncode == 0 and b'--case' in direct.stdout,direct.stderr
        assert snapshot(work) == {}
    print('PASS: 17 paired legacy/canonical geographic modes, 34 actual guarded dispatches, '
          'inert import and direct help; complete saved/legacy rows, source/config/report preservation, '
          'explicit missing/invalid/WAL/journal/output errors, JSON/HTML/filters, no active analyzer. '
          'Only generated_at/output names differ; no cold-bootstrap/OS isolation or concurrent-writer snapshot claim.')


if __name__ == '__main__':
    main()
