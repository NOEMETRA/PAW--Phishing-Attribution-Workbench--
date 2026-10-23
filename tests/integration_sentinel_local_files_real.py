"""Actual passive local-file CLI checks ignore unrelated campaign storage."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, CampaignDatabase, snapshot
from paw.core.evidence import seal_case


def invoke(root, action):
    code = """import sys
sys.path.insert(0,%r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy,violations
sys.argv=['paw','monitor',%r]
try:
    with offline_policy(): main()
finally:
    assert not violations(),violations()
    for name in ('config','database','monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('LOCAL_FILES_NO_CAMPAIGN_STORAGE_OR_COLLECTORS')
""" % (str(REPO), action)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'LOCAL_FILES_NO_CAMPAIGN_STORAGE_OR_COLLECTORS' in text, text
    return result.returncode, text


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-local-file-cli-') as temporary:
        root = Path(temporary)
        for mode in ('missing-cases', 'empty-cases', 'saved', 'invalid-config',
                     'config-directory', 'corrupt-database', 'legacy-database',
                     'wal-database', 'journal-database'):
            work = root / mode
            work.mkdir()
            config = work / 'sentinel_config.json'
            database = work / 'sentinel.db'
            if mode == 'invalid-config': config.write_bytes(b'{original malformed config')
            elif mode == 'config-directory': config.mkdir()
            elif mode == 'corrupt-database': database.write_bytes(b'original corrupt database')
            elif mode in ('saved', 'legacy-database', 'wal-database', 'journal-database'):
                writer = CampaignDatabase(str(database))
                writer.add_campaign('unrelated-stored-case', 'https://example.invalid/never-visit')
                if mode == 'legacy-database':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE victim_intelligence')
                elif mode == 'wal-database':
                    with closing(sqlite3.connect(database)) as conn: conn.execute('PRAGMA journal_mode=WAL')
                elif mode == 'journal-database':
                    Path(str(database)+'-journal').write_bytes(b'original pending journal')
            cases = work / 'cases'
            if mode != 'missing-cases': cases.mkdir()
            if mode not in ('missing-cases', 'empty-cases'):
                for name in ('case-sealed', 'case-tampered', 'case-unsealed'):
                    case = cases / name
                    case.mkdir()
                    (case/'input.eml').write_bytes(b'Original case bytes')
                    (case/'.hidden-source').write_bytes(b'Literal hidden fixture bytes')
                    (case/'saved.pyc').write_bytes(b'Literal opaque fixture bytes; never executed')
                    if name != 'case-unsealed': seal_case(case)
                    if name == 'case-tampered': (case/'input.eml').write_bytes(b'Changed case bytes')
            before = snapshot(work)
            for action in ('files', 'integrity'):
                exit_code, text = invoke(work, action)
                assert exit_code == 0, text
                assert 'all single-link regular files; no filename or extension exclusions' in text, text
                assert 'hidden/pyc exclusions' not in text, text
                if action == 'integrity':
                    expected = (0, 0, 0) if mode in ('missing-cases', 'empty-cases') else (1, 1, 1)
                    for label, count in zip(('Integrity OK', 'Compromised', 'Unknown'), expected):
                        assert f'{label}: {count}' in text, text
                    if mode not in ('missing-cases', 'empty-cases'):
                        for case in sorted(cases.iterdir()):
                            assert f'{case.name}: {sum(p.is_file() for p in case.rglob("*"))} files' in text, text
                else:
                    assert 'first scan is not historical change detection' in text, text
                    if mode in ('missing-cases', 'empty-cases'): assert 'No case observations returned' in text, text
                    else:
                        for name in ('case-sealed', 'case-tampered', 'case-unsealed'):
                            assert name in text, text
                            section=text.split('Case: '+name,1)[1].split('\n📁 Case:',1)[0]
                            count=sum(p.is_file() for p in (cases/name).rglob('*'))
                            assert f'New files: {count}' in section, text
                assert snapshot(work) == before, (mode, action)
                checks.append({'case': mode, 'action': action, 'exit_code': exit_code,
                               'source_tree_unchanged': True})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Actual cold CLI bootstrap then guarded local-file dispatch; zero blocked operations, no campaign database/config or collectors.',
        'scope': 'Constructed actual seals/tampering/unsealed files, not authenticity or classification evidence. Live worker admission is checked in integration_cli_api_real.py.'}, indent=2))


if __name__ == '__main__':
    main()
