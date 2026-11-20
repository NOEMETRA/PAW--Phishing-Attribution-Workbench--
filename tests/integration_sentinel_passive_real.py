"""Actual CLI monitor list dispatch preserves saved/missing Sentinel storage."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.sentinel.database import CampaignDatabase


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


def invoke(root, action='list', *options):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    # Bootstrap imports before guarded dispatch, as in the existing actual CLI
    # integrations; a cold urllib3 import probes IPv6 with a local socket.
    code = """import sys
sys.path.insert(0, %r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy, violations
sys.argv=['paw', 'monitor'] + %r
try:
    with offline_policy():
        main()
finally:
    assert not violations(), violations()
    for name in ('monitor', 'ip_analyzer', 'intelligence_analyzer', 'geographic_reports'):
        assert 'paw.sentinel.' + name not in sys.modules, name
    print('SENTINEL_PASSIVE_NO_BLOCKED_OPERATIONS')
""" % (str(REPO), [action, *options])
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'SENTINEL_PASSIVE_NO_BLOCKED_OPERATIONS' in text, text
    return result.returncode, text


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-sentinel-passive-cli-') as temporary:
        root = Path(temporary)
        for name in ('missing-default', 'missing-configured', 'existing', 'legacy', 'corrupt', 'empty', 'wal'):
            work = root / name
            work.mkdir()
            database = work / 'sentinel.db'
            if name == 'missing-configured':
                (work / 'sentinel_config.json').write_text(json.dumps(
                    {'storage': {'database_path': 'absent/target.db'}}), encoding='utf-8')
            elif name in ('existing', 'legacy', 'wal'):
                if name == 'existing':
                    database = work / 'stored # Ω %.db'
                    (work / 'sentinel_config.json').write_text(json.dumps(
                        {'storage': {'database_path': database.name}}), encoding='utf-8')
                writer = CampaignDatabase(str(database))
                writer.add_campaign('saved-active', 'https://example.invalid/stored-active')
                removed = writer.add_campaign('saved-removed', 'https://example.invalid/stored-removed')
                writer.update_campaign_status(removed, 'removed')
                if name == 'legacy':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE victim_intelligence')
                elif name == 'wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
            elif name == 'corrupt':
                database.write_bytes(b'original damaged source')
            elif name == 'empty':
                with closing(sqlite3.connect(database)):
                    pass
            before = snapshot(work)
            code, text = invoke(work)
            if name in ('existing', 'legacy'):
                assert code == 0, text
                assert 'stored-active' in text and 'stored-removed' not in text, text
            else:
                assert code != 0, text
                assert 'No active campaigns' not in text, text
            assert snapshot(work) == before, name
            checks.append({'case': name, 'exit_code': code, 'source_tree_unchanged': True})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Real CLI list under offline dispatch; zero blocked attempts; no monitoring/enrichment imports'}, indent=2))


if __name__ == '__main__':
    main()
