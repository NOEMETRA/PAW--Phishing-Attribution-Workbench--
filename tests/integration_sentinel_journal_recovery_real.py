"""Recover a disposable copy after SIGKILL during an uncommitted SQLite spill."""
from contextlib import closing
import hashlib
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from paw.sentinel.database import CampaignDatabase


def snapshot(directory):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}


def records(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as conn:
        return {name: conn.execute(f'SELECT * FROM {name} ORDER BY id').fetchall()
                for name in ('campaigns', 'checks', 'alerts')}


def main():
    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        source = root / 'source'
        source.mkdir()
        original = source / 'sentinel.db'
        writer = CampaignDatabase(str(original))
        campaign = writer.add_campaign('lab', 'http://127.0.0.1/')
        for _ in range(32):
            writer.record_check(campaign, 'supplied', metadata={'note':'a' * 8192})
        writer.record_alert(campaign, 'supplied', 'stored')
        committed = records(original)
        before = snapshot(source)
        # Spill actual dirty pages to the primary file before dying. The
        # fixture process is the only owner of the source during this phase.
        code = """
import os, signal, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
assert conn.execute('PRAGMA journal_mode=DELETE').fetchone()[0] == 'delete'
conn.execute('PRAGMA synchronous=FULL')
conn.execute('PRAGMA cache_size=3')
conn.execute('BEGIN IMMEDIATE')
conn.execute("UPDATE checks SET metadata=replace(metadata,'aaaa','bbbb')")
conn.execute("UPDATE alerts SET message='uncommitted'")
os.kill(os.getpid(), signal.SIGKILL)
"""
        import signal
        killed = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(original)], timeout=15)
        assert killed.returncode == -signal.SIGKILL
        crashed = snapshot(source)
        assert 'sentinel.db-journal' in crashed and crashed[original.name] != before[original.name]
        assert original.with_name('sentinel.db-journal').read_bytes()[:8] == bytes.fromhex('d9d505f920a163d7')
        try:
            CampaignDatabase(str(original), read_only=True)
        except ValueError as exc:
            assert 'sidecars' in str(exc)
        else:
            raise AssertionError('Passive reader admitted a hot journal')
        assert snapshot(source) == crashed

        copied = root / 'copy'
        shutil.copytree(source, copied)
        assert snapshot(copied) == crashed
        recovered = copied / original.name
        with closing(sqlite3.connect(recovered.as_uri() + '?mode=rw', uri=True)) as conn:
            assert conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert not (copied/'sentinel.db-journal').exists()
        assert records(recovered) == committed
        reader = CampaignDatabase(str(recovered), read_only=True)
        assert len(reader.get_campaign_history(campaign)['checks']) == 10
        resumed = CampaignDatabase(str(recovered))
        resumed.record_check(campaign, 'after recovery')
        after = records(recovered)
        assert after['checks'][:-1] == committed['checks']
        assert after['checks'][-1][0] > committed['checks'][-1][0]
        assert after['alerts'] == committed['alerts']
        assert snapshot(source) == crashed
        print('PASS: rollback journal and dirty pages observed; 32 checks and 1 alert recovered '
              'on the copy, 1 subsequent check committed; source pair unchanged.')


if __name__ == '__main__':
    main()
