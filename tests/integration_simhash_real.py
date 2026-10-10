"""Actual offline full, SQLite and HTTP queries; fixtures test header scope only."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parents[1]


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def main():
    sys.path.insert(0, str(REPO))
    from paw.core.index import SIMHASH_METHOD, SIMHASH_SCOPE
    from paw.core.verify import verify_case
    words = b'alpha beta gamma delta epsilon zeta eta theta'
    base = b'From: a@example.com\r\nSubject: '+words+b'\r\n\r\nOriginal body'
    samples = {'base.eml':base,
               'reordered.eml':base.replace(words, b'theta eta zeta epsilon delta gamma beta alpha'),
               'body.eml':base.replace(b'Original body', b'Different body'),
               'no-headers.eml':b'\r\nOriginal body',
               'original-public.eml':next((REPO/'inbox').glob('*.eml')).read_bytes()}
    with tempfile.TemporaryDirectory(prefix='paw-simhash-real-', dir=REPO.parent) as directory:
        root = Path(directory); inputs = root/'inputs'; inputs.mkdir()
        for name, raw in samples.items(): (inputs/name).write_bytes(raw)
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1',
                   PYTHONUTF8='1', PAW_DATA_DIR=str(root))
        result = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60'],
            cwd=root, env=env, capture_output=True, timeout=150)
        assert result.returncode == 0, (result.stdout+result.stderr).decode(errors='replace')[-6000:]
        cases = {}
        for case in (root/'cases').glob('case-*'):
            name = read(case/'manifest.json')['source_name']; cases[name] = case
            assert (case/'input.eml').read_bytes() == samples[name] and verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            assert read(case/'campaign_correlations.json')['status'] == 'unavailable'
        assert set(cases) == set(samples)
        with closing(sqlite3.connect(root/'cases/index.db')) as connection:
            connection.row_factory = sqlite3.Row
            rows = {row['id']:dict(row) for row in connection.execute('SELECT * FROM cases')}
        assert len(rows) == 5 and all(row['simhash_method'] == SIMHASH_METHOD for row in rows.values())
        header_rows = [rows[cases[name].name[5:]] for name in ('base.eml','reordered.eml','body.eml')]
        assert len({row['simhash'] for row in header_rows}) == 1
        assert all(row['simhash_status']=='observed' for row in header_rows)
        empty = rows[cases['no-headers.eml'].name[5:]]
        assert empty['simhash'] is None and empty['simhash_status']=='not_evaluated_no_features'
        for row in header_rows:
            score = read(root/'cases'/('case-'+row['id'])/'report/score.json')
            assert row['score'] == score['score'] and 'simhash' not in score['score_components']
        snapshot = {str(path.relative_to(root/'cases')):hashlib.sha256(path.read_bytes()).hexdigest()
                    for case in cases.values() for path in case.rglob('*') if path.is_file()}
        cli = subprocess.run([sys.executable,'-X','utf8','-m','paw','query','--by','domain',
                              '--value','example.com'], cwd=root, env=env, capture_output=True, timeout=20)
        assert cli.returncode == 0, cli.stderr.decode(errors='replace')
        matches = json.loads(cli.stdout)
        expected_ids = {row['id'] for row in header_rows}
        assert {row['id'] for row in matches} == expected_ids
        assert all(row['simhash_method']==SIMHASH_METHOD and row['simhash_scope']==SIMHASH_SCOPE
                   and row['similarity_validation']=='not_validated' for row in matches)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        server = None
        with (root/'api.log').open('wb') as log:
            try:
                server = subprocess.Popen([sys.executable,'-m','uvicorn','paw.web.api:app',
                    '--host','127.0.0.1','--port',str(port)], cwd=root, env=env, stdout=log, stderr=log)
                end = time.monotonic()+20
                while time.monotonic() < end:
                    assert server.poll() is None, (root/'api.log').read_text(errors='replace')
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/health',timeout=2): break
                    except (urllib.error.URLError, TimeoutError): time.sleep(.1)
                else: raise TimeoutError('Loopback API startup')
                request = urllib.request.Request(f'http://127.0.0.1:{port}/api/query',
                    data=json.dumps({'query_type':'domain','value':'example.com'}).encode(),
                    headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(request, timeout=15) as response:
                    api_matches = json.load(response)['matches']
                assert {row['id'] for row in api_matches} == expected_ids
                assert all(row['execution_status']=='completed' and row['simhash_method']==SIMHASH_METHOD
                    and row['simhash_scope']==SIMHASH_SCOPE and row['similarity_validation']=='not_validated'
                    for row in api_matches)
                # Controlled legacy-index fixture, not simulated analysis: use
                # actual parsed headers/case IDs, only recreate old DB metadata.
                legacy_values = {}
                with closing(sqlite3.connect(root/'cases/index.db')) as connection:
                    for case in cases.values():
                        headers = read(case/'headers.json')
                        text = f"{headers.get('subject','')} {headers.get('from','')} {' '.join(headers.get('received',[]))}"
                        digest = hashlib.md5(text.encode()).hexdigest()[:16]
                        legacy_values[case.name[5:]] = digest
                        connection.execute('UPDATE cases SET simhash=? WHERE id=?', (digest,case.name[5:]))
                    connection.execute('ALTER TABLE cases DROP COLUMN simhash_method')
                    connection.execute('ALTER TABLE cases DROP COLUMN simhash_status')
                    connection.commit()
                    legacy_before = connection.execute('SELECT * FROM cases ORDER BY id').fetchall()
                with urllib.request.urlopen(request, timeout=15) as response:
                    historical = json.load(response)['matches']
                assert {row['id'] for row in historical} == expected_ids
                assert all(row['simhash_method']=='legacy_md5_prefix_64' and
                    row['simhash_status']=='legacy_not_similarity_fingerprint' and
                    row['simhash']==legacy_values[row['id']] for row in historical)
                with closing(sqlite3.connect(root/'cases/index.db')) as connection:
                    assert connection.execute('SELECT * FROM cases ORDER BY id').fetchall() == legacy_before
                    assert 'simhash_method' not in {row[1] for row in connection.execute('PRAGMA table_info(cases)')}
            finally:
                if server is not None:
                    server.terminate()
                    try: server.wait(timeout=10)
                    except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=5)
        after = {str(path.relative_to(root/'cases')):hashlib.sha256(path.read_bytes()).hexdigest()
                 for case in cases.values() for path in case.rglob('*') if path.is_file()}
        assert after == snapshot and all(verify_case(str(case)) for case in cases.values())
        print('PASS: 5 actual supervised full --no-egress cases (4 constructed header contracts, 1 original public EML); header-only scope, unavailable empty features, versioned SQLite and real CLI/loopback HTTP query metadata; controlled legacy-index fixture is read-only over HTTP; original MIME/seals unchanged. No similarity threshold, deduplication or campaign/actor conclusion validated.')


if __name__ == '__main__': main()
