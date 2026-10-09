"""Real offline CLI age coverage; no registry/date response is simulated."""
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def main():
    plain=b'From: a@example.com\r\nSubject: Age coverage contract\r\n\r\nhello'
    samples={'plain.eml':plain,'missing.eml':b'Subject: Missing\r\n\r\nhello',
             'empty.eml':b'From:\r\n\r\nhello',
             'duplicate.eml':b'From: b@other.com\r\n'+plain,
             'group.eml':plain.replace(b'a@example.com',b'Group: a@example.com;'),
             'fragment.eml':plain.replace(b'a@example.com',b'a@exa mple.com'),
             'defective.eml':plain.replace(b'a@example.com',b'Name\xff <a@example.com>')}
    with tempfile.TemporaryDirectory(prefix='paw-age-',dir=REPO.parent) as temporary:
        root=Path(temporary); inputs=root/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        run=subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-6000:]
        sys.path.insert(0,str(REPO))
        from paw.core.profiler import observe_domain_age, nrd_days
        from paw.core.verify import verify_case
        names=set()
        for case in (root/'cases').glob('case-*'):
            name=read(case/'manifest.json')['source_name']; names.add(name)
            assert (case/'input.eml').read_bytes()==samples[name] and verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            domain=read(case/'domains.json')['from_domain']
            score,coverage=read(case/'report/score.json'),read(case/'analysis_coverage.json')
            age=domain['domain_age']
            assert age==coverage['stages']['domain_age']==score['coverage']['stages']['domain_age']
            assert age['status']=='unavailable' and age['reason_code']=='timestamp_unavailable'
            assert age['source']=='domains.json.from_domain.created' and age['verified'] is False
            assert age['age_days'] is None and domain['nrd_days'] is None
            assert 'domain_age' in coverage['not_evaluated']
            assert score['score_components']['sender_domain_heuristics']==0
            replay=observe_domain_age(domain.get('created'),reference_time=age['reference_time'])
            replay['source']='domains.json.from_domain.created'
            assert replay==age
            assert nrd_days(domain.get('created'),reference_time=age['reference_time']) is None
        assert names==set(samples)
        with closing(sqlite3.connect(root/'cases/index.db')) as conn:
            rows=conn.execute('SELECT nrd_days FROM cases').fetchall()
        assert len(rows)==len(samples) and all(row[0] is None for row in rows)
        print('PASS: 7 actual full --no-egress CLI cases; unavailable registration age stays null in domains/coverage/score/index, stored reference reproduces observations, original bytes and seals valid. Future timestamps are covered by local calculation contracts, not live RDAP.')


if __name__=='__main__': main()
