"""Actual supervised offline TLD contracts; constructed EMLs are not labels."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def main():
    domains={suffix:'example.'+suffix for suffix in ('click','icu','cfd','rest','tk','gq','ml','ga','cf')}
    domains.update(plain='example.com',unknown='example.invalid',label='click.example.com',
                   service='mail.example.click',uppercase='EXAMPLE.CLICK',
                   ace='xn--bcher-kva.click',single='click',literal='[192.0.2.1]')
    samples={name+'.eml':('From: a@'+domain+'\r\nSubject: TLD contract\r\n\r\nhello').encode()
             for name,domain in domains.items()}
    samples['duplicate.eml']=b'From: b@other.com\r\n'+samples['click.eml']
    samples['group.eml']=samples['click.eml'].replace(b'a@example.click',b'Group: a@example.click;')
    samples['defective.eml']=samples['click.eml'].replace(b'a@example.click',b'Name\xff <a@example.click>')
    samples['fragment.eml']=samples['click.eml'].replace(b'a@example.click',b'a@exa mple.click')
    samples['root-dot.eml']=samples['click.eml'].replace(b'a@example.click',b'a@example.click.')
    samples['missing.eml']=b'Subject: TLD contract\r\n\r\nhello'
    samples['empty.eml']=b'From:\r\n'+samples['missing.eml']
    unavailable={'single','literal','duplicate','group','defective','fragment','root-dot','missing','empty'}
    positive={'click','icu','cfd','rest','tk','gq','ml','ga','cf','service','uppercase','ace'}
    with tempfile.TemporaryDirectory(prefix='paw-tld-',dir=REPO.parent) as temporary:
        root=Path(temporary); inputs=root/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        run=subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-6000:]
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        from paw.core.scoring import score_case
        observed={}
        for case in (root/'cases').glob('case-*'):
            filename=read(case/'manifest.json')['source_name']; name=Path(filename).stem
            assert (case/'input.eml').read_bytes()==samples[filename]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            headers,auth,score,coverage=[read(case/file) for file in ('headers.json','auth.json','report/score.json','analysis_coverage.json')]
            record=score['sender_domain_observations']['tld_comparison']
            assert record==coverage['stages']['tld_comparison']
            assert record['source']=='message_headers' and record['verified'] is False
            assert record['reputation_status']=='not_evaluated'
            expected=.1 if name in positive else 0
            assert record['contribution']==expected,(name,record)
            assert score['score_components']['sender_domain_heuristics']==expected,(name,score)
            assert score['score_components']['verified_authentication_failures']==0
            if name in unavailable:
                assert record['status']=='not_evaluated' and record['listed'] is None and record['tld'] is None,(name,record)
                assert 'tld_comparison' in score['coverage']['not_evaluated']
            else:
                assert record['status']=='observed_unverified'
                assert record['listed'] is (name in positive)
                assert 'tld_comparison' not in score['coverage']['not_evaluated']
            persisted=score_case({}, {}, {'domain':auth.get('from_domain') or ''},headers=headers)
            assert persisted['sender_domain_observations']==score['sender_domain_observations']
            if name in {'missing','empty','duplicate','group','defective','fragment','root-dot'}:
                hinted=score_case({}, {}, {'domain':'example.click'},headers=headers)
                assert hinted['sender_domain_observations']['tld_comparison']['status']=='not_evaluated'
                assert hinted['score_components']['sender_domain_heuristics']==0
            observed[name]=record
        assert set(observed)=={Path(name).stem for name in samples}
        assert observed['click']==observed['uppercase']
        print('PASS: 24 actual full --no-egress TLD cases; retained static list/weight, normalized spelling, identity gates, unknown suffixes, no reputation verdict, original bytes, JSON/coverage parity and seals')


if __name__=='__main__': main()
