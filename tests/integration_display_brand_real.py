"""Actual supervised display-brand comparisons; fixtures are not accuracy labels."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def main():
    domains={'root':'google.com','service':'accounts.google.com','nested':'mail.accounts.google.com',
             'country-suffix':'accounts.google.co.uk','unrelated':'news.attacker.com',
             'brand-subdomain':'google.attacker.com','hosted':'news.google.github.io',
             'hosted-blog':'news.google.blogspot.com','unknown':'example.invalid'}
    samples={name+'.eml':('From: Google <a@'+domain+'>\r\nSubject: Brand structure contract\r\n\r\nhello').encode()
             for name,domain in domains.items()}
    samples['quoted.eml']=samples['service.eml'].replace(b'Google <',b'"Google" <')
    samples['encoded.eml']=samples['service.eml'].replace(b'Google <',b'=?utf-8?b?R29vZ2xl?= <')
    samples['duplicate.eml']=b'From: Other <a@other.com>\r\n'+samples['unrelated.eml']
    samples['defective.eml']=samples['unrelated.eml'].replace(b'Google <',b'Google\xff <')
    samples['bare.eml']=samples['unrelated.eml'].replace(b'Google <a@news.attacker.com>',b'google@news.attacker.com')
    with tempfile.TemporaryDirectory(prefix='paw-display-brand-',dir=REPO.parent) as temporary:
        root=Path(temporary); inputs=root/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        execution=subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert execution.returncode==0,(execution.stdout+execution.stderr).decode(errors='replace')[-6000:]
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
            record=score['sender_domain_observations']['display_brand_comparison']
            assert record==coverage['stages']['display_brand_comparison']
            assert record['verified'] is False and record['ownership_status']=='not_evaluated'
            expected=.2 if name in {'unrelated','brand-subdomain','hosted','hosted-blog','unknown'} else 0
            assert score['score_components']['sender_domain_heuristics']==expected,(name,score)
            assert record['contribution']==(.2 if name in {'unrelated','hosted','hosted-blog','unknown'} else 0)
            assert score['score_components']['verified_authentication_failures']==0
            if name in {'root','service','nested','country-suffix','quoted','encoded'}:
                assert record['result']=='registrable_label_match'
            if name in {'hosted','hosted-blog'}: assert record['private_suffix'] is True
            if name in {'defective','duplicate'}:
                assert record['status']=='not_evaluated' and record['result'] is None
            persisted=score_case({}, {}, {'domain':auth.get('from_domain') or ''},headers=headers)
            assert persisted['sender_domain_observations']==score['sender_domain_observations']
            assert persisted['score_components']['sender_domain_heuristics']==expected
            observed[name]=record
        assert set(observed)=={Path(name).stem for name in samples}
        assert observed['service']==observed['quoted']==observed['encoded']
        print('PASS: 14 actual full --no-egress display-brand cases; public/private suffix scope, retained risk, identity defects, original bytes, JSON/coverage parity and seals')


if __name__=='__main__': main()
