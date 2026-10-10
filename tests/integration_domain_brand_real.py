"""Actual supervised offline domain-label comparisons; fixtures are not labels."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def main():
    domains={'root':'paypa1.com','service':'mail.paypa1.com','nested':'mx.mail.paypa1.com',
             'country':'mail.paypa1.co.uk','private':'mail.paypa1.github.io',
             'two-labels':'appl3.paypa1.com','plain':'paypal.com','plain-service':'mail.paypal.com',
             'hosted-exact':'news.google.github.io','brand-subdomain':'paypal.attacker.com',
             'leftmost-typo':'paypa1.attacker.com','unknown':'paypa1.invalid',
             'unknown-service':'mail.paypa1.invalid','country-plain':'mail.example.co.uk'}
    samples={name+'.eml':('From: a@'+domain+'\r\nSubject: Domain label contract\r\n\r\nhello').encode()
             for name,domain in domains.items()}
    samples['uppercase.eml']=samples['service.eml'].replace(b'mail.paypa1.com',b'MAIL.PAYPA1.COM')
    samples['duplicate.eml']=b'From: b@other.com\r\n'+samples['root.eml']
    samples['group.eml']=samples['root.eml'].replace(b'a@paypa1.com',b'Group: a@paypa1.com;')
    samples['defective.eml']=samples['root.eml'].replace(b'a@paypa1.com',b'Name\xff <a@paypa1.com>')
    samples['fragment.eml']=samples['root.eml'].replace(b'a@paypa1.com',b'a@paypa1.co m')
    samples['missing.eml']=b'Subject: Domain label contract\r\n\r\nhello'
    samples['empty.eml']=b'From:\r\n'+samples['missing.eml']
    samples['root-dot.eml']=samples['root.eml'].replace(b'a@paypa1.com',b'a@paypa1.com.')
    with tempfile.TemporaryDirectory(prefix='paw-domain-brand-',dir=REPO.parent) as temporary:
        root=Path(temporary); inputs=root/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result=subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert result.returncode==0,(result.stdout+result.stderr).decode(errors='replace')[-6000:]
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
            record=score['sender_domain_observations']['domain_brand_comparison']
            assert record==coverage['stages']['domain_brand_comparison']
            assert record['source']=='message_headers',(name,record)
            assert record['verified'] is False and record['ownership_status']=='not_evaluated'
            expected=.2 if name in {'root','service','nested','country','private','two-labels','brand-subdomain','leftmost-typo','unknown','uppercase'} else 0
            assert record['contribution']==expected,(name,record)
            assert score['score_components']['sender_domain_heuristics']==expected,(name,score)
            assert score['score_components']['verified_authentication_failures']==0
            if name in {'duplicate','group','defective','fragment','missing','empty','root-dot'}:
                assert record['status']=='not_evaluated' and record['max_similarity'] is None
                assert score['bk_score'] is None
                assert 'domain_brand_comparison' in score['coverage']['not_evaluated']
            elif name in {'unknown','unknown-service'}:
                assert record['status']=='partial' and record['registrable_domain'] is None
            else:
                assert record['status']=='observed_unverified'
            if name=='private':
                assert record['private_suffix'] is True
                assert record['registrable_domain']=='paypa1.github.io'
            persisted=score_case({}, {}, {'domain':auth.get('from_domain') or ''},headers=headers)
            assert persisted['sender_domain_observations']==score['sender_domain_observations']
            assert persisted['score_components']['sender_domain_heuristics']==expected
            if name in {'missing','empty'}:
                hinted=score_case({}, {}, {'domain':'mail.paypa1.com'},headers=headers)
                hinted_record=hinted['sender_domain_observations']['domain_brand_comparison']
                assert hinted_record['source']=='message_headers'
                assert hinted_record['status']=='not_evaluated' and hinted_record['comparisons']==[]
                assert hinted['bk_score'] is None and hinted['score_components']['sender_domain_heuristics']==0
            observed[name]=record
        expected_names={Path(name).stem for name in samples}
        assert set(observed)==expected_names,{'missing':sorted(expected_names-set(observed)),
                                             'unexpected':sorted(set(observed)-expected_names)}
        assert observed['service']==observed['uppercase']
        print('PASS: 22 actual full --no-egress domain-label cases; registrable/private labels, single contribution, retained first-label rules, unknown suffixes, identity gates and unavailable-From provenance, original bytes, JSON/coverage parity and seals')


if __name__=='__main__': main()
