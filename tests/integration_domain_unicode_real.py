"""Real supervised offline IDNA observations; constructed EMLs are not labels."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    domains = {'ascii':'example.invalid', 'latin':'café.invalid',
               'latin-ace':'xn--caf-dma.invalid', 'cyrillic':'пример.рф',
               'cyrillic-ace':'xn--e1afmkfd.xn--p1ai',
               'mixed':'exаmple.invalid', 'mixed-ace':'xn--exmple-4nf.invalid',
               'bad-ace':'xn--a.invalid', 'upper-case':'XN--CAF-DMA.INVALID',
               'root-dot':'XN--CAF-DMA.INVALID.'}
    samples = {name+'.eml':('From: a@'+domain+'\r\nSubject: IDNA contract\r\n\r\nhello').encode('utf-8')
               for name,domain in domains.items()}
    samples['duplicate.eml'] = b'From: a@xn--caf-dma.invalid\r\n'+samples['latin-ace.eml']
    samples['group.eml'] = samples['latin-ace.eml'].replace(b'a@xn--caf-dma.invalid', b'Group: a@xn--caf-dma.invalid;')
    samples['defective.eml'] = samples['latin-ace.eml'].replace(b'a@xn--caf-dma.invalid', b'Name\xff <a@xn--caf-dma.invalid>')
    samples['missing.eml'] = b'Subject: no sender\r\n\r\nhello'
    with tempfile.TemporaryDirectory(prefix='paw-unicode-', dir=REPO.parent) as temporary:
        root = Path(temporary)
        inputs = root/'inputs'
        inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'full', str(inputs),
            '--no-egress', '--lang', 'en', '--deadline', '120', '--stage-timeout', '60', '--memory-mib', '1024'],
            cwd=root, env=env, capture_output=True, timeout=150)
        assert result.returncode==0,(result.stdout+result.stderr).decode(errors='replace')[-6000:]
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        from paw.core.scoring import score_case
        observed = {}
        for case in (root/'cases').glob('case-*'):
            filename = read(case/'manifest.json')['source_name']
            name = Path(filename).stem
            assert (case/'input.eml').read_bytes()==samples[filename]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            headers,auth,score,coverage = [read(case/file) for file in (
                'headers.json','auth.json','report/score.json','analysis_coverage.json')]
            record = score['sender_domain_observations']['unicode_domain']
            assert coverage['stages']['unicode_domain']==record
            assert record['mixed_script'] is None and score['mixed_flag'] is None
            assert record['script_analysis_status']=='not_evaluated'
            assert record['homograph_analysis_status']=='not_evaluated'
            assert record['verified'] is False and record['contribution']==0
            assert score['score_components']['sender_domain_heuristics']==0,(name,score)
            assert score['score_components']['verified_authentication_failures']==0
            assert {'domain_script_analysis','domain_homograph_analysis'} <= set(score['coverage']['not_evaluated'])
            unavailable = {'duplicate','group','defective','missing','root-dot','latin','cyrillic','mixed'}
            expected = 'partial' if name=='bad-ace' else 'unavailable' if name in unavailable else 'observed_unverified'
            assert record['status']==expected,(name,headers,record)
            if expected=='observed_unverified':
                assert record['decoded_non_ascii'] is (name!='ascii')
            else:
                assert record['decoded_non_ascii'] is None
            if name in {'latin','cyrillic','mixed','root-dot'}:
                assert headers['from_identity']['status']=='partial'
                assert headers['header_field_defects']
            persisted = score_case({}, {}, {'domain':auth.get('from_domain') or ''}, headers=headers)
            assert persisted['sender_domain_observations']==score['sender_domain_observations']
            assert persisted['score_components']['sender_domain_heuristics']==0
            observed[name] = record
        assert set(observed)=={Path(name).stem for name in samples}
        assert observed['latin-ace']==observed['upper-case']
        for first,second in (('latin','latin-ace'),('cyrillic','cyrillic-ace'),('mixed','mixed-ace')):
            assert observed[second]['unicode_domain']==domains[first]
        print('PASS: 14 real full --no-egress Unicode/ACE cases; nullable script interpretation, representation parity, defective From gating, JSON/coverage parity, original bytes and seals')


if __name__ == '__main__':
    main()
