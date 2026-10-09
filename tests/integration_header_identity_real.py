"""Supervised no-egress CLI mailbox parsing; fixtures are not phishing labels."""
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
    names = {'unquoted.eml':b'PayPal A <a@example.invalid>',
             'quoted.eml':b'"PayPal A" <a@example.invalid>',
             'encoded.eml':b'=?utf-8?b?UGF5UGFsIEE=?= <a@example.invalid>',
             'bare.eml':b'paypal@merchant.invalid',
             'bad-bytes.eml':b'PayPal \xff <a@example.invalid>'}
    samples = {name:b'From: '+value+b'\r\nTo: b@example.invalid\r\nSubject: Constructed mailbox contract\r\n\r\nhello\r\n'
               for name,value in names.items()}
    samples['bad-date.eml'] = samples['unquoted.eml'].replace(b'To:',b'Date: not a date\r\nTo:')
    with tempfile.TemporaryDirectory(prefix='paw-identity-',dir=REPO.parent) as temporary:
        root = Path(temporary).resolve()
        inputs = root/'inputs'
        inputs.mkdir()
        for name,raw in samples.items():
            (inputs/name).write_bytes(raw)
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert result.returncode == 0,(result.stdout+result.stderr).decode(errors='replace')[-6000:]
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        cases = list((root/'cases').glob('case-*'))
        assert len(cases) == len(samples)
        observed = {}
        for case in cases:
            name = read(case/'manifest.json')['source_name']
            assert (case/'input.eml').read_bytes() == samples[name]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            headers,score = read(case/'headers.json'),read(case/'report/score.json')
            coverage = read(case/'analysis_coverage.json')['stages']['header_parsing']
            assert coverage['field_defects'] == headers['header_field_defects']
            assert score['score_components']['verified_authentication_failures'] == 0
            assert score['calibrated'] is False
            observed[name] = {'score':score,'headers':headers,'coverage':coverage}
        for name in ('unquoted.eml','quoted.eml','encoded.eml'):
            assert observed[name]['score']['score_components']['sender_domain_heuristics'] == .2
            assert observed[name]['coverage']['status'] == 'completed'
        assert observed['bare.eml']['score']['score_components']['sender_domain_heuristics'] == 0
        assert observed['bad-bytes.eml']['score']['score_components']['sender_domain_heuristics'] == 0
        assert observed['bad-bytes.eml']['coverage']['status'] == 'partial'
        issue, = observed['bad-bytes.eml']['headers']['header_field_defects']
        assert issue['field'] == 'From' and issue['type'] == 'UndecodableBytesDefect'
        assert observed['bad-date.eml']['coverage']['status'] == 'partial'
        # Coverage is deliberately different; a parser defect adds no score.
        for key in ('score_components','raw_score','decision_score','score','decision','thresholds'):
            assert observed['bad-date.eml']['score'][key] == observed['unquoted.eml']['score'][key]
        print('PASS: 6 real full --no-egress mailbox cases; equivalent names, absent display names, explicit field defects, original bytes, scores and seals verified')


if __name__ == '__main__':
    main()
