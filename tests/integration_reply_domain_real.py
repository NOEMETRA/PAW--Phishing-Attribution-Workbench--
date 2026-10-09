"""Real offline full CLI domain comparisons; constructed EMLs are not labels."""
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
    base = b'From: a@example.invalid\r\nSubject: Constructed domain comparison\r\n'
    replies = {'plain':b'a@example.invalid','comment':b'a@example.invalid (support)',
               'quoted-local':b'"a@b"@example.invalid','subdomain':b'a@news.example.invalid',
               'unrelated':b'a@other.invalid','lookalike':b'a@evil-example.invalid',
               'list':b'a@other.invalid, b@example.invalid','group':b'Team: a@other.invalid;',
               'defective':b'Name\xff <a@other.invalid>','malformed':b'broken'}
    samples = {name+'.eml':base+b'Reply-To: '+value+b'\r\n\r\nhello' for name,value in replies.items()}
    samples['duplicate-reply.eml'] = base+b'Reply-To: a@other.invalid\r\nReply-To: b@example.invalid\r\n\r\nhello'
    samples['missing-from.eml'] = b'Reply-To: a@other.invalid\r\nSubject: Missing sender\r\n\r\nhello'
    samples['duplicate-from.eml'] = b'From: b@example.invalid\r\n'+samples['unrelated.eml']
    samples['group-from.eml'] = samples['unrelated.eml'].replace(b'a@example.invalid',b'Team: a@example.invalid;',1)
    samples['no-reply.eml'] = base+b'\r\nhello'
    with tempfile.TemporaryDirectory(prefix='paw-reply-domain-',dir=REPO.parent) as temporary:
        root = Path(temporary)
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
        from paw.core.scoring import score_case
        observed = {}
        for case in (root/'cases').glob('case-*'):
            name = read(case/'manifest.json')['source_name']
            assert (case/'input.eml').read_bytes() == samples[name]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            headers,score,auth = (read(case/file) for file in ('headers.json','report/score.json','auth.json'))
            coverage = read(case/'analysis_coverage.json')
            comparison = score['sender_domain_observations']['reply_to_comparison']
            assert comparison == coverage['stages']['reply_to_comparison']
            assert comparison['verified'] is False
            assert score['score_components']['verified_authentication_failures'] == 0
            persisted = score_case({}, {}, {'domain':auth.get('from_domain') or ''},headers=headers)
            assert persisted['sender_domain_observations'] == score['sender_domain_observations']
            assert persisted['score_components']['sender_domain_heuristics'] == score['score_components']['sender_domain_heuristics']
            expected = .15 if name in {'unrelated.eml','lookalike.eml'} else 0
            assert score['score_components']['sender_domain_heuristics'] == expected,(name,score)
            assert comparison['contribution'] == expected
            completed = name in {'plain.eml','comment.eml','quoted-local.eml','subdomain.eml','unrelated.eml','lookalike.eml'}
            assert comparison['status'] == ('completed' if completed else 'not_evaluated')
            assert comparison['result'] == ('different' if expected else 'same_or_subdomain' if completed else None)
            if name in {'list.eml','group.eml','defective.eml','malformed.eml','duplicate-reply.eml','duplicate-from.eml','group-from.eml','missing-from.eml'}:
                assert coverage['stages']['header_parsing']['status'] == 'partial'
            observed[name] = True
        assert set(observed) == set(samples)
        print('PASS: 15 real full --no-egress domain comparison cases; uncertainty, original bytes, JSON parity, contributions and seals verified')


if __name__ == '__main__':
    main()
