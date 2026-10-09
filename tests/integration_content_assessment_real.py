"""Real full CLI content contracts; constructed EMLs are not accuracy labels."""
from email.message import EmailMessage
from email import policy
import hashlib
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
    with tempfile.TemporaryDirectory(prefix='paw-content-', dir=REPO.parent) as temporary:
        root = Path(temporary).resolve()
        assert root.is_relative_to(REPO.parent.resolve())
        inputs = root / 'inputs'
        inputs.mkdir()
        bodies = {'short.eml': 'a' * 100,
                  'long.eml': 'a' * 10000,
                  'style.eml': 'A' * 600 + '!!!???',
                  'indicators.eml': 'URGENT: verify your account. ID: 123456. Konto login.',
                  'incidental.eml': 'refundability importantissimo village login',
                  'split-urgency.eml': 'required',
                  'split-threat.eml': 'your account',
                  'split-pattern.eml': 'team'}
        subjects = {'split-urgency.eml': 'action', 'split-threat.eml': 'verify',
                    'split-pattern.eml': 'security'}
        originals = {}
        for name, body in bodies.items():
            message = EmailMessage(policy=policy.SMTP)
            message['From'] = 'regression@example.invalid'
            message['To'] = 'recipient@example.invalid'
            message['Subject'] = subjects.get(name, 'Content contract fixture')
            message['X-PAW-Fixture'] = 'constructed regression; not classifier accuracy ground truth'
            message.set_content(body)
            originals[name] = message.as_bytes()
            (inputs / name).write_bytes(originals[name])
        environment = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'full', str(inputs),
            '--no-egress', '--lang', 'en', '--deadline', '120', '--stage-timeout', '60',
            '--memory-mib', '1024'], cwd=root, env=environment, capture_output=True, timeout=150)
        assert result.returncode == 0, result.stdout.decode('utf-8', errors='replace')[-8000:] + result.stderr.decode('utf-8', errors='replace')[-2000:]
        sys.path.insert(0, str(REPO))
        from paw.core.verify import verify_case
        cases = list((root / 'cases').glob('case-*'))
        assert len(cases) == len(originals)
        observed = {}
        for case in cases:
            name = read(case / 'manifest.json')['source_name']
            assert hashlib.sha256((case / 'input.eml').read_bytes()).digest() == hashlib.sha256(originals[name]).digest()
            assert verify_case(str(case))
            execution = read(case / 'execution.json')
            assert execution['no_egress'] is True
            headers = read(case / 'headers.json')
            auxiliary = headers['ml_score']
            assert auxiliary['schema_version'] == 2
            assert auxiliary['assessment_status'] == 'heuristic_only'
            assert auxiliary['calibrated'] is False
            assert auxiliary['risk_level'] == 'not_evaluated'
            assert auxiliary['recommendations']['block_email'] is False
            assert auxiliary['recommendations']['inject_canary'] is False
            assert abs(sum(auxiliary['contributions'].values()) - auxiliary['phishing_score']) < 1e-9
            assert 'content_length' not in auxiliary['contributions']
            observed[name] = auxiliary
        assert set(observed) == set(bodies)
        for name in ('short.eml', 'long.eml', 'style.eml', 'incidental.eml',
                     'split-urgency.eml', 'split-threat.eml', 'split-pattern.eml'):
            assert observed[name]['phishing_score'] == 0, (name, observed[name])
            assert observed[name]['recommendations']['flag_for_review'] is False
        assert observed['long.eml']['features']['content_length'] > observed['short.eml']['features']['content_length']
        assert observed['style.eml']['features']['capitalization_ratio'] > 0
        indicator = observed['indicators.eml']
        assert indicator['recommendations']['flag_for_review'] is True
        assert 'verify your account' in indicator['evidence']['threat_score']
        assert indicator['features']['mixed_languages'] == 1
        print('PASS: 8 real full --no-egress cases; originals, seals, field boundaries, content evidence and action contracts verified')


if __name__ == '__main__':
    main()
