"""Real supervised offline CLI regressions; fixtures are not accuracy labels."""
import base64
from email.message import EmailMessage
from email import policy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    with tempfile.TemporaryDirectory(prefix='paw-url-evidence-', dir=REPO.parent) as temporary:
        root = Path(temporary).resolve()
        assert root.is_relative_to(REPO.parent.resolve())
        inputs = root / 'inputs'
        inputs.mkdir()
        reserved = 'https://example.invalid/a%2Fb?x=a%26admin%3D1'
        lookalike = 'https://аррӏе.com/login'
        embedded = 'https://candidate.invalid/a%2Fb'
        token = base64.b64encode(embedded.encode()).decode()
        wrapper = 'https://tracking.invalid/click?next=' + token
        json_token = base64.b64encode(json.dumps({'href':embedded, 'email_id':'fixture'}).encode()).decode()
        json_wrapper = 'https://tracking.invalid/json/' + json_token
        malformed = 'https://example.invalid:bad/a'
        defanged = 'hxxps://refanged[.]invalid/a%2Fb'
        encoded_url = quote('https://encoded.invalid/a%2Fb', safe='')
        item = EmailMessage(policy=policy.SMTP)
        item['From'] = 'regression@example.invalid'
        item['To'] = 'recipient@example.invalid'
        item['Subject'] = 'URL evidence regression fixture'
        item['X-PAW-Fixture'] = 'constructed regression; not classifier accuracy ground truth'
        item.set_content('\n'.join([reserved, lookalike, wrapper, json_wrapper, malformed, defanged, encoded_url,
            'Ordinary invoice.pdf sender@example.invalid special-offer!']))
        plain_bytes = item.as_bytes()
        (inputs / 'plain.eml').write_bytes(plain_bytes)
        html_url = 'HTTPS://example.invalid/upper%2Fpath?x=a%26b&y=2'
        item.set_content('<a href="HTTPS://example.invalid/upper%2Fpath?x=a%26b&amp;y=2">go</a>', subtype='html')
        html_bytes = item.as_bytes()
        (inputs / 'html.eml').write_bytes(html_bytes)
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        command = [sys.executable, '-X', 'utf8', '-m', 'paw', 'full', str(inputs),
            '--no-egress', '--deadline', '60', '--stage-timeout', '30']
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=90)
        (root / 'cli.log').write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, (result.stdout + result.stderr).decode('utf-8', errors='replace')
        sys.path.insert(0, str(REPO))
        from paw.core.verify import verify_case
        cases = list((root / 'cases').glob('case-*'))
        assert len(cases) == 2
        for case in cases:
            source = read(case / 'manifest.json')['source_name']
            original = plain_bytes if source == 'plain.eml' else html_bytes
            assert hashlib.sha256((case / 'input.eml').read_bytes()).digest() == hashlib.sha256(original).digest()
            assert verify_case(str(case))
            execution = read(case / 'execution.json')
            assert execution['no_egress'] is True and execution['scope'] == 'offline_local'
            assert not execution['blocked_operations']
            headers = read(case / 'headers.json')
            evidence = read(case / 'url_evidence.json')
            assert headers['url_evidence'] == evidence
            coverage = read(case / 'analysis_coverage.json')['stages']['url_interpretation']
            if source == 'plain.eml':
                assert headers['urls'] == [reserved, lookalike, wrapper, json_wrapper,
                    'https://refanged.invalid/a%2Fb', 'https://encoded.invalid/a%2Fb']
                assert malformed not in headers['urls']
                assert embedded not in headers['urls']
                assert all('apple.com' not in url for url in headers['urls'])
                invalid = next(e for e in evidence if e['url'] == malformed)
                assert invalid['status'] == 'invalid' and invalid['network_target'] is False
                derived = next(e for e in evidence if e['url'] == 'https://refanged.invalid/a%2Fb')
                assert derived['source_url'] == defanged and derived['provenance'] == 'derived_text_url'
                url_results = read(case / 'deobfuscation_results.json')['deobfuscated_artifacts']['urls']
                nested = next(r for r in url_results if r['original_url'] == wrapper)['embedded_url_candidates']
                assert nested[0]['url'] == embedded and nested[0]['network_target'] is False
                json_nested = next(r for r in url_results if r['original_url'] == json_wrapper)['embedded_url_candidates']
                assert json_nested[0]['url'] == embedded and json_nested[0]['source_json_pointer'] == '/href'
                assert json_nested[0]['network_target'] is False
                assert coverage['status'] == 'partial'
                assert coverage['invalid_or_unresolved_count'] == 1
                assert coverage['embedded_candidate_count'] == 2
            else:
                assert headers['urls'] == [html_url]
                assert coverage['status'] == 'completed'
        print(json.dumps({'real_cli_cases':len(cases), 'integrity_verified':True,
            'original_bytes_preserved':True, 'explicit_no_egress':True,
            'url_identity_and_candidate_provenance_verified':True}))


if __name__ == '__main__':
    main()
