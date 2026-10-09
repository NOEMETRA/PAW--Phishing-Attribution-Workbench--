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
        bad_escapes = ['https://example.invalid/%ZZ',
            'https://example.invalid/?x=%0G', 'https://example.invalid/#%']
        valid_octet = 'https://example.invalid/%FF'
        defanged = 'hxxps://refanged[.]invalid/a%2Fb'
        encoded_url = quote('https://encoded.invalid/a%2Fb', safe='')
        colliding_sources = ['hxxps://example[.]invalid/a%2Fb?x=a%26admin%3D1',
            quote(reserved, safe=''), base64.b64encode(reserved.encode()).decode()]
        item = EmailMessage(policy=policy.SMTP)
        item['From'] = 'regression@example.invalid'
        item['To'] = 'recipient@example.invalid'
        item['Subject'] = 'URL evidence regression fixture'
        item['X-PAW-Fixture'] = 'constructed regression; not classifier accuracy ground truth'
        item.set_content('\n'.join([reserved, lookalike, wrapper, json_wrapper, malformed,
            valid_octet, defanged, encoded_url] + bad_escapes + colliding_sources +
            ['Ordinary invoice.pdf sender@example.invalid special-offer!']))
        plain_bytes = item.as_bytes()
        (inputs / 'plain.eml').write_bytes(plain_bytes)
        html_url = 'HTTPS://example.invalid/upper%2Fpath?x=a%26b&y=2'
        split_url = 'https://split.invalid/a%2Fb?x=a%26b'
        item.set_content('<a href="HTTPS://example.invalid/upper%2Fpath?x=a%26b&amp;y=2">go</a>'
            ' https://split.invalid/<span>a%2Fb</span>?x=a%26b', subtype='html')
        html_bytes = item.as_bytes()
        (inputs / 'html.eml').write_bytes(html_bytes)
        failed_target = 'https://example.invalid/%ZZ'
        deep = 'https://example.invalid/a'
        for _ in range(10):
            deep = quote(deep, safe='')
        oversize = 'hxxps://example[.]invalid/' + 'a' * 65536
        unresolved = base64.b64encode(b'https is mentioned but this is not a URL').decode()
        failed_sources = ['hxxps://example[.]invalid/%ZZ', quote(failed_target, safe=''),
            base64.b64encode(failed_target.encode()).decode(),
            ''.join('\\x%02x' % ord(c) for c in failed_target), deep, oversize, unresolved]
        item.set_content('\n'.join(failed_sources))
        failed_bytes = item.as_bytes()
        (inputs / 'failed.eml').write_bytes(failed_bytes)
        originals = {'plain.eml':plain_bytes, 'html.eml':html_bytes, 'failed.eml':failed_bytes}
        hidden_bad = 'hxxps://example[.]invalid/%ZZ'
        hidden_target = 'https://hidden.invalid/a%2Fb?x=a%26b&y=2'
        hidden_defanged = 'hxxps://hidden[.]invalid/a%2Fb?x=a%26b&y=2'
        hidden_encoded = quote(hidden_target, safe='')
        hidden_base64 = base64.b64encode(hidden_target.encode()).decode()
        bad_encoded = quote(failed_target, safe='')
        js_observed = 'https://script.invalid/a%2Fb?x=a%26b'
        uppercase_target = 'HTTPS://uppercase.invalid/a%2Fb'
        mixed_target = 'hTtPs://mixed.invalid/a'
        defanged_upper = 'HXXPS://refanged[.]invalid/a?x=%FF'
        bad_upper = 'HTTPS://bad.invalid/%ZZ'
        uppercase_base64, mixed_base64, defanged_base64, bad_base64 = [
            base64.b64encode(value.encode()).decode() for value in
            [uppercase_target, mixed_target, defanged_upper, bad_upper]]
        invalid_sources = {hidden_bad:failed_target, bad_encoded:failed_target, bad_base64:bad_upper}
        # subtype, body, expected targets, candidate sources, MIME observed count
        hidden_fixtures = {
            'html-bad-only.eml':('html', '<a href="' + hidden_bad + '">go</a>',
                [], [hidden_bad], 0),
            'html-hidden.eml':('html', '<div xmlns="https://namespace.invalid/schema"'
                ' xmlns:custom="hxxps://namespace[.]invalid/other"><a href="' + hidden_bad + '">go</a>'
                '<form action="' + hidden_defanged.replace('&', '&amp;') + '"></form>'
                '<div data-next="' + hidden_encoded + '" data-other="' + hidden_base64 + '"></div></div>',
                [hidden_target], [hidden_bad, hidden_defanged, hidden_encoded, hidden_base64], 0),
            'inline-script.eml':('html', '<script>const bad="' + bad_encoded + '";const good="' + hidden_base64 + '";</script>',
                [hidden_target], [bad_encoded, hidden_base64], 0),
            'javascript.eml':('javascript', 'const bad="' + bad_encoded + '";const good="' + hidden_defanged + '";const raw="' + js_observed + '";',
                [js_observed, hidden_target], [bad_encoded, hidden_defanged, js_observed], 1),
            'base64-schemes.eml':('html', ''.join('<a data-url="' + value + '">go</a>'
                for value in [uppercase_base64, mixed_base64, defanged_base64, bad_base64]),
                [uppercase_target, mixed_target, 'https://refanged.invalid/a?x=%FF'],
                [uppercase_base64, mixed_base64, defanged_base64, bad_base64], 0),
        }
        for name, (subtype, body, _, _, _) in hidden_fixtures.items():
            item.set_content(body, subtype=subtype)
            originals[name] = item.as_bytes()
            (inputs / name).write_bytes(originals[name])
        multipart_sources = {}
        for kind, incomplete in [('script', '<script>unfinished'), ('style', '<style>unfinished'),
                                 ('comment', '<!-- unfinished')]:
            multi = EmailMessage(policy=policy.SMTP)
            for name in ['From', 'To', 'Subject', 'X-PAW-Fixture']:
                multi[name] = item[name]
            multi.make_mixed()
            for body in [incomplete, '<div xmlns="https://namespace.invalid/schema">'
                         '<a href="hxxps://later[.]invalid/a?x=1&amp;y=2">go</a></div>']:
                part = EmailMessage(policy=policy.SMTP)
                part.set_content(body, subtype='html')
                multi.attach(part)
            name = 'multipart-' + kind + '.eml'
            multipart_sources[name] = 'hxxps://later[.]invalid/a?x=1&y=2'
            originals[name] = multi.as_bytes()
            (inputs / name).write_bytes(originals[name])
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        command = [sys.executable, '-X', 'utf8', '-m', 'paw', 'full', str(inputs),
            '--no-egress', '--deadline', '60', '--stage-timeout', '30']
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=90)
        (root / 'cli.log').write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, (result.stdout + result.stderr).decode('utf-8', errors='replace')
        sys.path.insert(0, str(REPO))
        from paw.core.verify import verify_case
        cases = list((root / 'cases').glob('case-*'))
        assert len(cases) == len(originals)
        for case in cases:
            source = read(case / 'manifest.json')['source_name']
            original = originals[source]
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
                    valid_octet,
                    'https://refanged.invalid/a%2Fb', 'https://encoded.invalid/a%2Fb']
                assert malformed not in headers['urls']
                assert embedded not in headers['urls']
                assert all('apple.com' not in url for url in headers['urls'])
                invalid = next(e for e in evidence if e['url'] == malformed)
                assert invalid['status'] == 'invalid' and invalid['network_target'] is False
                for value in bad_escapes:
                    assert value not in headers['urls']
                    invalid = next(e for e in evidence if e['url'] == value)
                    assert invalid['status'] == 'invalid' and invalid['network_target'] is False
                collisions = [e for e in evidence if e['url'] == reserved]
                assert collisions[0]['provenance'] == 'observed'
                assert [e['source_url'] for e in collisions[1:]] == colliding_sources
                assert all(e['transformations'] and e['provenance'] == 'derived_text_url'
                           for e in collisions[1:])
                derived = next(e for e in evidence if e['url'] == 'https://refanged.invalid/a%2Fb')
                assert derived['source_url'] == defanged and derived['provenance'] == 'derived_text_url'
                url_results = read(case / 'deobfuscation_results.json')['deobfuscated_artifacts']['urls']
                nested = next(r for r in url_results if r['original_url'] == wrapper)['embedded_url_candidates']
                assert nested[0]['url'] == embedded and nested[0]['network_target'] is False
                json_nested = next(r for r in url_results if r['original_url'] == json_wrapper)['embedded_url_candidates']
                assert json_nested[0]['url'] == embedded and json_nested[0]['source_json_pointer'] == '/href'
                assert json_nested[0]['network_target'] is False
                assert coverage['status'] == 'partial'
                assert coverage['invalid_or_unresolved_count'] == 4
                assert coverage['embedded_candidate_count'] == 2
            elif source == 'html.eml':
                assert headers['urls'] == [html_url, split_url]
                assert coverage['status'] == 'completed'
            elif source in hidden_fixtures:
                _, _, expected_targets, candidate_sources, observed_count = hidden_fixtures[source]
                assert headers['urls'] == expected_targets
                assert coverage['status'] == 'partial'
                assert coverage['observed_count'] == observed_count
                assert coverage['network_target_count'] == len(expected_targets)
                assert coverage['invalid_or_unresolved_count'] == 1
                url_results = read(case / 'deobfuscation_results.json')['deobfuscated_artifacts']['urls']
                assert {r['original_url'] for r in url_results} == set(candidate_sources)
                assert len(evidence) == len(candidate_sources)
                for value in candidate_sources:
                    record = next(e for e in evidence if e.get('source_url', e['url']) == value)
                    if value in invalid_sources:
                        assert record['status'] == 'invalid' and record['network_target'] is False
                        assert record['reason'] == 'Malformed percent escape in URL'
                        assert record['decoding_attempts'][-1]['to'] == invalid_sources[value]
                    else:
                        assert record['status'] == 'completed' and record['network_target'] is True
                        assert record['url'] in expected_targets
            elif source in multipart_sources:
                assert headers['urls'] == ['https://later.invalid/a?x=1&y=2']
                assert coverage['status'] == 'completed'
                assert coverage['observed_count'] == coverage['invalid_or_unresolved_count'] == 0
                assert coverage['network_target_count'] == 1
                assert len(evidence) == 1
                assert evidence[0]['source_url'] == multipart_sources[source]
                assert evidence[0]['network_target'] is True
            else:
                assert headers['urls'] == []
                assert coverage['status'] == 'partial'
                assert coverage['observed_count'] == coverage['network_target_count'] == 0
                assert coverage['invalid_or_unresolved_count'] == len(failed_sources)
                assert coverage['limited_analysis_count'] == 2
                assert len(evidence) == len(failed_sources)
                assert {e['source_url'] for e in evidence} == set(failed_sources)
                url_results = read(case / 'deobfuscation_results.json')['deobfuscated_artifacts']['urls']
                for value in failed_sources:
                    record = next(e for e in evidence if e['source_url'] == value)
                    result = next(r for r in url_results if r['original_url'] == value)
                    assert record['url'] == value and record['provenance'] == 'text_url_candidate'
                    assert record['network_target'] is False and record['reason'] == result['reason']
                    assert record['decoding_attempts'] == result.get('decoding_attempts', [])
                    expected = 'partial' if value in [deep, oversize] else 'not_url' if value == unresolved else 'invalid'
                    assert record['status'] == expected
                    if expected == 'invalid':
                        assert record['decoding_attempts'][-1]['to'] == failed_target
        print(json.dumps({'real_cli_cases':len(cases), 'integrity_verified':True,
            'original_bytes_preserved':True, 'explicit_no_egress':True,
            'url_identity_and_candidate_provenance_verified':True}))


if __name__ == '__main__':
    main()
