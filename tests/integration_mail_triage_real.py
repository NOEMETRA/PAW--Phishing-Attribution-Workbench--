"""Actual isolated PAW CLI with static fixture HTML and saved evidence anchors."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def read(case, name):
    return json.loads((case/name).read_text())


def main():
    form = '<form method="post" action="https://example.org/"><input type="password" name="fixture"></form>'
    anchor = '<a href="https://example.org/path"><span>https://example.com/</span></a>'
    tests = {
        'cross-domain': (form, False, 'review'),
        'archived-lf': (form, False, 'review'),
        'same-site': (form.replace('example.org','auth.example.com'), False, 'no_supported_signal'),
        'duplicate-action': (form.replace('method=', 'action="/" method='), False, 'no_supported_signal'),
        'inert': ('<!--'+form+'--><template>'+form+'</template>', False, 'no_supported_signal'),
        'disabled': (form.replace('type=', 'disabled type='), False, 'no_supported_signal'),
        'nested': (form.replace('<input', '<form><input').replace('</form>', '</form></form>'), False, 'not_evaluated'),
        'ambiguous-sender': (form, True, 'not_evaluated'),
        'anchor-mismatch': (anchor, False, 'review'),
        'anchor-ambiguous-sender': (anchor, True, 'review'),
        'anchor-same-site': (anchor.replace('example.org','login.example.com'), False, 'no_supported_signal'),
        'anchor-duplicate-href': (anchor.replace('<a ', '<a href="/" '), False, 'no_supported_signal'),
        'anchor-non-url': (anchor.replace('https://example.com/','Open page'), False, 'no_supported_signal'),
        'anchor-inert': ('<template>'+anchor+'</template><!--'+anchor+'-->', False, 'no_supported_signal'),
        'anchor-unclosed': (anchor.replace('</a>',''), False, 'not_evaluated'),
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root/'messages'
        source.mkdir()
        for name, (content, ambiguous, _) in tests.items():
            sender = 'From: fixture@example.net\r\n' if ambiguous else ''
            eml = (f'From: fixture@example.com\r\n{sender}To: example@example.net\r\nSubject: {name}\r\n'
                   f'MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{content}\r\n')
            if name == 'archived-lf':
                eml = eml.replace('\r\n', '\n')
            (source/(name+'.eml')).write_bytes(eml.encode())
        cli = [sys.executable,'-I','-B','-m','paw']
        result = subprocess.run(cli+['analyze',str(source),'--no-egress','--profile','strict'],
                                cwd=root, capture_output=True, text=True, timeout=45)
        assert result.returncode == 0, result.stdout+result.stderr
        seen = set()
        for case in (root/'cases').glob('case-*'):
            title = read(case,'headers.json')['subject']
            seen.add(title)
            triage = read(case,'mail_triage.json')
            score = read(case,'report/score.json')
            execution = read(case,'execution.json')
            assert (case/'input.eml').read_bytes() == (source/(title+'.eml')).read_bytes()
            assert execution['no_egress'] and not execution['blocked_operations']
            assert triage['referral_status'] == tests[title][2], (title,triage)
            assert score['decision'] == 'Inconclusive'
            if title in ('cross-domain','archived-lf'):
                finding, = triage['findings']
                assert finding['from_domain'] == 'example.com' and finding['action_hostname'] == 'example.org'
                evidence = finding['source']
                text = (case/evidence['text_path']).read_bytes()
                assert sha256(text).hexdigest() == evidence['text_sha256']
                assert evidence['part_id'] == '0'
                if title == 'archived-lf':
                    assert finding['source_part_status'] == triage['coverage']['status'] == 'partial'
                for key,value in [('form','<form'),('named_password_input','<input')]:
                    coords = finding[key]
                    assert text.decode().splitlines()[coords['line']-1][coords['column']:].startswith(value)
            elif title in ('anchor-mismatch','anchor-ambiguous-sender'):
                finding, = triage['findings']
                assert finding['rule'] == 'displayed_link_hostname_mismatch'
                assert (finding['displayed_hostname'], finding['destination_hostname']) == ('example.com','example.org')
                evidence = finding['source']
                text = (case/evidence['text_path']).read_bytes()
                assert sha256(text).hexdigest() == evidence['text_sha256']
                line,col = (finding['anchor'][field] for field in ('line','column'))
                assert text.decode().splitlines()[line-1][col:].startswith('<a ')
            else:
                assert not triage['findings']
            assert triage['referral_status'] in (case/'report/executive.md').read_text()
            subprocess.run(cli+['verify','--case',str(case)], cwd=root, check=True, capture_output=True, timeout=10)
        assert seen == tests.keys()
    print('PASS: evidence-linked static review for four supported referrals, eleven comparison cases, fifteen valid seals.')


if __name__ == '__main__':
    main()
