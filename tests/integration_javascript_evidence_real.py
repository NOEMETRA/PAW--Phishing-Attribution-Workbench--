"""Supervised full offline CLI JavaScript contracts; fixtures are not accuracy labels."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
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
    hidden_url = 'https://candidate.invalid/a'
    char_codes = ','.join(str(ord(char)) for char in hidden_url)
    samples = {'eval.eml':'eval("hello");',
               'binary.eml':'atob("//4A");',
               'expressions.eml':'String.fromCharCode(65+1,variable2);',
               'recursive.eml':'atob("YXRvYignWVE9PScp");',
               'uri.eml':'decodeURIComponent("%FF"); decodeURIComponent("a+b%2Fc");',
               'limited.eml':'atob("YQ==");'*33+' '*10000,
               'nested.eml':'eval(("hello")); String.fromCharCode(foo(65),66);',
               'decoded-url.eml':'String.fromCharCode('+char_codes+');'}
    with tempfile.TemporaryDirectory(prefix='paw-js-',dir=REPO.parent) as temporary:
        root = Path(temporary).resolve()
        inputs = root/'inputs'
        inputs.mkdir()
        originals = {}
        for name, source in samples.items():
            message = EmailMessage(policy=policy.SMTP)
            message['From'] = 'regression@example.invalid'
            message['To'] = 'recipient@example.invalid'
            message['Subject'] = 'JavaScript evidence contract; constructed, not accuracy ground truth'
            message.set_content(source,subtype='javascript')
            originals[name] = message.as_bytes()
            (inputs/name).write_bytes(originals[name])
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        process = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert process.returncode == 0, (process.stdout+process.stderr).decode(errors='replace')[-6000:]
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        from paw.core.mime_analysis import analyze_mime
        cases = list((root/'cases').glob('case-*'))
        assert len(cases) == len(originals)
        observed = {}
        for case in cases:
            name = read(case/'manifest.json')['source_name']
            assert (case/'input.eml').read_bytes() == originals[name]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            result = read(case/'deobfuscation_results.json')
            js = result['deobfuscated_artifacts']['javascript']
            mime = analyze_mime(BytesParser(policy=policy.default).parsebytes(originals[name]))
            assert js['original_code'] == js['final_code'] == mime['javascript']
            assert js['javascript_schema_version'] == 2
            assert js['risk_detection'] == 'not_evaluated'
            assert js['execution']['status'] == 'not_evaluated'
            assert js['transformations'] == []
            assert result['suspicion_score'] is None
            assert result['coverage']['javascript']['risk_detection'] == 'not_evaluated'
            assert read(case/'report/score.json')['score_components']['deobfuscation_heuristics'] == 0
            assert read(case/'url_evidence.json') == []
            observed[name] = js
        assert observed['eval.eml']['literal_candidates']['candidates'][0]['status'] == 'not_executed'
        assert observed['binary.eml']['literal_candidates']['candidates'][0]['decoded_text'].encode('latin-1') == b'\xff\xfe\x00'
        assert observed['expressions.eml']['literal_candidates']['candidates'][0]['status'] == 'unsupported_literal'
        assert len(observed['recursive.eml']['literal_candidates']['candidates']) == 1
        assert observed['uri.eml']['literal_candidates']['candidates'][0]['status'] == 'invalid_encoding'
        assert observed['limited.eml']['assessment_status'] == 'partial'
        assert len(observed['limited.eml']['literal_candidates']['candidates']) == 32
        limited = observed['limited.eml']['literal_candidates']
        assert limited['scanned_characters'] == len('atob("YQ==");'*32)
        assert limited['available_window_characters'] > limited['scanned_characters']
        assert limited['unprocessed_source_span'] == [limited['scanned_characters'],len(observed['limited.eml']['original_code'])]
        nested = observed['nested.eml']['literal_candidates']['candidates']
        assert [candidate['original'] for candidate in nested] == ['eval(("hello"))','String.fromCharCode(foo(65),66)']
        assert all(candidate['status'] == 'unsupported_literal' for candidate in nested)
        hidden, = observed['decoded-url.eml']['literal_candidates']['candidates']
        assert hidden['decoded_text'] == hidden_url and hidden['network_target'] is False
        print('PASS: 8 real full --no-egress JavaScript cases; source, full nested spans, bounded coverage, candidates, no execution, URL inventory, scores and seals verified')


if __name__ == '__main__':
    main()
