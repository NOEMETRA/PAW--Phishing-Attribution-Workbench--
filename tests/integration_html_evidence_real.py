"""Real full offline HTML contracts; fixtures are not classifier accuracy labels."""
import base64
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
    payload = '<form action="https://example.invalid"><input type="password"></form>'
    token = base64.b64encode(payload.encode()).decode()
    samples = {'entities.eml':'<p>Caffè &amp; tea&nbsp;&#233;</p>',
               'escaped.eml':'<p>&lt;form&gt;&lt;input type="password"&gt;&lt;/form&gt;&lt;script&gt;eval("hello")&lt;/script&gt;</p>',
               'encoded.eml':'<iframe src="data:text/html;base64,'+token+'"></iframe>',
               'binary.eml':'<img src="data:image/png;base64,//4A">',
               'static.eml':payload+'<script>eval("hello")</script><div style="display:none">preheader</div>'}
    with tempfile.TemporaryDirectory(prefix='paw-html-',dir=REPO.parent) as temporary:
        root = Path(temporary).resolve()
        inputs = root/'inputs'
        inputs.mkdir()
        originals, decoded_html = {}, {}
        for name, source in samples.items():
            message = EmailMessage(policy=policy.SMTP)
            message['From'] = 'regression@example.invalid'
            message['To'] = 'recipient@example.invalid'
            message['Subject'] = 'Constructed HTML evidence contract; not accuracy ground truth'
            message.set_content(source,subtype='html')
            originals[name] = message.as_bytes()
            decoded_html[name] = BytesParser(policy=policy.default).parsebytes(originals[name]).get_content()
            (inputs/name).write_bytes(originals[name])
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        process = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert process.returncode == 0, process.stdout.decode(errors='replace')[-6000:]+process.stderr.decode(errors='replace')[-2000:]
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        cases = list((root/'cases').glob('case-*'))
        assert len(cases) == len(originals)
        observed = {}
        for case in cases:
            name = read(case/'manifest.json')['source_name']
            assert (case/'input.eml').read_bytes() == originals[name]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            result = read(case/'deobfuscation_results.json')
            html = result['deobfuscated_artifacts']['html']
            assert html['original_html'] == html['final_html'] == decoded_html[name]
            assert html['html_schema_version'] == 2
            assert html['risk_detection'] == 'not_evaluated'
            assert html['suspicion_score'] == 0
            assert result['coverage']['html']['risk_detection'] == 'not_evaluated'
            assert read(case/'report/score.json')['score_components']['deobfuscation_heuristics'] == 0
            observed[name] = html
        assert observed['escaped.eml']['form_analysis']['forms'] == []
        assert observed['escaped.eml']['javascript_analysis']['inline_scripts'] == []
        assert len(observed['static.eml']['form_analysis']['forms']) == 1
        assert len(observed['static.eml']['javascript_analysis']['inline_scripts']) == 1
        assert observed['encoded.eml']['form_analysis']['forms'] == []
        candidate, = observed['encoded.eml']['encoded_attribute_candidates']['candidates']
        assert candidate['decoded_text'] == payload and candidate['candidate_only'] is True
        binary, = observed['binary.eml']['encoded_attribute_candidates']['candidates']
        assert binary['status'] == 'opaque_bytes' and binary['decoded_text'] is None
        print('PASS: 5 real full --no-egress HTML cases; original markup, candidates, descriptive coverage, scores and seals verified')

if __name__ == '__main__':
    main()
