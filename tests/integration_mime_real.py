"""Run the actual offline engine on real constructed MIME bytes; no mocked modules."""
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import sys
import time

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo))
from paw.core.trace import trace_one
from paw.core.verify import verify_case

root = Path(os.environ.get('PAW_VERIFICATION_DIR', str(repo.parent/'paw-validation'))).resolve()
data = root/'real_mime_run'
data.mkdir(parents=True, exist_ok=True)
payloads = [b'First real attachment bytes', b'Second different attachment bytes', b'']
os.chdir(data)
started = time.perf_counter()
checks, numeric = [], []
for line_length, expected in ((78, 'partial'), (76, 'completed')):
    # The old default SMTP fixture generates a 78-byte QP line. The current
    # transfer contract correctly preserves it as noncanonical/partial. Keep
    # that regression AND a canonical counterpart; do not relax the parser.
    message = EmailMessage(policy=policy.SMTP.clone(max_line_length=line_length))
    message['From'] = 'Analyst <analyst@example.invalid>'
    message['To'] = 'Recipient <recipient@example.invalid>'
    message['Subject'] = 'Controlled MIME regression'
    message.set_content('Caf\u00e9: contenu conserv\u00e9.', charset='iso-8859-1')
    message.add_alternative('<html><body><a href="https://example.invalid/check?a=1&amp;b=2">Caf\u00e9</a></body></html>', subtype='html', charset='iso-8859-1')
    for payload in payloads:
        message.add_attachment(payload, maintype='application', subtype='octet-stream', filename='../same.bin')
    source = data/f'controlled_mime_{line_length}.eml'
    source.write_bytes(message.as_bytes())
    parsed = BytesParser(policy=policy.default).parsebytes(source.read_bytes())
    html, = (part for part in parsed.walk() if part.get_content_type() == 'text/html')
    assert html['Content-Transfer-Encoding'] == 'quoted-printable'
    encoded_lengths = [len(line) for line in html.get_payload().encode('ascii').split(b'\r\n')]
    assert (max(encoded_lengths) == 78 if line_length == 78 else max(encoded_lengths) <= 76)
    case = Path(trace_one(str(source), lang='en', stix=True, abuse=True, anchor=False, no_egress=True, profile='strict'))
    assert (case/'input.eml').read_bytes() == source.read_bytes()
    attachments = json.loads((case/'attachments.json').read_text(encoding='utf-8'))
    assert len(attachments) == 3
    assert {item['sha256'] for item in attachments} == {hashlib.sha256(payload).hexdigest() for payload in payloads}
    assert len({item['evidence_path'] for item in attachments}) == 3
    for item in attachments:
        assert hashlib.sha256((case/item['evidence_path']).read_bytes()).hexdigest() == item['sha256']
        assert item['risk_score'] is None and item['ole_macro'] is None
    headers = json.loads((case/'headers.json').read_text(encoding='utf-8'))
    assert 'https://example.invalid/check?a=1&b=2' in headers['urls']
    mime = json.loads((case/'mime_analysis.json').read_text(encoding='utf-8'))
    assert mime['status'] == expected
    body, = (part for part in mime['parts'] if part['part_id'] == '0.0.1')
    if expected == 'partial':
        assert body['byte_source'] == 'transfer_decoded_partial_syntax'
        assert body['transfer_decoding']['status'] == 'partial'
        assert body['transfer_decoding']['declared_encodings'] == ['quoted-printable']
        assert mime['issues'] == [{'part_id': '0.0.1', 'transfer_decoding': body['transfer_decoding']}]
    else:
        assert body['byte_source'] == 'transfer_decoded_bytes' and mime['issues'] == []
        assert 'transfer_decoding' not in body
    assert body['sha256'] == hashlib.sha256(html.get_payload(decode=True)).hexdigest()
    assert body['decoding']['declared_charset'] == 'iso-8859-1'
    coverage = json.loads((case/'analysis_coverage.json').read_text(encoding='utf-8'))
    assert coverage['stages']['mime_parsing']['status'] == expected
    assert coverage['stages']['mime_body_evidence']['status'] == expected
    score = json.loads((case/'report/score.json').read_text(encoding='utf-8'))
    numeric.append({key: score[key] for key in ('score_components', 'raw_score', 'score', 'decision_score', 'decision')})
    execution = json.loads((case/'execution.json').read_text(encoding='utf-8'))
    assert execution['no_egress'] and not execution['blocked_operations']
    assert verify_case(case)
    checks.append({'case':str(case), 'max_encoded_line_bytes':max(encoded_lengths),
                   'mime_status':expected, 'original_and_payloads_preserved':True, 'seal_verified':True})
assert numeric[0] == numeric[1]
report = {'status':'passed', 'flow':'Actual full offline trace on constructed MIME bytes',
    'sample_origin':'Local controlled fixture, not an original mailbox email',
    'attachment_count':3, 'same_filenames_and_empty_attachment_preserved':True,
    'attachment_count_scope':'per case', 'case_count':len(checks),
    'original_input_preserved':True, 'html_link_entity_decoded':True,
    'charset_metadata_preserved':True, 'all_evidence_verified':True,
    'elapsed_seconds':round(time.perf_counter()-started,3), 'execution':execution, 'checks':checks,
    'canonical_and_noncanonical_numeric_scores_match':True}
(root/'real_mime_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
