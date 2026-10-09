"""Run the actual offline engine on real constructed MIME bytes; no mocked modules."""
from email.message import EmailMessage
from email import policy
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
message = EmailMessage(policy=policy.SMTP)
message['From'] = 'Analyst <analyst@example.invalid>'
message['To'] = 'Recipient <recipient@example.invalid>'
message['Subject'] = 'Controlled MIME regression'
message.set_content('Caf\u00e9: contenu conserv\u00e9.', charset='iso-8859-1')
message.add_alternative('<html><body><a href="https://example.invalid/check?a=1&amp;b=2">Caf\u00e9</a></body></html>', subtype='html', charset='iso-8859-1')
payloads = [b'First real attachment bytes', b'Second different attachment bytes', b'']
for payload in payloads:
    message.add_attachment(payload, maintype='application', subtype='octet-stream', filename='../same.bin')
source = data/'controlled_mime.eml'
source.write_bytes(message.as_bytes())
os.chdir(data)
started = time.perf_counter()
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
assert mime['status'] == 'completed'
assert any(part.get('decoding', {}).get('declared_charset') == 'iso-8859-1' for part in mime['parts'])
execution = json.loads((case/'execution.json').read_text(encoding='utf-8'))
assert execution['no_egress'] and not execution['blocked_operations']
assert verify_case(case)
report = {'status':'passed', 'flow':'Actual full offline trace on constructed MIME bytes',
    'sample_origin':'Local controlled fixture, not an original mailbox email',
    'attachment_count':3, 'same_filenames_and_empty_attachment_preserved':True,
    'original_input_preserved':True, 'html_link_entity_decoded':True,
    'charset_metadata_preserved':True, 'all_evidence_verified':True,
    'elapsed_seconds':round(time.perf_counter()-started,3), 'execution':execution}
(root/'real_mime_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
