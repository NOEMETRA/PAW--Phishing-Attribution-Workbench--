"""Local review drafts. No mail is sent and ARF/X-ARF conformance is not claimed."""
import datetime
import json
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate


def _read(case, name):
    path = Path(case)/name
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}


def _draft(case, reporter_email=None):
    case = Path(case)
    headers = _read(case, 'headers.json')
    return {'schema':'paw-local-review-draft-v1', 'status':'draft',
            'format_compliance':{'arf':'not_validated', 'xarf':'not_validated'},
            'case_id':case.name, 'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'reporter':reporter_email, 'recipient':None,
            'sender_claim':headers.get('from'),
            'authentication_header_claims':headers.get('authentication_results',[]),
            'authentication_analysis':_read(case,'auth.json'),
            'origin_candidate':_read(case,'origin.json'),
            'domains':_read(case,'domains.json'), 'assessment':_read(case,'report/score.json'),
            'original':{'path':'input.eml', 'inputs':_read(case,'manifest.json').get('inputs',[])},
            'integrity':{'status':'verify_case_separately', 'index':'evidence/merkle_index.json',
                         'root':'evidence/merkle_root.bin'},
            'limitations':['Heuristic assessment does not establish abuse or a compromised account',
                          'Header claims are separate from independent verification',
                          'This local draft has no automatic recipient and has not been sent',
                          'Draft is included in the later case seal; a root cannot be embedded circularly']}


def generate_abuse_package(case_dir, Lang='en'):
    case = Path(case_dir)
    draft = _draft(case)
    language = 'it' if Lang.startswith('it') else 'en'
    context = {'case_id':case.name, 'generated_utc':draft['generated_utc'],
               'from_addr':draft['sender_claim'] or 'unavailable',
               'origin_candidate':draft['origin_candidate'].get('ip') or 'unavailable',
               'decision':draft['assessment'].get('decision','Inconclusive'),
               'score':draft['assessment'].get('score'),
               'authentication_json':json.dumps(draft['authentication_analysis'],ensure_ascii=False,indent=2)}
    template = Path(__file__).resolve().parents[1]/'templates'/f'abuse_{language}_review.txt'
    output = case/'package'/f'abuse_email_{language}.txt'
    output.parent.mkdir(exist_ok=True)
    output.write_text(template.read_text(encoding='utf-8').format(**context),encoding='utf-8')
    return str(output)


def generate_arf_package(case_dir, reporter_email=None, recipient_email=None):
    """Compatibility filename for a local MIME draft, not an RFC 5965 report."""
    case = Path(case_dir)
    draft = _draft(case,reporter_email)
    draft['recipient'] = recipient_email
    message = MIMEMultipart('mixed')
    if reporter_email: message['From'] = reporter_email
    if recipient_email: message['To'] = recipient_email
    message['Subject'] = f'PAW local review draft - {case.name}'
    message['Date'] = formatdate()
    message['X-PAW-Status'] = 'local-draft; ARF-conformance-not-validated; not-sent'
    message.attach(MIMEText('Local review draft. Assessment is heuristic; consult auth.json for verification.\n'
                           'This MIME message is not a validated ARF report and has not been sent.','plain','utf-8'))
    details = MIMEApplication(json.dumps(draft,ensure_ascii=False,indent=2).encode('utf-8'),'json')
    details.add_header('Content-Disposition','attachment',filename='paw-review-draft.json')
    message.attach(details)
    original = case/'input.eml'
    if original.exists():
        attachment = MIMEApplication(original.read_bytes(),'octet-stream')
        attachment.add_header('Content-Disposition','attachment',filename='input.eml')
        message.attach(attachment)
    output = case/'package'/'arf_report.eml'
    output.parent.mkdir(exist_ok=True)
    output.write_bytes(message.as_bytes())
    return str(output)


def generate_xarf_package(case_dir, reporter_email=None):
    """Compatibility filename; structured PAW draft, X-ARF conformance unvalidated."""
    output = Path(case_dir)/'package'/'xarf_report.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(_draft(case_dir,reporter_email),indent=2,ensure_ascii=False,allow_nan=False),encoding='utf-8')
    return str(output)
