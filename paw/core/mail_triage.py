"""Evidence-linked review referrals from static email content."""
from urllib.parse import urlsplit

from tldextract import TLDExtract

from .authentication import normalize_domain
from .form_analysis import FormAnalyzer
from ..deobfuscate.url import http_url_status


def _positions(node):
    return {name:node[name] for name in ('tag_index', 'line', 'column')}


def _password_control(node):
    if node['tag'] != 'input' or not node['attributes_complete']:
        return False
    attrs = {field['name']: field['value'] for field in node['attributes']}
    if len(attrs) != len(node['attributes']) or {'disabled','form'} & attrs.keys():
        return False
    return (attrs.get('type') or '').casefold() == 'password' and bool((attrs.get('name') or '').strip())


def evaluate_mail_triage(html_result, body_inventory, headers, from_domain, mime_status):
    """Refer an observable cross-domain password form for analyst review."""
    referral = {'schema_version':1, 'referral_status':'not_evaluated', 'findings':[],
                'coverage':{'status':'not_evaluated','documents':[],'mime_status':mime_status},
                'calibrated':False, 'scope':'Static review referral on parser-selected outer HTML body'}
    sender = normalize_domain(from_domain)
    if ((headers.get('from_identity') or {}).get('status') != 'parsed'
            or headers.get('from_header_count') != 1 or not sender):
        referral['coverage']['reason'] = 'Single parsed From domain unavailable'
        return referral

    documents = html_result.get('documents', [html_result]) if html_result else []
    sources = {part['part_id']: part for part in body_inventory['parts']}
    analyze = FormAnalyzer().analyze_forms
    extractor = TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)

    def registrable(hostname):
        parsed = extractor(hostname)
        return (parsed.domain, parsed.suffix) if parsed.domain and parsed.suffix else None

    sender_domain = registrable(sender) if documents else None
    if documents and sender_domain is None:
        referral['coverage']['reason'] = 'From domain absent from the bundled suffix snapshot'
        return referral
    for document in documents:
        source = document['source']
        part_id = source['part_id']
        coverage = {'part_id':part_id, 'status':'partial'}
        referral['coverage']['documents'].append(coverage)
        preserved = sources[part_id]
        if (preserved['text_status'] != 'captured' or preserved['decoding']['status'] != 'completed'
                or preserved.get('mime_context',{}).get('status') != 'completed'):
            coverage['reason'] = 'HTML text or MIME structure is unavailable or ambiguous'
            continue
        forms = analyze(document['original_html'])
        if forms['status'] != 'completed' or any(form['nested_form'] for form in forms['forms']):
            coverage['reason'] = 'Form inventory is partial or contains nested forms'
            continue
        coverage.update(status=preserved['status'], forms_examined=len(forms['forms']))
        if preserved['status'] != 'completed':
            coverage['reason'] = 'Captured HTML text with partial MIME payload evidence'
        for form in forms['forms']:
            if (form['action_declaration']['status'] != 'declared'
                    or form['method_declaration']['status'] != 'declared'
                    or (form['method'] or '').casefold() != 'post'
                    or not form['action'] or http_url_status(form['action'])[0] != 'completed'):
                continue
            target = urlsplit(form['action'])
            domain = normalize_domain(target.hostname)
            if target.username is not None or not domain:
                continue
            first = next((control for control in form['inputs'] if _password_control(control)), None)
            if first is None:
                continue
            action_domain = registrable(domain)
            if action_domain is None:
                coverage.update(status='partial', reason='Action domain absent from the bundled suffix snapshot')
                continue
            if action_domain == sender_domain:
                continue
            referral['findings'].append({
                'rule':'password_post_to_different_from_domain',
                'from_domain':sender, 'action_hostname':domain,
                'domain_comparison':'bundled public and private suffix snapshot',
                'source':{name:source[name] for name in ('artifact','part_id','text_path','text_sha256')},
                'source_part_status':preserved['status'],
                'form':_positions(form), 'named_password_input':_positions(first),
            })

    partial = mime_status != 'completed' or any(row['status'] != 'completed' for row in referral['coverage']['documents'])
    referral['coverage']['status'] = 'partial' if partial else 'completed'
    if referral['findings']:
        referral['referral_status'] = 'review'
    elif not partial:
        referral['referral_status'] = 'no_supported_signal'
    return referral
