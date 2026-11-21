"""Evidence-linked review referrals from static email content."""
from ipaddress import ip_address
from urllib.parse import urlsplit

from tldextract import TLDExtract

from .authentication import normalize_domain
from .form_analysis import FormAnalyzer
from .link_labels import LinkLabels
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


def _declared_host(value):
    if not value or http_url_status(value)[0] != 'completed':
        return None
    parsed = urlsplit(value)
    return parsed.hostname if parsed.username is None else None


def _url_hostname(value):
    return normalize_domain(_declared_host(value))


def _bare_hostname(label):
    if label.isascii() and '.' in label:
        normalized = normalize_domain(label)
        if normalized and normalized == label.lower():
            return normalized
    return None


def _literal_address(host):
    if host and '%' not in host:
        try:
            return str(ip_address(host))
        except ValueError:
            pass
    return None


def _compare_links(text, registrable, evidence, sender, sender_site):
    parser = LinkLabels()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        parser.partial = True
    findings = []
    compared = 0
    for href,label,(line,column) in parser.links:
        displayed = _url_hostname(label)
        bare = displayed is None
        if bare:
            displayed = _bare_hostname(label)
        declared = _declared_host(href)
        address = _literal_address(declared)
        target = address or normalize_domain(declared)
        if not displayed or not target:
            continue
        # A bare label is more ambiguous than a full URL. Its comparison
        # requires a registrable From and a named destination outside it.
        if bare and (address or sender_site is None):
            continue
        displayed_site = registrable(displayed)
        target_site = None if address else registrable(target)
        if not displayed_site or (not address and not target_site):
            parser.partial = True
            continue
        compared += 1
        if not address and (displayed_site == target_site or (bare and target_site == sender_site)):
            continue
        finding = {'displayed_hostname':displayed,'destination_hostname':target,
                   'anchor':{'line':line,'column':column}, **evidence}
        if address:
            findings.append({'rule':'displayed_domain_links_to_ip_address', **finding})
        elif bare:
            findings.append({'rule':'bare_link_hostname_mismatch', 'from_domain':sender, **finding})
        else:
            findings.append({'rule':'displayed_link_hostname_mismatch', **finding})
    return findings, {'status':'partial' if parser.partial else 'completed', 'links_compared':compared}


def _compare_forms(text, analyze, sender_domain, sender_site, registrable, evidence):
    if sender_site is None:
        return [], {'status':'not_evaluated','reason':'Single comparable From domain unavailable'}
    forms = analyze(text)
    if forms['status'] != 'completed' or any(form['nested_form'] for form in forms['forms']):
        return [], {'status':'partial','reason':'Form inventory is partial or contains nested forms'}
    findings = []
    coverage = {'status':'completed','forms_examined':len(forms['forms'])}
    for form in forms['forms']:
        if (form['action_declaration']['status'] != 'declared'
                or form['method_declaration']['status'] != 'declared'
                or (form['method'] or '').casefold() != 'post'):
            continue
        domain = _url_hostname(form['action'])
        first = next((control for control in form['inputs'] if _password_control(control)), None)
        if not domain or first is None:
            continue
        action_domain = registrable(domain)
        if action_domain is None:
            coverage.update(status='partial', reason='Action domain absent from the bundled suffix snapshot')
            continue
        if action_domain != sender_site:
            findings.append({
                'rule':'password_post_to_different_from_domain',
                'from_domain':sender_domain, 'action_hostname':domain,
                'form':_positions(form), 'named_password_input':_positions(first), **evidence,
            })
    return findings, coverage


def evaluate_mail_triage(html_result, body_inventory, headers, from_domain, mime_status):
    """Refer evidence-backed differences for analyst review."""
    referral = {'schema_version':1, 'referral_status':'not_evaluated', 'findings':[],
                'coverage':{'status':'not_evaluated','documents':[],'mime_status':mime_status},
                'calibrated':False, 'scope':'Static review referral on parser-selected outer HTML body'}
    documents = html_result.get('documents', [html_result]) if html_result else []
    sources = {part['part_id']: part for part in body_inventory['parts']}
    analyzer = FormAnalyzer()
    extractor = TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)

    def registrable(hostname):
        parsed = extractor(hostname)
        return (parsed.domain, parsed.suffix) if parsed.domain and parsed.suffix else None

    sender = normalize_domain(from_domain)
    sender_parsed = ((headers.get('from_identity') or {}).get('status') == 'parsed'
                     and headers.get('from_header_count') == 1)
    sender_site = registrable(sender) if documents and sender_parsed and sender else None
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
        if preserved['text_size'] > analyzer.limits.html_bytes:
            coverage['reason'] = 'HTML byte limit'
            continue
        evidence = {
            'source':{name:source[name] for name in ('artifact','part_id','text_path','text_sha256')},
            'source_part_status':preserved['status'],
            'domain_comparison':'bundled public and private suffix snapshot',
        }
        text = document['original_html']
        links, link_coverage = _compare_links(text, registrable, evidence, sender, sender_site)
        forms, form_coverage = _compare_forms(text, analyzer.analyze_forms, sender, sender_site, registrable, evidence)
        referral['findings'].extend(links+forms)
        coverage.update(links=link_coverage, forms=form_coverage)
        if all(row['status'] == 'completed' for row in (preserved, link_coverage, form_coverage)):
            coverage['status'] = 'completed'

    partial = mime_status != 'completed' or any(row['status'] != 'completed' for row in referral['coverage']['documents'])
    referral['coverage']['status'] = 'partial' if partial else 'completed'
    if referral['findings']:
        referral['referral_status'] = 'review'
    elif not partial:
        referral['referral_status'] = 'no_supported_signal'
    return referral
