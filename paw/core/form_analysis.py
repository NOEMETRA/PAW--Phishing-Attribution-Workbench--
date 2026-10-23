"""Bounded supplied-HTML form observations, never merchant/behavior verification."""
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
from .html_contexts import HTMLTextContextParser
import re
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class FormLimits:
    html_bytes: int = 1024 * 1024
    forms: int = 128
    controls: int = 2048
    attributes: int = 8192
    observations: int = 2048
    context_nodes: int = 128
    value_chars: int = 4096

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError('Form limits must be positive integers')


class FormAnalyzer:
    """Inventory literal form/control attributes and unverified pattern matches."""

    def __init__(self, *, limits=None):
        if limits is not None and not isinstance(limits, FormLimits):
            raise ValueError('limits must be FormLimits')
        self.limits = limits if limits is not None else FormLimits()
        # Known payment processors and their patterns
        self.payment_processors = {
            'stripe': {
                'domains': ['js.stripe.com', 'api.stripe.com', 'checkout.stripe.com'],
                'form_patterns': ['stripe', 'pk_live_', 'pk_test_'],
                'input_names': ['stripeToken', 'stripe_key', 'stripe_publishable_key']
            },
            'paypal': {
                'domains': ['www.paypal.com', 'api.paypal.com', 'paypalobjects.com'],
                'form_patterns': ['paypal', 'paypal_button', 'bn_code'],
                'input_names': ['business', 'item_name', 'amount', 'currency_code']
            },
            'braintree': {
                'domains': ['js.braintreegateway.com', 'api.braintreegateway.com'],
                'form_patterns': ['braintree', 'dropin'],
                'input_names': ['braintree_token', 'payment_method_nonce']
            },
            'authorize_net': {
                'domains': ['js.authorize.net', 'api.authorize.net'],
                'form_patterns': ['authorize', 'authnet'],
                'input_names': ['api_login_id', 'transaction_key']
            },
            '2checkout': {
                'domains': ['www.2checkout.com', 'api.2checkout.com'],
                'form_patterns': ['2checkout', 'twocheckout'],
                'input_names': ['sid', 'cart_order_id']
            },
            'adyen': {
                'domains': ['checkoutshopper-live.adyen.com', 'checkoutshopper-test.adyen.com'],
                'form_patterns': ['adyen', 'adyen_checkout'],
                'input_names': ['adyen-encrypted-data', 'adyen-origin-key']
            },
            'square': {
                'domains': ['js.squareup.com', 'api.squareup.com'],
                'form_patterns': ['square', 'squareup'],
                'input_names': ['sq-card-number', 'sq-expiration-date', 'sq-cvv']
            },
            'shopify': {
                'domains': ['cdn.shopify.com', 'checkout.shopify.com'],
                'form_patterns': ['shopify', 'shopify-checkout'],
                'input_names': ['checkout', 'shopify_payment']
            }
        }

        # Common form field patterns
        self.field_patterns = {
            'credit_card': [
                r'card[_-]?number', r'cc[_-]?num', r'credit[_-]?card',
                r'card[_-]?no', r'cc[_-]?number'
            ],
            'expiry': [
                r'expir(?:y|ation)', r'exp[_-]?date', r'exp[_-]?month',
                r'exp[_-]?year', r'cc[_-]?exp'
            ],
            'cvv': [
                r'cvv', r'cvc', r'cvv2', r'cid', r'security[_-]?code',
                r'card[_-]?verification'
            ],
            'name': [
                r'card[_-]?name', r'name[_-]?on[_-]?card', r'holder[_-]?name',
                r'billing[_-]?name'
            ],
            'email': [
                r'email', r'e[_-]?mail', r'customer[_-]?email'
            ],
            'amount': [
                r'amount', r'price', r'total', r'cost', r'value'
            ],
            'currency': [
                r'currency', r'curr', r'iso[_-]?currency'
            ]
        }


    def analyze_forms(self, html_content, url=None):
        result = {'schema_version': 2, 'status': 'completed', 'verified': False,
                  'scope': 'static supplied HTML, not browser form ownership or submission',
                  'source': {'hash_scope': 'complete supplied HTML encoded as UTF-8'},
                  'url': None, 'limits': asdict(self.limits), 'forms': [],
                  'unassigned_controls': [], 'base_observations': [], 'script_observations': [],
                  'processor_observations': [], 'payment_processors': [],
                  'suspicious_patterns': [], 'correlation_keys': [],
                  'attribution_hints': {'status': 'unavailable', 'verified': False,
                      'payment_ecosystem': 'unknown', 'merchant_category': 'unknown',
                      'risk_indicators': [], 'correlation_keys': [],
                      'reason': 'Static strings do not verify payments, risk, merchant or operator identity'},
                  'form_summary': {}, 'errors': [], 'coverage': {
                      'total_form_count': 0, 'omitted_form_count': 0,
                      'total_control_count': 0, 'omitted_control_count': 0,
                      'total_attribute_count': 0, 'omitted_attribute_count': 0,
                      'total_observation_count': 0, 'omitted_observation_count': 0,
                      'total_context_node_count': 0, 'omitted_context_node_count': 0,
                      'omitted_base_node_count': 0, 'omitted_base_href_count': 0,
                      'limited_value_count': 0, 'issues': []}}
        parser = _Forms(self, result)
        if url is not None:
            if not isinstance(url, str) or len(url) > self.limits.value_chars:
                parser.issue('invalid_or_limited_page_url')
            else:
                try:
                    url.encode('utf-8')
                except UnicodeEncodeError:
                    parser.issue('invalid_page_url_unicode')
                else:
                    result['url'] = url
        if not isinstance(html_content, str):
            parser.issue('invalid_html_type')
            return result
        if len(html_content) > self.limits.html_bytes:
            parser.issue('html_byte_limit')
            return result
        try:
            raw = html_content.encode('utf-8')
        except UnicodeEncodeError:
            parser.issue('invalid_html_unicode')
            return result
        if len(raw) > self.limits.html_bytes:
            parser.issue('html_byte_limit')
            return result
        result['source'].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        try:
            parser.feed(html_content)
            parser.close()
        except (AssertionError, ValueError):
            parser.issue('html_parser_failure')
        parser.finish(html_content)
        return result

    def correlate_forms_across_pages(self, page_analyses):
        """Retained API: equality of form patterns is not sourced campaign correlation."""
        return {'status': 'unavailable', 'verified': False,
                'reason': 'No independently validated page/campaign correlation contract',
                'common_processors': {}, 'common_field_patterns': {},
                'form_similarity_clusters': [], 'payment_ecosystem_consistency': {},
                'suspicious_pattern_trends': {}}


class _Forms(HTMLTextContextParser):
    CONTROLS = {'input', 'select', 'textarea', 'button'}
    INERT = set(HTMLTextContextParser.CDATA_CONTENT_ELEMENTS)
    DECLARATIONS = {'action', 'method', 'src', 'href'}

    def __init__(self, analyzer, result):
        super().__init__(convert_charrefs=True)
        self.analyzer, self.result, self.limits = analyzer, result, analyzer.limits
        self.stack = []
        self.inert = None
        self.template_depth = 0
        self.tag_index = 0
        self.control_count = 0
        self.attribute_count = 0
        self.observation_count = 0
        self.context_count = 0

    def issue(self, reason):
        self.result['status'] = 'partial'
        if reason not in self.result['coverage']['issues']:
            self.result['coverage']['issues'].append(reason)
            self.result['errors'].append(reason)

    def attributes(self, attrs):
        rows = []
        omitted_declarations = set()
        self.result['coverage']['total_attribute_count'] += len(attrs)
        for index, (name, value) in enumerate(attrs):
            if self.attribute_count >= self.limits.attributes:
                self.result['coverage']['omitted_attribute_count'] += 1
                if name in self.DECLARATIONS:
                    omitted_declarations.add(name)
                self.issue('attribute_count_limit')
                continue
            self.attribute_count += 1
            row = {'index': index, 'name': name, 'value': value,
                   'name_complete': len(name) <= self.limits.value_chars,
                   'declaration_name': name if name in self.DECLARATIONS else None,
                   'status': 'observed', 'representation': 'HTML parser attribute; character references decoded'}
            if len(name) > self.limits.value_chars or (value is not None and len(value) > self.limits.value_chars):
                self.result['coverage']['limited_value_count'] += 1
                row.update(status='limited', name=name[:self.limits.value_chars], value=None,
                           name_sha256=hashlib.sha256(name.encode('utf-8')).hexdigest())
                if value is not None:
                    row.update(value_preview=value[:self.limits.value_chars],
                               value_sha256=hashlib.sha256(value.encode('utf-8')).hexdigest())
                self.issue('attribute_value_limit')
            rows.append(row)
        return rows, len(rows) == len(attrs) and all(r['status'] == 'observed' for r in rows), sorted(omitted_declarations)

    @staticmethod
    def declared(node, name):
        rows = [r for r in node['attributes'] if r['declaration_name'] == name]
        if name in node['omitted_declaration_names']:
            return {'status': 'not_interpreted_omitted_declaration', 'value': None}
        if len(rows) > 1:
            return {'status': 'not_interpreted_duplicate_attributes', 'value': None}
        if not rows:
            return {'status': 'not_declared', 'value': None}
        if rows[0]['status'] != 'observed':
            return {'status': 'not_interpreted_limited_declaration', 'value': None}
        return {'status': 'declared', 'value': rows[0]['value']}

    def observe(self, **row):
        coverage = self.result['coverage']
        coverage['total_observation_count'] += 1
        if self.observation_count >= self.limits.observations:
            coverage['omitted_observation_count'] += 1
            self.issue('observation_count_limit')
            return None
        self.observation_count += 1
        return {'verified': False, 'interpretation_status': 'lexical_observation', **row}

    def node(self, tag, attrs):
        rows, complete, omitted_declarations = self.attributes(attrs)
        return {'tag': tag, 'tag_index': self.tag_index,
                'line': self.getpos()[0], 'column': self.getpos()[1],
                'attributes': rows, 'attributes_complete': complete,
                'omitted_attribute_count': len(attrs) - len(rows),
                'omitted_declaration_names': omitted_declarations}

    def handle_starttag(self, tag, attrs):
        self.tag_index += 1
        if self.inert:
            return
        if tag == 'template':
            self.template_depth += 1
            return
        if self.template_depth:
            return
        if tag == 'form':
            coverage = self.result['coverage']; coverage['total_form_count'] += 1
            if len(self.result['forms']) >= self.limits.forms:
                coverage['omitted_form_count'] += 1
                self.issue('form_count_limit'); self.stack.append(None)
            else:
                form = self.node(tag, attrs)
                form.update(index=len(self.result['forms']), inputs=[], field_types={},
                            payment_indicators=[], suspicious_elements=[])
                self.result['forms'].append(form); self.stack.append(form)
        elif tag in self.CONTROLS:
            coverage = self.result['coverage']; coverage['total_control_count'] += 1
            if self.control_count >= self.limits.controls or (self.stack and self.stack[-1] is None):
                coverage['omitted_control_count'] += 1; self.issue('control_count_limit_or_omitted_form')
            else:
                self.control_count += 1
                control = self.node(tag, attrs)
                control['field_type_candidates'] = []
                control['form_index'] = self.stack[-1]['index'] if self.stack else None
                for attr in control['attributes']:
                    if attr['status'] != 'observed' or attr['name'] not in {'name', 'id', 'placeholder'} or attr['value'] is None:
                        continue
                    for category, patterns in self.analyzer.field_patterns.items():
                        for pattern in patterns:
                            for match in re.finditer(pattern, attr['value'], re.I):
                                row = self.observe(category=category, context='control_attribute_pattern',
                                    attribute_index=attr['index'], attribute=attr['name'],
                                    matched_text=match.group(), offset=match.start())
                                if row is not None: control['field_type_candidates'].append(row)
                if self.stack: self.stack[-1]['inputs'].append(control)
                else: self.result['unassigned_controls'].append(control)
        elif tag in {'base', 'script'}:
            coverage = self.result['coverage']
            coverage['total_context_node_count'] += 1
            if self.context_count >= self.limits.context_nodes:
                coverage['omitted_context_node_count'] += 1
                if tag == 'base':
                    coverage['omitted_base_node_count'] += 1
                    if any(name == 'href' for name, _value in attrs):
                        coverage['omitted_base_href_count'] += 1
                self.issue('context_node_count_limit')
                if tag == 'script': self.inert = tag
                return
            self.context_count += 1
            script = self.node(tag, attrs)
            if tag == 'base':
                self.result['base_observations'].append(script)
                return
            self.result['script_observations'].append(script)
            source = self.declared(script, 'src')
            script['src_declaration'] = source
            if source['status'] == 'declared' and source['value']:
                try: hostname = urlsplit(source['value']).hostname
                except ValueError: hostname = None
                for name, patterns in self.analyzer.payment_processors.items():
                    if hostname and hostname.lower() in patterns['domains']:
                        row = self.observe(processor=name, context='script_hostname_literal',
                            value=source['value'], tag_index=script['tag_index'],
                            line=script['line'], column=script['column'])
                        if row is not None: self.result['processor_observations'].append(row)
        if tag in self.INERT:
            self.inert = tag

    def handle_endtag(self, tag):
        if self.inert:
            if tag == self.inert: self.inert = None
            return
        if tag == 'template' and self.template_depth:
            self.template_depth -= 1
            return
        if self.template_depth: return
        if tag == 'form' and self.stack: self.stack.pop()

    def resolve(self, literal, base):
        if not isinstance(literal, str):
            return {'status': 'not_evaluated', 'candidate': None}
        try:
            if any(ord(c) <= 32 or ord(c) == 127 for c in literal):
                return {'status': 'unsupported_url_characters', 'candidate': None}
            if base is not None:
                try:
                    parsed_base = urlsplit(base)
                    valid_base = (parsed_base.scheme.lower() in {'http', 'https'} and parsed_base.hostname
                                  and not any(ord(c) <= 32 or ord(c) == 127 for c in base))
                except ValueError:
                    valid_base = False
                if not valid_base:
                    base = None
            candidate = urljoin(base or '', literal)
            if len(candidate) > self.limits.value_chars:
                self.issue('derived_url_value_limit')
                return {'status': 'limited_candidate', 'candidate': None}
            parsed = urlsplit(candidate)
            parsed.port  # reject malformed ports without performing a lookup
            if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
                return {'status': 'unresolved_or_unsupported_scheme', 'candidate': None}
            return {'status': 'derived_candidate', 'candidate': candidate, 'verified': False,
                    'method': 'urllib.parse.urljoin; not browser navigation'}
        except ValueError:
            return {'status': 'malformed_url', 'candidate': None}

    def finish(self, html):
        if self.stack or self.inert or self.template_depth:
            self.issue('unterminated_lexical_scope')
        # First href-bearing base is a lexical candidate context, never a verified origin.
        base = self.result['url']
        selected = False
        for node in self.result['base_observations']:
            declaration = self.declared(node, 'href')
            node['href_declaration'] = declaration
            node['href_resolution'] = self.resolve(declaration['value'], self.result['url'])
            node['selected_candidate_context'] = False
            if not selected and declaration['status'] != 'not_declared':
                selected = True
                node['selected_candidate_context'] = True
                base = node['href_resolution']['candidate']
        # Only an omitted href-bearing base can hide the first join context.
        if not selected and self.result['coverage']['omitted_base_href_count']:
            base = None
        self.result['resolution_context'] = {'value': base, 'verified': False,
            'selected_base_tag_index': next((n['tag_index'] for n in self.result['base_observations']
                                            if n['selected_candidate_context']), None),
            'scope': 'candidate URL-join context from supplied page URL and retained base declaration'}
        for form in self.result['forms']:
            form['action_declaration'] = self.declared(form, 'action')
            form['method_declaration'] = self.declared(form, 'method')
            form['action'] = form['action_declaration']['value']
            form['method'] = form['method_declaration']['value']
            form['action_resolution'] = self.resolve(form['action'], base)
        # Preserve all existing registry tokens as text matches, not detected processors.
        for name, patterns in self.analyzer.payment_processors.items():
            for token in patterns['form_patterns'] + patterns['input_names']:
                for match in re.finditer(re.escape(token), html, re.I):
                    row = self.observe(processor=name, context='supplied_html_token',
                                       token=token, matched_text=match.group(), offset=match.start())
                    if row is not None: self.result['processor_observations'].append(row)
        forms = self.result['forms']
        controls = [control for form in forms for control in form['inputs']]
        self.result['form_summary'] = {'total_forms': len(forms), 'total_inputs': len(controls),
            'unassigned_control_count': len(self.result['unassigned_controls']),
            'scope': 'retained static markup occurrences; not submitted fields or payments',
            'forms_by_declared_method': dict(Counter(form['method'] for form in forms if form['method'] is not None))}


def analyze_html_forms(html_content, url=None):
    return FormAnalyzer().analyze_forms(html_content, url)
