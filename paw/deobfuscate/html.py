#!/usr/bin/env python3
"""
PAW - HTML Deobfuscation Module
Deoffusca contenuto HTML offuscato nei phishing
"""

import re
import base64
import hashlib
import copy
from typing import Dict, List, Any, Optional
import logging
from ..core.html_contexts import HTMLTextContextParser

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    from bs4.builder import HTMLParserTreeBuilder
    from bs4.builder._htmlparser import BeautifulSoupHTMLParser
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False
    logger.warning("BeautifulSoup non disponibile, funzionalità HTML limitate")


if HAS_BEAUTIFULSOUP:
    class _ContextSoupParser(HTMLTextContextParser, BeautifulSoupHTMLParser):
        def handle_data(self, data):
            super().handle_data(self.text_data(data))

    class _ContextSoupBuilder(HTMLParserTreeBuilder):
        def feed(self, markup):
            args, kwargs = self.parser_args
            parser = _ContextSoupParser(self.soup, *args, **kwargs)
            parser.feed(markup)
            parser.close()
            parser.already_closed_empty_element = []


def _observation_soup(markup):
    # The optional tree builder consumes the same lexical boundaries as MIME,
    # URL, CID, form and kit inventories. Original source is never rewritten.
    return BeautifulSoup(markup, builder=_ContextSoupBuilder())


def html_observation_coverage(result):
    """Metadata view shared by the score coverage, reports and API consumers."""
    documents = result.get('documents', []) if result.get('html_schema_version') == 3 else [result] if result else []
    rows = []
    for index, document in enumerate(documents):
        candidates = document.get('encoded_attribute_candidates', {})
        row = {'document_index':index, 'status':document.get('assessment_status', 'not_evaluated'),
               'observers':document.get('observer_coverage', {}),
               'encoded_attributes':{key:candidates[key] for key in ('status', 'limits', 'reason') if key in candidates},
               'source':document.get('source', {})}
        row['encoded_attributes']['inventoried_count'] = len(candidates.get('candidates', []))
        rows.append(row)
    return {'schema_version':1, 'status':result.get('assessment_status', 'not_evaluated'),
            'risk_detection':'not_evaluated', 'document_count':len(rows), 'documents':rows,
            'scope':'parser_selected_static_observations',
            'limitation':'Counts describe enumerated observer records, not browser behavior or exhaustive resources. '
                         'Hidden counts include selector matches; form inputs include descendant matches per form. '
                         'Output limits do not bound parsing or enumeration: callers must bound input. '
                         'Failed/unavailable observers have unknown totals and omissions. '
                         'Script content is a preview; full original HTML is retained. '
                         'No rendering, execution, resource resolution or risk assessment'}

class HTMLDeobfuscator:
    """Deoffuscatore specializzato per HTML"""

    def __init__(self):
        self.hidden_selectors = [
            '[style*="display:none"]',
            '[style*="visibility:hidden"]',
            '[style*="opacity:0"]',
            '[style*="position:absolute"][style*="left:-9999px"]',
            '[style*="position:absolute"][style*="top:-9999px"]',
            '[type="hidden"]',
            '[style*="font-size:0"]',
            '[style*="width:0"]',
            '[style*="height:0"]'
        ]

    def _run_observer(self, name, observer, source, empty, rows_key=None):
        """Bound published rows and retain failures separately from empty results.

        Enumeration still uses the complete parser-selected tree. These are
        output limits, not parser/CPU limits; callers must bound source input.
        """
        limits = {'records': 256}
        if name == 'forms':
            limits['inputs'] = 1024
        if name in {'hidden', 'javascript'}:
            limits['preview_characters'] = 200
        coverage = {'status': 'not_evaluated', 'limits': limits,
                    'observed_count': None, 'inventoried_count': 0,
                    'omitted_count': None, 'issues': [],
                    'count_scope': 'enumerated_records_before_output_limits'}
        if not HAS_BEAUTIFULSOUP:
            coverage['reason'] = 'Optional HTML parser unavailable'
            return copy.deepcopy(empty), coverage
        unavailable_counts = copy.deepcopy(coverage)
        try:
            result = observer(source)
            rows = result if rows_key is None else result[rows_key]
            coverage.update(status='completed', observed_count=len(rows),
                            inventoried_count=min(len(rows), limits['records']),
                            omitted_count=max(0, len(rows)-limits['records']))
            selected = rows[:limits['records']]
            if name == 'forms':
                total_inputs = sum(len(row['inputs']) for row in rows)
                retained_inputs = 0
                for row in selected:
                    row['inputs'] = row['inputs'][:limits['inputs']-retained_inputs]
                    retained_inputs += len(row['inputs'])
                    row['suspicious_indicators'] = [value for value in row['suspicious_indicators']
                                                    if value != 'suspicious_hidden_input']
                    row['suspicious_indicators'].extend('suspicious_hidden_input' for value in row['inputs']
                                                        if value['suspicious'])
                coverage.update(observed_input_count=total_inputs,
                                inventoried_input_count=retained_inputs,
                                omitted_input_count=total_inputs-retained_inputs)
            if rows_key is None:
                result = selected
            else:
                result[rows_key] = selected
            # Aggregate fields describe retained rows only, never omitted rows.
            if name == 'iframes':
                result['suspicious_count'] = sum(len(row['suspicious_indicators']) for row in selected)
            if name == 'javascript':
                result['suspicious_patterns'] = [pattern for row in selected for pattern in row.pop('_patterns')]
                coverage['truncated_content_count'] = sum(row['length'] > 200 for row in selected)
                coverage['omitted_content_characters'] = sum(max(0, row['length']-200) for row in selected)
            if name == 'hidden':
                coverage['truncated_content_count'] = sum(row['element_length'] > 200 for row in selected)
                coverage['omitted_content_characters'] = sum(max(0, row['element_length']-200) for row in selected)
            if coverage['omitted_count'] or coverage.get('omitted_input_count'):
                coverage.update(status='partial', reason='Published observation limit exceeded')
            return result, coverage
        except Exception as exc:
            coverage = unavailable_counts
            coverage.update(status='failed', reason='Static observer failed',
                            issues=[{'code':'observer_error', 'exception_type':type(exc).__name__}])
            return copy.deepcopy(empty), coverage

    def deobfuscate_documents(self, documents: List[str]) -> Dict[str, Any]:
        """Keep independent input documents independent, with local limits."""
        if not isinstance(documents, list) or any(not isinstance(value, str) for value in documents):
            raise ValueError('HTML documents must be a list of strings')
        rows = [dict(document_index=index, **self.deobfuscate_html(value))
                for index, value in enumerate(documents)]
        return {'html_schema_version':3, 'parsing_scope':'independent_documents',
                'document_count':len(rows), 'documents':rows,
                'limits_scope':'per_document; aggregate input must be bounded by the caller',
                'assessment_status':('partial' if any(row['assessment_status']=='partial' for row in rows)
                                     else 'descriptive_only' if rows else 'not_evaluated'),
                'parsing_status':'available' if HAS_BEAUTIFULSOUP else 'not_evaluated',
                'transformations':[], 'suspicion_indicators':[],
                'risk_detection':'not_evaluated', 'suspicion_score':0.0, 'calibrated':False,
                'limitation':'Independent static documents, not one concatenated HTML tree; each document retains its original text, observations and limits. No browser rendering, script execution or calibrated risk assessment'}

    def deobfuscate_html(self, html_content: str) -> Dict[str, Any]:
        """
        Deoffusca contenuto HTML applicando multiple tecniche

        Args:
            html_content: Contenuto HTML potenzialmente offuscato

        Returns:
            Dizionario con HTML finale e trasformazioni applicate
        """
        # Parse original markup only. Global entity decoding turns literal
        # escaped text into fabricated nodes; decoded attributes are candidates.
        current_html = html_content
        candidates = self._observe_base64_attributes(html_content)

        # 3. Analizza elementi nascosti
        hidden_analysis, hidden_coverage = self._run_observer(
            'hidden', self._analyze_hidden_elements, current_html, [])

        # 4. Analizza form offuscati
        form_analysis, form_coverage = self._run_observer(
            'forms', self._analyze_form_obfuscation, current_html,
            {'forms':[], 'suspicious_patterns':[]}, 'forms')

        # 5. Analizza iframe sospetti
        iframe_analysis, iframe_coverage = self._run_observer(
            'iframes', self._analyze_iframes, current_html,
            {'iframes':[], 'suspicious_count':0}, 'iframes')

        # 6. Analizza JavaScript inline offuscato
        js_analysis, js_coverage = self._run_observer(
            'javascript', self._analyze_inline_javascript, current_html,
            {'inline_scripts':[], 'suspicious_patterns':[]}, 'inline_scripts')
        observer_coverage = {'hidden_elements':hidden_coverage, 'forms':form_coverage,
                             'iframes':iframe_coverage, 'javascript':js_coverage}

        return {
            'original_html': html_content,
            'final_html': html_content,
            'html_schema_version': 2,
            'transformations': [],
            'suspicion_indicators': [],
            'encoded_attribute_candidates': candidates,
            'entity_reference_count': len(re.findall(r'&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);', html_content)),
            'hidden_elements': hidden_analysis,
            'form_analysis': form_analysis,
            'iframe_analysis': iframe_analysis,
            'javascript_analysis': js_analysis,
            'observer_coverage': observer_coverage,
            'observer_schema_version': 1,
            'assessment_status': 'partial' if candidates['status'] != 'completed' or any(
                row['status'] != 'completed' for row in observer_coverage.values()) else 'descriptive_only',
            'parsing_status': 'available' if HAS_BEAUTIFULSOUP else 'not_evaluated',
            'risk_detection': 'not_evaluated',
            'suspicion_score': 0.0,
            'calibrated': False,
            'limitation': 'Best-effort static HTML observations and decoded attribute candidates do not establish safety or phishing; no browser rendering or script execution. Shared lexical text boundaries are not HTML5 tree construction, foreign-content or scripting-dependent noscript/escaped script-data interpretation',
        }

    def _observe_base64_attributes(self, html_content: str) -> Dict[str, Any]:
        """Bounded data-URI observations, without changing source attributes."""
        result = {'status':'completed', 'candidates':[],
                  'limits':{'nodes':1024, 'candidates':32, 'encoded_characters':16384}}
        if not HAS_BEAUTIFULSOUP:
            result.update(status='not_evaluated', reason='Optional HTML parser unavailable')
            return result
        try:
            soup = _observation_soup(html_content)
            nodes = soup.find_all(limit=1025)
            if len(nodes) > 1024: result['status'] = 'partial'
            for index, tag in enumerate(nodes[:1024]):
                for attr in ('src','href','data','value','alt'):
                    value = tag.get(attr)
                    if not isinstance(value,str): continue
                    match = re.fullmatch(r'data:([^,]*);base64,(.*)',value,re.IGNORECASE|re.DOTALL)
                    if not match: continue
                    if len(result['candidates']) == 32:
                        result['status'] = 'partial'
                        return result
                    candidate = {'tag':tag.name, 'node_index':index, 'attribute':attr,
                                 'original_attribute':value, 'attribute_source':'parsed_original_html_attribute',
                                 'declared_media_type':match.group(1), 'candidate_only':True,
                                 'network_target':False, 'decoded_text':None}
                    result['candidates'].append(candidate)
                    token = match.group(2)
                    if len(token) > 16384:
                        candidate.update(status='partial',reason='Encoded attribute size limit exceeded')
                        result['status'] = 'partial'
                        continue
                    try:
                        decoded = base64.b64decode(token,validate=True)
                        candidate.update(decoded_size=len(decoded),sha256=hashlib.sha256(decoded).hexdigest())
                        try:
                            candidate.update(status='decoded_text_candidate',decoded_text=decoded.decode('utf-8',errors='strict'))
                        except UnicodeError:
                            candidate['status'] = 'opaque_bytes'
                    except ValueError:
                        candidate.update(status='invalid',reason='Invalid base64 data URI')
            return result
        except Exception as e:
            result.update(status='partial',reason=f'HTML candidate parsing failed: {type(e).__name__}')
            return result

    def _analyze_hidden_elements(self, html_content: str) -> List[Dict]:
        """Analizza elementi HTML nascosti"""
        if not HAS_BEAUTIFULSOUP:
            return []

        soup = _observation_soup(html_content)
        hidden_elements = []

        for selector in self.hidden_selectors:
            elements = soup.select(selector)
            for elem in elements:
                element = str(elem)
                hidden_elements.append({
                    'element': element[:200] + '...' if len(element) > 200 else element,
                    'element_length': len(element),
                    'selector': selector,
                    'tag': elem.name,
                    'observation_only': True,
                    'risk_detection': 'not_evaluated',
                    'attributes': dict(elem.attrs) if elem.attrs else {}
                })

        return hidden_elements


    def _analyze_form_obfuscation(self, html_content: str) -> Dict[str, Any]:
        """Analizza form potenzialmente offuscati"""
        if not HAS_BEAUTIFULSOUP:
            return {'forms': [], 'suspicious_patterns': []}

        soup = _observation_soup(html_content)
        forms = soup.find_all('form')
        analysis = {
            'forms': [],
            'suspicious_patterns': []
        }

        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET'),
                'inputs': [],
                'suspicious_indicators': []
            }

            # Analizza action URL
            action = form.get('action', '')
            if action:
                if self._is_suspicious_url(action):
                    form_data['suspicious_indicators'].append('suspicious_action_url')
                if 'base64' in action.lower():
                    form_data['suspicious_indicators'].append('base64_in_action')

            # Analizza input fields
            inputs = form.find_all('input')
            for input_field in inputs:
                input_data = {
                    'type': input_field.get('type', 'text'),
                    'name': input_field.get('name', ''),
                    'value': input_field.get('value', ''),
                    'suspicious': False
                }

                # Controlla valori nascosti sospetti
                if input_field.get('type') == 'hidden':
                    value = input_field.get('value', '')
                    if value and (len(value) > 100 or 'http' in value):
                        input_data['suspicious'] = True
                        form_data['suspicious_indicators'].append('suspicious_hidden_input')

                form_data['inputs'].append(input_data)

            analysis['forms'].append(form_data)

        return analysis


    def _analyze_iframes(self, html_content: str) -> Dict[str, Any]:
        """Analizza iframe potenzialmente malevoli"""
        if not HAS_BEAUTIFULSOUP:
            return {'iframes': [], 'suspicious_count': 0}

        soup = _observation_soup(html_content)
        iframes = soup.find_all('iframe')
        analysis = {
            'iframes': [],
            'suspicious_count': 0
        }

        for iframe in iframes:
            iframe_data = {
                'src': iframe.get('src', ''),
                'width': iframe.get('width', ''),
                'height': iframe.get('height', ''),
                'suspicious_indicators': [],
                'dimension_attributes_present': {key:key in iframe.attrs for key in ('width', 'height')},
                'visibility': 'not_evaluated',
            }

            src = iframe.get('src', '')
            if src:
                # Iframe con dimensioni 0 o molto piccole
                width = iframe.get('width')
                height = iframe.get('height')

                if any(isinstance(value, str) and re.fullmatch(r'0*[01]', value)
                       for value in (width, height)):
                    iframe_data['suspicious_indicators'].append('invisible_iframe')
                    analysis['suspicious_count'] += 1

                # Src sospetto
                if self._is_suspicious_url(src):
                    iframe_data['suspicious_indicators'].append('suspicious_src')
                    analysis['suspicious_count'] += 1

            analysis['iframes'].append(iframe_data)

        return analysis


    def _analyze_inline_javascript(self, html_content: str) -> Dict[str, Any]:
        """Analizza JavaScript inline per offuscamento"""
        analysis = {
            'inline_scripts': [],
            'suspicious_patterns': []
        }

        if not HAS_BEAUTIFULSOUP:
            return analysis
        # A raw regex sees tags inside comments as scripts. Parse original
        # markup; this is static observation, not browser execution semantics.
        soup = _observation_soup(html_content)
        scripts = [tag.get_text() for tag in soup.find_all('script')]

        for script in scripts:
            script_data = {
                'content': script[:200] + '...' if len(script) > 200 else script,
                'length': len(script),
                'suspicious_indicators': []
            }
            patterns = []

            # Controlla pattern sospetti
            if 'eval(' in script:
                script_data['suspicious_indicators'].append('eval_usage')
                patterns.append('eval_in_script')

            if 'String.fromCharCode' in script:
                script_data['suspicious_indicators'].append('fromcharcode_usage')
                patterns.append('fromcharcode_in_script')

            if 'atob(' in script:
                script_data['suspicious_indicators'].append('base64_decode')
                patterns.append('atob_in_script')

            if 'document.write' in script:
                script_data['suspicious_indicators'].append('document_write')
                patterns.append('document_write_in_script')

            script_data['_patterns'] = patterns
            analysis['inline_scripts'].append(script_data)

        return analysis

    def _is_suspicious_url(self, url: str) -> bool:
        """Verifica se un URL sembra sospetto"""
        if not url:
            return False

        suspicious_patterns = [
            r'data:text/html',
            r'javascript:',
            r'vbscript:',
            r'base64,',
            r'eval\(',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}'
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False
