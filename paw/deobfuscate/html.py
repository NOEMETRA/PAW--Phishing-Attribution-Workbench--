#!/usr/bin/env python3
"""
PAW - HTML Deobfuscation Module
Deoffusca contenuto HTML offuscato nei phishing
"""

import re
import base64
import hashlib
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False
    logger.warning("BeautifulSoup non disponibile, funzionalità HTML limitate")

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
        hidden_analysis = self._analyze_hidden_elements(current_html)

        # 4. Analizza form offuscati
        form_analysis = self._analyze_form_obfuscation(current_html)

        # 5. Analizza iframe sospetti
        iframe_analysis = self._analyze_iframes(current_html)

        # 6. Analizza JavaScript inline offuscato
        js_analysis = self._analyze_inline_javascript(current_html)

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
            'assessment_status': 'partial' if candidates['status'] != 'completed' else 'descriptive_only',
            'parsing_status': 'available' if HAS_BEAUTIFULSOUP else 'not_evaluated',
            'risk_detection': 'not_evaluated',
            'suspicion_score': 0.0,
            'calibrated': False,
            'limitation': 'Best-effort static HTML observations and decoded attribute candidates do not establish safety or phishing; no browser rendering or script execution',
        }

    def _observe_base64_attributes(self, html_content: str) -> Dict[str, Any]:
        """Bounded data-URI observations, without changing source attributes."""
        result = {'status':'completed', 'candidates':[],
                  'limits':{'nodes':1024, 'candidates':32, 'encoded_characters':16384}}
        if not HAS_BEAUTIFULSOUP:
            result.update(status='not_evaluated', reason='Optional HTML parser unavailable')
            return result
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
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

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            hidden_elements = []

            for selector in self.hidden_selectors:
                try:
                    elements = soup.select(selector)
                    for elem in elements:
                        hidden_elements.append({
                            'element': str(elem)[:200] + '...' if len(str(elem)) > 200 else str(elem),
                            'selector': selector,
                            'tag': elem.name,
                            'observation_only': True,
                            'risk_detection': 'not_evaluated',
                            'attributes': dict(elem.attrs) if elem.attrs else {}
                        })
                except Exception:
                    continue

            return hidden_elements

        except Exception as e:
            logger.warning(f"Errore nell'analisi elementi nascosti: {e}")
            return []

    def _analyze_form_obfuscation(self, html_content: str) -> Dict[str, Any]:
        """Analizza form potenzialmente offuscati"""
        if not HAS_BEAUTIFULSOUP:
            return {'forms': [], 'suspicious_patterns': []}

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
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

        except Exception as e:
            logger.warning(f"Errore nell'analisi form: {e}")
            return {'forms': [], 'suspicious_patterns': []}

    def _analyze_iframes(self, html_content: str) -> Dict[str, Any]:
        """Analizza iframe potenzialmente malevoli"""
        if not HAS_BEAUTIFULSOUP:
            return {'iframes': [], 'suspicious_count': 0}

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
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
                    'suspicious_indicators': []
                }

                src = iframe.get('src', '')
                if src:
                    # Iframe con dimensioni 0 o molto piccole
                    width = iframe.get('width', '0')
                    height = iframe.get('height', '0')

                    try:
                        if (int(width) <= 1 or int(height) <= 1):
                            iframe_data['suspicious_indicators'].append('invisible_iframe')
                            analysis['suspicious_count'] += 1
                    except ValueError:
                        pass

                    # Src sospetto
                    if self._is_suspicious_url(src):
                        iframe_data['suspicious_indicators'].append('suspicious_src')
                        analysis['suspicious_count'] += 1

                analysis['iframes'].append(iframe_data)

            return analysis

        except Exception as e:
            logger.warning(f"Errore nell'analisi iframe: {e}")
            return {'iframes': [], 'suspicious_count': 0}

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
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            scripts = [tag.get_text() for tag in soup.find_all('script')
                       if not tag.find_parent(['textarea','title','style'])]
        except Exception:
            return analysis

        for script in scripts:
            script_data = {
                'content': script[:200] + '...' if len(script) > 200 else script,
                'length': len(script),
                'suspicious_indicators': []
            }

            # Controlla pattern sospetti
            if 'eval(' in script:
                script_data['suspicious_indicators'].append('eval_usage')
                analysis['suspicious_patterns'].append('eval_in_script')

            if 'String.fromCharCode' in script:
                script_data['suspicious_indicators'].append('fromcharcode_usage')
                analysis['suspicious_patterns'].append('fromcharcode_in_script')

            if 'atob(' in script:
                script_data['suspicious_indicators'].append('base64_decode')
                analysis['suspicious_patterns'].append('atob_in_script')

            if 'document.write' in script:
                script_data['suspicious_indicators'].append('document_write')
                analysis['suspicious_patterns'].append('document_write_in_script')

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
