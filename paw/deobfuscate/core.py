#!/usr/bin/env python3
"""
PAW - Deobfuscation Engine
Modulo avanzato per smascherare tecniche di offuscamento nei phishing
"""

import re
import base64
import html
from urllib.parse import unquote, urlparse
import json
from typing import Dict, List, Any, Optional
import logging

from .url import URLDeobfuscator
from .html import HTMLDeobfuscator
from .javascript import JavaScriptDeobfuscator
from .text import TextDeobfuscator
from .homoglyph import HomoglyphDetector

logger = logging.getLogger(__name__)

class DeobfuscationEngine:
    """Motore principale di deoffuscamento multi-layer"""

    def __init__(self):
        # Order matters: URL -> HTML -> JS -> Text -> Homoglyph
        # We will run iterative passes across layers to fully unravel nested obfuscation
        self.layers = [
            URLDeobfuscator(),
            HTMLDeobfuscator(),
            JavaScriptDeobfuscator(),
            TextDeobfuscator(),
            HomoglyphDetector()
        ]
        self.findings = []

    def analyze_artifacts(self, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analizza artefatti per tecniche di offuscamento

        Args:
            artifacts: Dizionario con chiavi 'urls', 'html', 'javascript', 'text', 'attachments'

        Returns:
            Risultati dell'analisi deoffuscamento
        """
        results = {
            'deobfuscated_artifacts': {},
            'transformations': [],
            'suspicion_score': 0.0,
            'techniques_detected': [],
            'complexity_rating': 'low'
        }

        # Analizza ogni tipo di artefatto
        for artifact_type, artifact_data in artifacts.items():
            if artifact_type == 'urls' and isinstance(artifact_data, list):
                results['deobfuscated_artifacts']['urls'] = []
                for url in artifact_data:
                    deobfuscated = self.deobfuscate_url(url)
                    results['deobfuscated_artifacts']['urls'].append(deobfuscated)
                    results['transformations'].extend(deobfuscated.get('transformations', []))

            elif artifact_type == 'html' and artifact_data:
                deobfuscated = self.deobfuscate_html(artifact_data)
                results['deobfuscated_artifacts']['html'] = deobfuscated
                results['transformations'].extend(deobfuscated.get('transformations', []))

            elif artifact_type == 'javascript' and artifact_data:
                deobfuscated = self.deobfuscate_javascript(artifact_data)
                results['deobfuscated_artifacts']['javascript'] = deobfuscated
                results['transformations'].extend(deobfuscated.get('transformations', []))

            elif artifact_type == 'text' and artifact_data:
                deobfuscated = self.deobfuscate_text(artifact_data)
                results['deobfuscated_artifacts']['text'] = deobfuscated
                results['transformations'].extend(deobfuscated.get('transformations', []))

        # Calcola punteggi complessivi
        results['suspicion_score'] = self.calculate_suspicion_score(results['transformations'])
        results['techniques_detected'] = list(set([t.get('technique', '') for t in results['transformations']]))
        results['complexity_rating'] = self.rate_complexity(results)

        return results

    def deobfuscate_url(self, url: str) -> Dict[str, Any]:
        """Use the URL-specific contract once; preserve all evidence metadata.

        Reapplying generic text/homoglyph layers can fabricate destinations and
        multiply decoder budgets. Visual comparison stays inside URL metadata.
        """
        return self.layers[0].deobfuscate_url(url)

    def deobfuscate_html(self, html_content: str) -> Dict[str, Any]:
        """Deoffusca contenuto HTML con passaggi iterativi."""
        current = html_content
        transformations: List[Dict[str, Any]] = []
        max_iter = 4

        for _ in range(max_iter):
            changed = False
            for layer in self.layers:
                if hasattr(layer, 'deobfuscate_html'):
                    try:
                        res = layer.deobfuscate_html(current)
                        new_html = res.get('final_html') if isinstance(res, dict) else res
                        if isinstance(res, dict):
                            transformations.extend(res.get('transformations', []))
                        if new_html and new_html != current:
                            changed = True
                            current = new_html
                    except Exception as e:
                        logger.debug(f"deobfuscate_html layer error: {e}")
                        continue
            if not changed:
                break

        suspicion = self.calculate_suspicion_score(transformations)
        techniques = [t.get('technique', '') for t in transformations]

        return {
            'final_html': current,
            'transformations': transformations,
            'suspicion_indicators': techniques,
            'suspicion_score': suspicion
        }

    def deobfuscate_javascript(self, js_code: str) -> Dict[str, Any]:
        """Deoffusca codice JavaScript con passaggi iterativi."""
        current = js_code
        transformations: List[Dict[str, Any]] = []
        max_iter = 5

        for _ in range(max_iter):
            changed = False
            for layer in self.layers:
                if hasattr(layer, 'deobfuscate_javascript'):
                    try:
                        res = layer.deobfuscate_javascript(current)
                        new_code = res.get('final_code') if isinstance(res, dict) else res
                        if isinstance(res, dict):
                            transformations.extend(res.get('transformations', []))
                        if new_code and new_code != current:
                            changed = True
                            current = new_code
                    except Exception as e:
                        logger.debug(f"deobfuscate_javascript layer error: {e}")
                        continue
            if not changed:
                break

        suspicion = self.calculate_suspicion_score(transformations)
        techniques = [t.get('technique', '') for t in transformations]

        return {
            'final_code': current,
            'transformations': transformations,
            'suspicion_indicators': techniques,
            'suspicion_score': suspicion
        }

    def deobfuscate_text(self, text: str) -> Dict[str, Any]:
        """Preserve text once; visual comparison is not an iterative decoder."""
        result = self.layers[3].deobfuscate_text(text)
        result['suspicion_indicators'] = []
        return result

    def calculate_suspicion_score(self, transformations: List[Dict]) -> float:
        """Calcola punteggio di sospetto basato sulle trasformazioni"""
        if not transformations:
            return 0.0

        score = 0.0
        technique_weights = {
            'url_encoding': 0.1,
            'base64_decoding': 0.3,
            'javascript_eval': 0.4,
            'string_fromcharcode': 0.3,
            'unicode_escape': 0.2,
            'html_entity_decode': 0.1,
            'character_substitution': 0.2,
            'hidden_elements': 0.4,
            'iframe_abuse': 0.5
        }

        for transformation in transformations:
            technique = transformation.get('technique', '')
            weight = technique_weights.get(technique, 0.1)
            score += weight

        # Bonus per layering (più trasformazioni = più sospetto)
        layering_bonus = min(0.3, len(transformations) * 0.05)
        score += layering_bonus

        return min(1.0, score)

    def rate_complexity(self, results: Dict) -> str:
        """Valuta complessità dell'offuscamento"""
        transformations = results.get('transformations', [])
        techniques = results.get('techniques_detected', [])

        complexity_score = len(transformations) * 0.1 + len(techniques) * 0.2

        if complexity_score >= 0.8:
            return 'very_high'
        elif complexity_score >= 0.5:
            return 'high'
        elif complexity_score >= 0.3:
            return 'medium'
        elif complexity_score >= 0.1:
            return 'low'
        else:
            return 'none'
