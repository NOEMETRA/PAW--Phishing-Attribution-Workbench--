#!/usr/bin/env python3
"""
Homoglyph detector: sostituisce caratteri omografi (cirillico, unicode fancy) con equivalenti ASCII
"""
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class HomoglyphDetector:
    """Simple homoglyph normalization layer specialized for brand phishing."""

    def __init__(self):
        # Minimal mapping for common phishing targets; can be extended
        self.map = {
            # Cyrillic to Latin
            'а': 'a', 'А': 'A', 'е': 'e', 'Е': 'E', 'о': 'o', 'О': 'O',
            'р': 'p', 'Р': 'P', 'с': 'c', 'С': 'C', 'х': 'x', 'Х': 'X',
            'і': 'i', 'І': 'I', 'ј': 'j', 'Ј': 'J', 'ӏ': 'l', 'Ӏ': 'l',
            # Greek examples
            'ο': 'o', 'ι': 'i'
        }

        # Brand-specific heuristics: map suspicious strings to canonical brand names
        self.brand_aliases = {
            'рayраl': 'paypal',  # Cyrillic/Latin mix -> paypal
            'microsоft': 'microsoft'
        }

        # Additional common confusables (extendable)
        self.map.update({
            # Greek
            'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
            'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
            # Latin lookalikes
            'Ɩ': 'I', 'ⅼ': 'l', 'ɪ': 'i', 'ɡ': 'g', 'ѕ': 's', 'ᴀ': 'a', 'ᴏ': 'o',
            # Misc punctuation / spacing homoglyphs
            '\u200b': '', '\u200c': '', '\u200d': ''
        })

        # Expand brand aliases to catch common phishing targets and visual mixes
        self.brand_aliases.update({
            'paypa1': 'paypal',
            'paypaI': 'paypal',
            'раyраl': 'paypal',  # cyrillic variants
            'goog1e': 'google',
            'gοοgle': 'google',
            'mісrоsoft': 'microsoft'
        })

    def deobfuscate_text(self, text: str) -> Dict[str, Any]:
        if not text:
            return {'final_text': text, 'transformations': []}

        changed = False
        out = []
        for ch in text:
            if ch in self.map:
                out.append(self.map[ch])
                changed = True
            else:
                out.append(ch)

        new_text = ''.join(out)

        # Normalize whitespace/casing for brand heuristics
        norm_lower = new_text.lower()

        transformations: List[Dict[str, Any]] = []
        if changed:
            transformations.append({
                'technique': 'homoglyph_normalization',
                'from': text,
                'to': new_text,
                'description': 'Normalized unicode homoglyphs to ASCII'
            })

        # Brand alias corrections — perform on lowercase normalized text
        for alias, canonical in self.brand_aliases.items():
            if alias in norm_lower and canonical not in norm_lower:
                repaired = norm_lower.replace(alias, canonical)
                transformations.append({
                    'technique': 'brand_alias_fix',
                    'from': new_text,
                    'to': repaired,
                    'description': f'Replaced brand alias {alias} -> {canonical}'
                })
                new_text = repaired

        return {
            'final_text': new_text,
            'transformations': transformations,
            'suspicion_score': 0.15 if transformations else 0.0
        }

    def deobfuscate_url(self, url: str) -> Dict[str, Any]:
        """Compare the real hostname without changing the URL's destination.

        This small character map is a heuristic, not a complete Unicode UTS #39
        skeleton implementation. Its output must never be used as a network URL.
        """
        result = {'original_url':url, 'final_url':url, 'transformations':[],
            'suspicion_indicators':[], 'suspicion_score':0.0, 'is_changed':False}
        try:
            from urllib.parse import urlsplit, unquote
            host = urlsplit(url).hostname or ''
            unicode_host = unquote(host, errors='strict')
            labels = []
            for label in unicode_host.split('.'):
                labels.append(label.encode('ascii').decode('idna') if label.startswith('xn--') else label)
            unicode_host = '.'.join(labels)
            skeleton = ''.join(self.map.get(ch, ch) for ch in unicode_host)
            result['hostname_analysis'] = {'status':'completed', 'observed_hostname':host,
                'unicode_hostname':unicode_host, 'visual_skeleton':skeleton,
                'comparison_only':True, 'complete_unicode_confusables_coverage':False,
                'limitation':'Limited visual character heuristic; no brand ownership or maliciousness verification'}
            if skeleton != unicode_host:
                result['suspicion_indicators'] = [{'type':'hostname_visual_confusable',
                    'severity':'low', 'description':'Hostname contains mapped visual confusables',
                    'comparison_only':True}]
                result['suspicion_score'] = 0.15
        except (ValueError, UnicodeError) as exc:
            result['hostname_analysis'] = {'status':'partial', 'reason':str(exc), 'comparison_only':True}
        return result
