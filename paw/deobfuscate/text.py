"""Offline text observations; visual comparisons never replace MIME evidence."""
from typing import Any, Dict

from .homoglyph import HomoglyphDetector


class TextDeobfuscator:
    """Preserve decoded text and keep limited visual comparisons descriptive."""

    def __init__(self):
        self.homoglyph_detector = HomoglyphDetector()

    def deobfuscate_text(self, text: str) -> Dict[str, Any]:
        comparison = self.homoglyph_detector.deobfuscate_text(text)
        return {
            'text_schema_version': 2,
            'original_text': text,
            'final_text': text,
            'transformations': [],
            'suspicion_indicators': [],
            'analysis': {
                'word_count': len(text.split()),
                'character_count': len(text),
                'uppercase_ratio': sum(c.isupper() for c in text) / max(1, len(text)),
                'digit_ratio': sum(c.isdigit() for c in text) / max(1, len(text)),
                'special_char_ratio': sum(not c.isalnum() and not c.isspace() for c in text) / max(1, len(text)),
            },
            'visual_comparison': {
                'text': comparison['final_text'],
                'transformations': comparison['transformations'],
                'comparison_only': True,
                'complete_unicode_confusables_coverage': False,
                'limitation': 'Limited visual map; neither a decoded message nor verified impersonation',
            },
            'assessment_status': 'descriptive_only',
            'suspicion_score': 0.0,
            'calibrated': False,
            'readability_improvement': 0.0,
            'limitation': 'Text spelling, style and visual comparisons alone do not establish phishing; URL decoding is separate',
        }
