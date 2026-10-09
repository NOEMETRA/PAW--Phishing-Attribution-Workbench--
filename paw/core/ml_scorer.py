"""Static content observations, without a trained or calibrated classifier.

Legacy ML/canary entry points remain importable. Their version-2 output cannot
authorize blocking or canary injection, infer safety, or establish attribution.
"""
import re
from email.utils import getaddresses
from typing import Dict


class HeuristicContentScorer:
    """Explain an uncalibrated indicator sum; defer risk assessment to review."""

    urgency_words = ['urgent', 'immediate', 'action required', 'time sensitive',
                     'deadline', 'expires', 'limited time', 'act now', 'do not delay',
                     'critical', 'warning', 'alert', 'attention', 'important', 'priority']
    threat_words = ['account suspended', 'account blocked', 'account locked',
                    'security breach', 'unauthorized access', 'suspicious activity',
                    'verify your account', 'confirm your identity', 'password expired',
                    'login failed', 'payment declined', 'billing issue', 'refund', 'chargeback']
    suspicious_patterns = [r'\b\d{4,}\b', r'\bID[:#]\s*\w+', r'\bcustomer\s+support\b',
                           r'\btechnical\s+support\b', r'\bsecurity\s+team\b']

    def __init__(self):
        # Existing semantic weights retained for continuity, not calibrated risk.
        # Length, capitalization and punctuation are descriptive only.
        self.phishing_weights = {'urgency_score': 0.5, 'threat_score': 0.8,
                                'suspicious_patterns': 0.4, 'mixed_languages': 1.0,
                                'sender_pattern_score': 0.5}

    @staticmethod
    def _matching_words(content_fields, words):
        matches = []
        for word in words:
            pattern = r'(?<!\w)' + r'\s+'.join(re.escape(part) for part in word.split()) + r'(?!\w)'
            if any(re.search(pattern, text, re.IGNORECASE) for text in content_fields):
                matches.append(word)
        return matches

    @staticmethod
    def _sender_patterns(from_addr):
        """Address spelling only, never domain reputation or authentication."""
        if not from_addr:
            return 0.0, [], 'missing'
        try:
            addresses = getaddresses([from_addr])
        except ValueError:
            return 0.0, [], 'unparsed'
        if len(addresses) != 1 or addresses[0][1].count('@') != 1:
            return 0.0, [], 'unparsed'
        address = addresses[0][1].lower()
        local, domain = address.rsplit('@', 1)
        if not local or not domain:
            return 0.0, [], 'unparsed'
        patterns, score = [], 0.0
        if re.search(r'\d{4,}', address):
            patterns.append('four_or_more_digits')
            score += 0.5
        if address.count('-') > 1:
            patterns.append('multiple_hyphens')
            score += 0.3
        if address.count('.') > 2:
            patterns.append('multiple_dots')
            score += 0.2
        if domain.rsplit('.', 1)[-1] in {'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz'}:
            patterns.append('listed_tld')
            score += 1.0
        return min(score, 2.0), patterns, 'parsed'

    def score_email(self, email_data: Dict) -> Dict:
        fields = {name: email_data.get(name) for name in ('subject', 'body', 'from')}
        fields = {name: '' if value is None else value for name, value in fields.items()}
        if any(not isinstance(value, str) for value in fields.values()):
            raise TypeError('Content assessment requires textual subject, body and from fields')
        # Lexical content rules use subject/body. Sender spelling has its own
        # diagnostic, so a display name cannot inject urgency into body evidence.
        content_fields = (fields['subject'], fields['body'])
        # Joined text is only for descriptive statistics. Phrase/pattern evidence
        # must exist within an original field, never across this synthetic space.
        content = ' '.join(content_fields)
        urgency = self._matching_words(content_fields, self.urgency_words)
        threats = self._matching_words(content_fields, self.threat_words)
        patterns = [pattern for pattern in self.suspicious_patterns
                    if any(re.search(pattern, text, re.IGNORECASE) for text in content_fields)]
        danish = self._matching_words(content_fields, ['konto', 'vil', 'blive', 'bekræft'])
        english = self._matching_words(content_fields, ['account', 'verify', 'confirm', 'login'])
        mixed = bool(danish and english)
        sender_score, sender_patterns, sender_syntax = self._sender_patterns(fields['from'])
        features = {'urgency_score': len(urgency), 'threat_score': len(threats),
                    'suspicious_patterns': len(patterns), 'mixed_languages': int(mixed),
                    'sender_pattern_score': sender_score,
                    'content_length': len(content),
                    'capitalization_ratio': sum(c.isupper() for c in content) / max(len(content), 1),
                    'exclamation_marks': content.count('!'), 'question_marks': content.count('?')}
        contributions = {name: features[name] * weight for name, weight in self.phishing_weights.items()}
        score = sum(contributions.values())
        evidence = {'urgency_score': urgency, 'threat_score': threats, 'suspicious_patterns': patterns,
                    'mixed_languages': {'danish_matches': danish, 'english_matches': english} if mixed else {},
                    'sender_pattern_score': sender_patterns}
        reasons = [name for name, contribution in contributions.items() if contribution > 0]
        return {
            'schema_version': 2,
            'method': 'static_content_heuristics',
            'assessment_status': 'heuristic_only',
            'calibrated': False,
            'score_kind': 'uncalibrated_indicator_sum',
            # Compatibility name; consumers must check schema_version/score_kind.
            'phishing_score': score,
            'features': features,
            'weights': dict(self.phishing_weights),
            'contributions': contributions,
            'evidence': evidence,
            'risk_level': 'not_evaluated',
            'recommendations': {'inject_canary': False, 'block_email': False,
                                'flag_for_review': bool(reasons), 'reasons': reasons,
                                'action_status': 'not_authorized_by_heuristics'},
            'coverage': {'inputs_present': {name: bool(value) for name, value in fields.items()},
                         'sender_syntax': sender_syntax, 'sender_verified': False,
                         'rules_language_scope': ['English phrases', 'Danish/English word co-occurrence']},
            'limitation': ('Uncalibrated lexical indicators, not a probability or a phishing verdict. '
                           'Matches can occur in legitimate mail; no matches do not establish safety. '
                           'Sender spelling is not verified reputation. Human context is required.'),
        }


# Compatibility imports for callers using the former ML/canary names.
MLScorer = HeuristicContentScorer
_scorer = None


def get_ml_scorer() -> HeuristicContentScorer:
    global _scorer
    if _scorer is None:
        _scorer = HeuristicContentScorer()
    return _scorer


def analyze_content_indicators(email_data: Dict) -> Dict:
    return get_ml_scorer().score_email(email_data)


def score_email_for_canary(email_data: Dict) -> Dict:
    """Compatibility wrapper; version-2 output never recommends canary injection."""
    return analyze_content_indicators(email_data)
