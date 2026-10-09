# paw/core/ml_scorer.py
"""
Heuristic scorer for detecting phishing emails and deciding on canary injection.
"""

import re
from typing import Dict, List, Tuple

class MLScorer:
    """Rule-based heuristic scorer; no trained model for phishing detection and canary injection decisions."""

    def __init__(self):
        # Feature weights for phishing detection
        self.phishing_weights = {
            'urgency_score': 0.5,      # Ridotto ulteriormente
            'threat_score': 0.8,       # Ridotto ulteriormente
            'suspicious_patterns': 0.4, # Ridotto ulteriormente
            'mixed_languages': 1.0,    # Ridotto
            'sender_reputation': 0.5,  # Ridotto
            'content_length': 0.05,    # Ridotto drasticamente
            'capitalization_ratio': 0.2, # Ridotto
            'exclamation_marks': 0.1,  # Ridotto
            'question_marks': 0.05     # Ridotto
        }

        # Thresholds for decisions
        self.canary_injection_threshold = 2.0  # Ridotto - inietta canary per email leggermente sospette
        self.high_risk_threshold = 25.0        # Aumentato molto - blocca solo email estremamente sospette

    def score_email(self, email_data: Dict) -> Dict:
        """
        Score an email for phishing likelihood and canary injection decision.

        Args:
            email_data: Dictionary containing email analysis data

        Returns:
            Dictionary with scores and recommendations
        """
        features = self._extract_features(email_data)
        phishing_score = self._calculate_phishing_score(features)

        result = {
            'phishing_score': phishing_score,
            'features': features,
            'recommendations': self._make_recommendations(phishing_score, features),
            'risk_level': self._classify_risk(phishing_score)
        }

        return result

    def _extract_features(self, email_data: Dict) -> Dict:
        """Extract features from email data for scoring."""
        features = {}

        # Get text content
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        from_addr = email_data.get('from', '')

        text_content = f"{subject} {body} {from_addr}".lower()

        # Urgency indicators
        urgency_words = ['urgent', 'immediate', 'action required', 'time sensitive',
                        'deadline', 'expires', 'limited time', 'act now', 'do not delay',
                        'critical', 'warning', 'alert', 'attention', 'important', 'priority']
        features['urgency_score'] = sum(1 for word in urgency_words if word in text_content)

        # Threat indicators
        threat_words = ['account suspended', 'account blocked', 'account locked',
                       'security breach', 'unauthorized access', 'suspicious activity',
                       'verify your account', 'confirm your identity', 'password expired',
                       'login failed', 'payment declined', 'billing issue', 'refund', 'chargeback']
        features['threat_score'] = sum(1 for word in threat_words if word in text_content)

        # Suspicious patterns
        suspicious_patterns = [
            r'\b\d{4,}\b',  # Reference numbers
            r'\bID[:#]\s*\w+',  # ID references
            r'\bcustomer\s+support\b',
            r'\btechnical\s+support\b',
            r'\bsecurity\s+team\b'
        ]
        features['suspicious_patterns'] = sum(
            1 for pattern in suspicious_patterns
            if re.search(pattern, text_content, re.IGNORECASE)
        )

        # Language mixing
        danish_words = ['konto', 'vil', 'blive', 'bekræft']
        english_phishing = ['account', 'verify', 'confirm', 'login']
        has_danish = any(word in text_content for word in danish_words)
        has_english = any(word in text_content for word in english_phishing)
        features['mixed_languages'] = 1 if has_danish and has_english else 0

        # Sender analysis
        features['sender_reputation'] = self._analyze_sender_reputation(from_addr)

        # Content analysis
        features['content_length'] = len(text_content)
        features['capitalization_ratio'] = sum(1 for c in text_content if c.isupper()) / max(len(text_content), 1)
        features['exclamation_marks'] = text_content.count('!')
        features['question_marks'] = text_content.count('?')

        return features

    def _analyze_sender_reputation(self, from_addr: str) -> float:
        """Analyze sender reputation based on email address patterns."""
        if not from_addr:
            return 0.5

        score = 0.0

        # Check for suspicious patterns in email
        if re.search(r'\d{4,}', from_addr):  # Numbers in email
            score += 0.5
        if '-' in from_addr and from_addr.count('-') > 1:  # Multiple hyphens
            score += 0.3
        if from_addr.count('.') > 2:  # Many dots
            score += 0.2

        # Known suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']
        if any(from_addr.endswith(tld) for tld in suspicious_tlds):
            score += 1.0

        return min(score, 2.0)  # Cap at 2.0

    def _calculate_phishing_score(self, features: Dict) -> float:
        """Calculate overall phishing score using weighted features."""
        score = 0.0

        for feature, weight in self.phishing_weights.items():
            if feature in features:
                score += features[feature] * weight

        return score

    def _classify_risk(self, score: float) -> str:
        """Classify risk level based on score."""
        if score >= self.high_risk_threshold:
            return 'high_risk'
        elif score >= self.canary_injection_threshold:
            return 'medium_risk'
        elif score >= 3.0:
            return 'low_risk'
        else:
            return 'clean'

    def _make_recommendations(self, score: float, features: Dict) -> Dict:
        """Make recommendations based on score and features."""
        recommendations = {
            'inject_canary': False,
            'block_email': False,
            'flag_for_review': False,
            'reasons': []
        }

        if score >= self.high_risk_threshold:
            recommendations['block_email'] = True
            recommendations['reasons'].append('High phishing score - potential threat')
        elif score >= self.canary_injection_threshold:
            recommendations['inject_canary'] = True
            recommendations['flag_for_review'] = True
            recommendations['reasons'].append('Medium risk - inject canary link for monitoring')

        # Additional checks
        if features.get('mixed_languages', 0) > 0:
            recommendations['inject_canary'] = True
            recommendations['reasons'].append('Language mixing detected - suspicious pattern')

        if features.get('sender_reputation', 0) > 1.0:
            recommendations['flag_for_review'] = True
            recommendations['reasons'].append('Suspicious sender reputation')

        return recommendations

# Global scorer instance
_scorer = None

def get_ml_scorer() -> MLScorer:
    """Get the global ML scorer instance."""
    global _scorer
    if _scorer is None:
        _scorer = MLScorer()
    return _scorer

def score_email_for_canary(email_data: Dict) -> Dict:
    """
    Convenience function to score an email and get canary injection recommendation.

    Args:
        email_data: Dictionary with 'subject', 'body', 'from' keys

    Returns:
        Dictionary with scoring results and recommendations
    """
    scorer = get_ml_scorer()
    return scorer.score_email(email_data)