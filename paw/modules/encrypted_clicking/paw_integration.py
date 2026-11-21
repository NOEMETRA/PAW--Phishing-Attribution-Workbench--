# paw_integration.py - Integrazione del modulo encrypted clicking con PAW
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class PAWEncryptedClicking:
    def __init__(self):
        self.cases_dir = os.path.join(os.getcwd(), "cases")
        os.makedirs(self.cases_dir, exist_ok=True)

    def build_clicker_image(self):
        """Retain the legacy caller's boolean failure contract."""
        logger.warning("Legacy encrypted-clicking image build is retired.")
        return False

    def analyze_url_safely(self, url: str, case_id: str, enable_js: bool = False,
                          interaction_script: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """Analizza URL in container Docker crittografato"""
        # The legacy Docker workflow has not been verified end to end. Do not
        # expose a success result or generate interactions for an unavailable path.
        return {'status': 'unavailable', 'reason':
                'Encrypted Docker browser execution requires isolation and runtime validation'}

    def generate_session_password(self, case_id: str) -> str:
        """Genera password crittografica per la sessione basata sul case ID"""
        import hashlib
        import secrets

        # Combina case_id con salt casuale per questa sessione
        salt = secrets.token_hex(16)
        combined = f"{case_id}_{salt}_{datetime.utcnow().isoformat()}"

        # Genera hash sicuro
        password = hashlib.sha256(combined.encode()).hexdigest()
        return password

    def process_encrypted_results(self, encrypted_logs: str, case_id: str, crypto_password: str) -> Dict[str, Any]:
        """Processa e decrittografa i risultati"""
        from pathlib import Path
        try:
            root = Path(self.cases_dir).resolve()
            case = (root / case_id).resolve()
            if not case.is_relative_to(root):
                raise ValueError('Case path outside cases directory')
            files = list(case.glob('*.enc'))
            if not files:
                raise ValueError('No encrypted evidence file')
            latest = max(files, key=lambda item: item.stat().st_mtime_ns)
            payload = self.decrypt_analysis_results(case_id, latest.name, crypto_password)
            return {'status': 'failed' if payload.get('error') else 'completed',
                    'case_id': case_id, 'analysis_file': latest.name, 'analysis': payload}
        except Exception as exc:
            return {'status': 'failed', 'error': str(exc)}

    def generate_interaction_script(self, url: str, phishing_type: str = "generic") -> List[Dict]:
        """Observation only; interactions must be supplied by the analyst."""
        return []

    def decrypt_analysis_results(self, case_id: str, analysis_file: str,
                                 crypto_password: Optional[str] = None) -> Dict:
        """Authenticate and decrypt persisted evidence with the real session password."""
        import base64
        from pathlib import Path
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        if not crypto_password:
            raise ValueError('Session password required for decryption')
        root = Path(self.cases_dir).resolve()
        case = (root / case_id).resolve()
        path = (case / analysis_file).resolve()
        if not case.is_relative_to(root) or not path.is_relative_to(case):
            raise ValueError('Evidence path outside case directory')
        metadata = json.loads(path.read_text(encoding='utf-8'))
        salt = base64.b64decode(metadata['salt'], validate=True)
        if len(salt) != 32:
            raise ValueError('Invalid encryption salt')
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        cipher = Fernet(base64.urlsafe_b64encode(kdf.derive(crypto_password.encode())))
        payload = json.loads(cipher.decrypt(base64.urlsafe_b64decode(metadata['encrypted_data'])))

        def decode_nested(value):
            if isinstance(value, dict):
                return {key: decode_nested(item) for key, item in value.items()}
            if isinstance(value, list):
                return [decode_nested(item) for item in value]
            if isinstance(value, str):
                try:
                    token = base64.urlsafe_b64decode(value)
                    if token.startswith(b'gAAAA'):
                        return decode_nested(json.loads(cipher.decrypt(token)))
                except (ValueError, InvalidToken):
                    pass
            return value
        return decode_nested(payload)

    def enhance_scoring_with_click_analysis(self, decrypted_analysis: Dict, case_id: str) -> Dict:
        """Click observations have no calibrated score mapping yet."""
        return {'status': 'unavailable', 'reason': 'Click scoring is not calibrated',
                'original_score': None, 'final_score': None}


def main():
    """CLI per testing del modulo"""
    import argparse

    parser = argparse.ArgumentParser(description='PAW Encrypted Clicking Module')
    parser.add_argument('url', help='URL da analizzare')
    parser.add_argument('--case-id', default='test_case', help='ID del caso')
    parser.add_argument('--build', action='store_true', help='Opzione ritirata')
    parser.add_argument('--js', action='store_true', help='Abilita JavaScript')
    parser.add_argument('--phishing-type', choices=['generic', 'credential_harvesting', 'banking'],
                       default='generic', help='Tipo di phishing per script interazione')

    args = parser.parse_args()

    if args.build:
        parser.exit(1, "Legacy encrypted-clicking image build is retired. See the PAW Quick Start.\n")

    paw_clicker = PAWEncryptedClicking()

    # Genera script interazione
    interaction_script = paw_clicker.generate_interaction_script(args.url, args.phishing_type)

    # Esegui analisi
    result = paw_clicker.analyze_url_safely(args.url, args.case_id, args.js, interaction_script)

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
