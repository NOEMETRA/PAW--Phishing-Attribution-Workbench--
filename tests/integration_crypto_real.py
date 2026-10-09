"""Real authenticated cryptography against the production producer and reader."""
import json
import os
from pathlib import Path
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.fernet import InvalidToken
from paw.modules.encrypted_clicking.encrypted_clicker import EncryptedClickAnalyzer
from paw.modules.encrypted_clicking.paw_integration import PAWEncryptedClicking

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    case = root / 'case-real'
    case.mkdir()
    os.environ['CRYPTO_PASSWORD'] = 'local-roundtrip-only-not-a-user-secret'
    os.environ['CRYPTO_VAULT_PATH'] = str(case)
    producer = EncryptedClickAnalyzer()
    payload = {'target_url': 'http://127.0.0.1/', 'security_indicators':
        producer.encrypt_data({'has_password_fields': False}), 'network_requests': []}
    filename = Path(producer.save_encrypted_analysis(producer.encrypt_data(payload), payload['target_url'])).name
    reader = PAWEncryptedClicking()
    reader.cases_dir = str(root)
    decoded = reader.decrypt_analysis_results('case-real', filename, os.environ['CRYPTO_PASSWORD'])
    assert decoded['security_indicators'] == {'has_password_fields': False}
    try:
        reader.decrypt_analysis_results('case-real', filename, 'wrong-password')
    except InvalidToken:
        pass
    else:
        raise AssertionError('Incorrect password accepted')
    assert reader.generate_interaction_script('http://127.0.0.1/', 'banking') == []
    assert reader.analyze_url_safely('http://127.0.0.1/', 'case-real')['status'] == 'unavailable'
    assert reader.enhance_scoring_with_click_analysis(decoded, 'case-real')['final_score'] is None
    assert reader.process_encrypted_results('', 'case-real', os.environ['CRYPTO_PASSWORD'])['status'] == 'completed'
print(json.dumps({'status':'passed', 'authenticated_roundtrip':True,
    'wrong_password_rejected':True, 'experimental_execution':'unavailable'}))
