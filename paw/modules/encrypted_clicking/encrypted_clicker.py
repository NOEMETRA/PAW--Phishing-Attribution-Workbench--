# encrypted_clicker.py
import os
import json
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests
import time
from datetime import datetime

# Configurazione logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EncryptedClickAnalyzer:
    def __init__(self):
        self.session_key = self.generate_session_keys()
        self.encryption_key = self.derive_encryption_key()
        self.fernet = Fernet(self.encryption_key)
        vault_path = os.environ.get('CRYPTO_VAULT_PATH', '/mnt/crypto_vault')
        # Validate vault path exists and is absolute
        if not os.path.isabs(vault_path):
            raise ValueError(f"CRYPTO_VAULT_PATH must be absolute path, got: {vault_path}")
        if not os.path.exists(vault_path):
            raise ValueError(f"CRYPTO_VAULT_PATH does not exist: {vault_path}")
        self.vault_path = vault_path
        logger.info("EncryptedClickAnalyzer inizializzato con crittografia end-to-end")

    def generate_session_keys(self):
        """Genera chiavi crittografiche per la sessione"""
        return Fernet.generate_key()

    def derive_encryption_key(self):
        """Deriva chiave di encryption da password/master key"""
        password = os.environ.get('CRYPTO_PASSWORD')
        if not password:
            raise ValueError(
                "CRYPTO_PASSWORD environment variable must be set. "
                "Generate a secure password: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )

        # Generate random salt per session and store it
        import secrets
        salt = secrets.token_bytes(32)

        # Store salt for decryption (encrypted with session key)
        self.salt = salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_data(self, data):
        """Crittografa dati sensibili"""
        if isinstance(data, dict):
            data = json.dumps(data)
        elif not isinstance(data, str):
            data = str(data)
        encrypted = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt_data(self, encrypted_data):
        """Decrittografa dati"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Errore nella decrittografia: {e}")
            return None

    def setup_secure_browser(self):
        """Configura browser per analisi sicura"""
        chrome_options = Options()

        # Configurazioni di sicurezza
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--ignore-ssl-errors')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')

        # Privacy enhancements
        chrome_options.add_argument('--incognito')
        chrome_options.add_argument('--disable-plugins-discovery')
        chrome_options.add_argument('--disable-default-apps')

        # Performance optimizations
        chrome_options.add_argument('--disable-images')
        chrome_options.add_argument('--disable-javascript')  # Can be enabled per analysis
        chrome_options.add_argument('--disable-plugins')

        # Network monitoring
        chrome_options.add_argument('--log-net-log=/tmp/network_log.json')
        chrome_options.add_argument('--net-log-capture-mode=Everything')

        # Headless mode for container
        chrome_options.add_argument('--headless')

        return webdriver.Chrome(options=chrome_options)

    def analyze_url_encrypted(self, url, interaction_script=None, enable_js=False):
        """Analizza URL con crittografia end-to-end"""
        browser = self.setup_secure_browser()

        # Enable JavaScript if requested
        if enable_js:
            browser.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
            })

        analysis_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_url': url,
            'interactions': [],
            'network_requests': [],
            'screenshots': [],
            'dom_changes': [],
            'security_indicators': []
        }

        try:
            logger.info(f"Analisi URL: {url}")

            # Navigazione iniziale
            browser.get(url)
            time.sleep(3)

            # Screenshot crittografato
            screenshot_data = self.capture_encrypted_screenshot(browser, 'initial')
            analysis_data['screenshots'].append(screenshot_data)

            # Analisi iniziale DOM
            initial_dom = self.analyze_dom_changes(browser)
            analysis_data['dom_changes'].append(initial_dom)

            # Esegui interazioni se specificate
            if interaction_script:
                interactions = self.execute_interactions(browser, interaction_script)
                analysis_data['interactions'] = interactions

            # Cattura richieste di rete
            network_data = self.capture_network_requests(browser)
            analysis_data['network_requests'] = network_data

            # Analisi sicurezza
            security_data = self.analyze_security_indicators(browser, url)
            analysis_data['security_indicators'] = security_data

            # Analisi DOM finale
            final_dom = self.analyze_dom_changes(browser)
            analysis_data['dom_changes'].append(final_dom)

            logger.info("Analisi completata con successo")

        except Exception as e:
            logger.error(f"Errore durante l'analisi: {e}")
            analysis_data['error'] = str(e)
        finally:
            browser.quit()

        # Crittografa tutto il dataset
        encrypted_analysis = self.encrypt_data(analysis_data)

        # Salva in storage crittografato
        self.save_encrypted_analysis(encrypted_analysis, url)

        return encrypted_analysis

    def capture_encrypted_screenshot(self, browser, stage):
        """Cattura screenshot e lo crittografa"""
        try:
            screenshot_bytes = browser.get_screenshot_as_png()
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode()

            encrypted_screenshot = self.encrypt_data({
                'stage': stage,
                'screenshot': screenshot_b64,
                'timestamp': datetime.utcnow().isoformat()
            })

            return encrypted_screenshot
        except Exception as e:
            logger.error(f"Errore cattura screenshot: {e}")
            return self.encrypt_data({'error': 'Screenshot failed'})

    def execute_interactions(self, browser, interaction_script):
        """Esegue interazioni crittografate sul sito"""
        interactions = []

        for interaction in interaction_script:
            try:
                action_data = {
                    'action': interaction['type'],
                    'target': interaction.get('target'),
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': False
                }

                if interaction['type'] == 'click':
                    element = WebDriverWait(browser, 10).until(
                        EC.element_to_be_clickable((By.CSS_SELECTOR, interaction['selector']))
                    )
                    element.click()
                    action_data['success'] = True

                elif interaction['type'] == 'form_fill':
                    element = WebDriverWait(browser, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, interaction['selector']))
                    )
                    element.clear()
                    element.send_keys(interaction['data'])
                    action_data['success'] = True

                elif interaction['type'] == 'navigation':
                    browser.get(interaction['url'])
                    action_data['success'] = True

                elif interaction['type'] == 'wait':
                    time.sleep(interaction.get('seconds', 2))
                    action_data['success'] = True

                # Cattura stato dopo interazione
                action_data['screenshot'] = self.capture_encrypted_screenshot(browser, f"post_{interaction['type']}")

                interactions.append(self.encrypt_data(action_data))

                time.sleep(1)  # Attesa tra interazioni

            except Exception as e:
                action_data['success'] = False
                action_data['error'] = str(e)
                interactions.append(self.encrypt_data(action_data))
                logger.warning(f"Interazione fallita: {e}")

        return interactions

    def capture_network_requests(self, browser):
        """Cattura richieste di network dal browser"""
        try:
            logs = browser.get_log('performance')
            network_requests = []

            for log_entry in logs:
                try:
                    log_data = json.loads(log_entry['message'])
                    message = log_data.get('message', {})

                    if message.get('method') in ['Network.requestWillBeSent', 'Network.responseReceived']:
                        request_info = {
                            'method': message['method'],
                            'url': message['params'].get('request', {}).get('url', ''),
                            'timestamp': datetime.utcnow().isoformat(),
                            'headers': message['params'].get('request', {}).get('headers', {}),
                            'status': message['params'].get('response', {}).get('status', None)
                        }
                        network_requests.append(self.encrypt_data(request_info))
                except:
                    continue

            return network_requests
        except Exception as e:
            logger.error(f"Errore cattura network: {e}")
            return []

    def analyze_dom_changes(self, browser):
        """Analizza cambiamenti DOM post-interazione"""
        try:
            dom_snapshot = browser.execute_script("""
                return {
                    'url': window.location.href,
                    'title': document.title,
                    'forms': Array.from(document.forms).map(form => ({
                        'action': form.action,
                        'method': form.method,
                        'inputs': Array.from(form.elements).map(input => ({
                            'name': input.name,
                            'type': input.type,
                            'value': input.value,
                            'placeholder': input.placeholder
                        }))
                    })),
                    'scripts': Array.from(document.scripts).map(script => script.src || 'inline'),
                    'links': Array.from(document.links).map(link => ({
                        'href': link.href,
                        'text': link.textContent.trim(),
                        'target': link.target
                    })),
                    'cookies': document.cookie,
                    'localStorage': Object.keys(localStorage || {}),
                    'sessionStorage': Object.keys(sessionStorage || {})
                }
            """)

            return self.encrypt_data(dom_snapshot)
        except Exception as e:
            logger.error(f"Errore analisi DOM: {e}")
            return self.encrypt_data({'error': 'DOM analysis failed'})

    def analyze_security_indicators(self, browser, url):
        """Analizza indicatori di sicurezza"""
        try:
            security_data = browser.execute_script("""
                return {
                    'has_password_fields': document.querySelectorAll('input[type="password"]').length > 0,
                    'has_credit_card_fields': document.querySelectorAll('input[autocomplete*="cc-"]').length > 0,
                    'has_login_forms': document.querySelectorAll('form[action*="login"]').length > 0,
                    'has_external_scripts': Array.from(document.scripts).filter(s => s.src && !s.src.includes(window.location.hostname)).length,
                    'has_suspicious_keywords': ['phishing', 'scam', 'hack', 'virus'].some(word => document.body.textContent.toLowerCase().includes(word)),
                    'redirect_chain': window.location.href !== arguments[0] ? [arguments[0], window.location.href] : [arguments[0]]
                }
            """, url)

            return self.encrypt_data(security_data)
        except Exception as e:
            logger.error(f"Errore analisi sicurezza: {e}")
            return self.encrypt_data({'error': 'Security analysis failed'})

    def save_encrypted_analysis(self, encrypted_data, url):
        """Salva analisi crittografata con path traversal protection"""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
            filename = f"analysis_{timestamp}.enc"

            # Path traversal protection
            if '..' in filename or '/' in filename or '\\' in filename:
                raise ValueError(f"Invalid filename detected: {filename}")

            filepath = os.path.join(self.vault_path, filename)

            # Verify final path is within vault_path
            filepath_abs = os.path.abspath(filepath)
            vault_abs = os.path.abspath(self.vault_path)
            if not filepath_abs.startswith(vault_abs):
                raise ValueError(f"Path traversal attempt detected: {filepath_abs}")

            metadata = {
                'original_url': url,
                'analysis_date': datetime.utcnow().isoformat(),
                'encrypted_data': encrypted_data,
                'encryption_scheme': 'PBKDF2-SHA256-100000/Fernet',
                'salt': base64.b64encode(self.salt).decode(),  # Store salt for decryption
                'analyzer_version': '2.0.0'
            }

            with open(filepath, 'w') as f:
                json.dump(metadata, f, indent=2)
            return filepath

            logger.info(f"Analisi salvata: {filepath}")
        except Exception as e:
            logger.error(f"Errore salvataggio: {e}")
            raise

def main():
    """Funzione principale per esecuzione standalone"""
    import sys

    if len(sys.argv) < 2:
        print("Uso: python3 encrypted_clicker.py <url> [--js] [--interactions file.json]")
        sys.exit(1)

    url = sys.argv[1]
    enable_js = '--js' in sys.argv
    interactions_file = None

    if '--interactions' in sys.argv:
        idx = sys.argv.index('--interactions')
        if idx + 1 < len(sys.argv):
            interactions_file = sys.argv[idx + 1]

    # Carica script interazioni se specificato
    interaction_script = None
    if interactions_file:
        try:
            with open(interactions_file, 'r') as f:
                interaction_script = json.load(f)
        except Exception as e:
            logger.error(f"Errore caricamento interazioni: {e}")

    # Esegui analisi
    analyzer = EncryptedClickAnalyzer()
    result = analyzer.analyze_url_encrypted(url, interaction_script, enable_js)

    # Output risultato crittografato
    print(json.dumps({
        'status': 'encrypted',
        'encrypted_result': result,
        'timestamp': datetime.utcnow().isoformat()
    }))

if __name__ == "__main__":
    main()