# PAW v2.0 Migration Guide

> Historical record. For the current offline installation and container
> instructions, see the [Quick Start](QUICKSTART.md).

## Overview
This guide documents the critical security fixes and refactoring applied to PAW to prepare it for production deployment with real phishing analysis.

## CRITICAL SECURITY FIXES APPLIED ✅

### 1. Cryptography Hardening ✅
**Status: COMPLETED**

- **Removed hardcoded default password** in `encrypted_clicker.py:36`
  - Now requires `CRYPTO_PASSWORD` environment variable
  - Raises `ValueError` if not set
  - Includes instructions to generate secure password: `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`

- **Randomized salt per session** (line 44-48)
  - Replaced static salt `b'paw_encrypted_clicker_salt'`
  - Now generates random 32-byte salt with `secrets.token_bytes(32)`
  - Salt stored in metadata for decryption

- **Path traversal protection** (line 338-348)
  - Validates filenames for `..`, `/`, `\`
  - Verifies final path is within vault directory
  - Uses `os.path.abspath()` for canonicalization

- **Vault path validation** (line 27-33)
  - Validates `CRYPTO_VAULT_PATH` is absolute
  - Checks path exists before usage
  - Prevents injection attacks

### 2. Docker Isolation ✅
**Status: COMPLETED**

Created complete Docker infrastructure:

**Files created:**
- `Dockerfile` - Isolated analysis container
- `docker-compose.yml` - Orchestration with security hardening
- `.dockerignore` - Build optimization

**Security features:**
- Non-root user (`pawuser` UID 1000)
- Read-only filesystem except tmpfs
- Capabilities dropped (CAP_DROP: ALL)
- `no-new-privileges` security opt
- Resource limits (2GB RAM, 2 CPU)
- Network isolation via bridge network
- Tmpfs for Chrome temporary files

The browser container described above was retired. The [offline container
instructions](QUICKSTART.md#analyze-offline-in-a-linux-container) cover the
current service.

### 3. Package Installation ✅
**Status: COMPLETED**

Created standard Python package structure:

**Files created:**
- `setup.py` - setuptools configuration
- `pyproject.toml` - Modern Python packaging (PEP 517/518)

**Installation:**
```bash
# Development install
pip install -e .

# Production install
pip install .

# With optional dependencies
pip install -e .[dev,ml,docs]
```

**Command-line tools installed:**
- `paw` - Main CLI
- `paw-analyze` - Email analysis
- `paw-detonate` - URL detonation
- `paw-canary` - Canary server

### 4. Dependency Management ✅
**Status: COMPLETED**

**`requirements.txt` updated with pinned versions:**
- All 23 dependencies now have exact versions
- `cryptography==42.0.2` (was unpinned - CRITICAL)
- `beautifulsoup4==4.12.2` added (was missing)
- `lxml==4.9.3` added (was missing)

**Security-critical pins:**
```
cryptography==42.0.2   # CVEs in older versions
requests==2.31.0       # SSRF fixes
selenium==4.16.0       # Latest stable
```

### 5. Configuration Management ✅
**Status: COMPLETED**

Created `.env.example` with complete configuration template covering:
- Encryption settings (CRYPTO_PASSWORD, CRYPTO_VAULT_PATH)
- PGP signing (optional)
- Rekor anchoring (optional)
- Canary server (SMTP credentials)
- Threat intelligence APIs (optional)
- Browser settings
- Logging configuration
- Security controls
- Database settings

**Usage:**
```bash
cp .env.example .env
nano .env  # Fill in your values
```

## REMAINING WORK (TO BE COMPLETED)

### 6. Remove Mock Implementations 🔨
**Status: PENDING**
**Priority: HIGH**

#### Files to fix:

**A. `paw/intelligence/criminal_hunter.py`**

Mock implementations to replace:
- Lines 168-216: `_technique_whois_local()` - Returns raw WHOIS data, needs proper parsing
- Lines 434-475: `_correlate_threat_intel_standalone()` - Uses hardcoded threat actor mappings
- Lines 476-481: `_generate_le_package_standalone()` - Minimal placeholder

**Fix strategy:**
```python
# Replace hardcoded threat actor mapping with real-time analysis
def _correlate_threat_intel_standalone(self, domain: str, ips: List[Dict]) -> Dict:
    # Implement real threat correlation based on:
    # - ASN risk scoring
    # - IP reputation databases (local DB, not API)
    # - Historical campaign database
    # - Certificate transparency logs
    # - DNS history patterns

    # Use machine learning classifier trained on labeled phishing datasets
    # DO NOT use hardcoded mappings like:
    # mapping = {'yandex': 'russian_financial_scammer'}  # REMOVE THIS
```

**B. `paw/intelligence/infrastructure_mapper.py`**

Mock implementations to replace:
- Line 82: `_get_whois_info()` - Returns placeholder `{'raw_data': 'WHOIS data placeholder'}`
- Line 95: `_build_timeline()` - Returns hardcoded date `{'date': '2025-10-01', 'event': 'Domain registered'}`

**Fix strategy:**
```python
def _get_whois_info(self, ip: str) -> Dict:
    # Implement real WHOIS lookup using python-whois
    import whois
    try:
        w = whois.whois(ip)
        return {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers,
            'status': w.status,
            'updated_date': w.updated_date
        }
    except Exception as e:
        logger.error(f"WHOIS lookup failed: {e}")
        return {}

def _build_timeline(self, domain: str) -> List[Dict]:
    # Query Certificate Transparency logs for real timeline
    # Use crt.sh API or local CT log database
    # Correlate with passive DNS data
    # Extract registration dates from WHOIS
    # Build chronological event timeline
    pass
```

**C. `paw/core/attribution_matrix.py`**

Hardcoded patterns to remove:
- Static operator patterns (lines 50-80)
- Hardcoded confidence thresholds
- Manual cluster definitions

**Fix strategy:**
```python
# Implement machine learning-based attribution
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

class AttributionMatrix:
    def __init__(self):
        self.model = self._load_or_train_model()
        self.scaler = StandardScaler()

    def calculate_operator_hypothesis(self, pivots: List[Dict]) -> Dict:
        # Extract features from pivots
        features = self._extract_features(pivots)

        # Normalize features
        features_scaled = self.scaler.transform([features])

        # Predict operator cluster
        cluster_id = self.model.predict(features_scaled)[0]
        confidence = self.model.predict_proba(features_scaled)[0][cluster_id]

        return {
            'cluster_id': int(cluster_id),
            'confidence': float(confidence),
            'hypothesis': self._generate_hypothesis(cluster_id, pivots)
        }

    def _load_or_train_model(self):
        # Load pre-trained model from disk or train on labeled dataset
        model_path = 'models/attribution_rf_model.pkl'
        if os.path.exists(model_path):
            import joblib
            return joblib.load(model_path)
        else:
            # Train on labeled phishing campaign dataset
            return self._train_attribution_model()
```

### 7. Sanitize JavaScript Execution 🔨
**Status: PENDING**
**Priority: MEDIUM**

**File:** `paw/modules/encrypted_clicking/encrypted_clicker.py`

**Issues:**
- Lines 103-105: Unsafe CDP command execution
- Lines 264-288: Arbitrary JavaScript execution via `execute_script()`

**Fix:**
```python
# Add script sanitization
def _sanitize_script(self, script: str) -> str:
    """Sanitize JavaScript before execution"""
    # Blacklist dangerous functions
    dangerous_patterns = [
        r'eval\s*\(',
        r'Function\s*\(',
        r'document\.write',
        r'location\s*=',
        r'window\.location',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, script):
            raise ValueError(f"Dangerous JavaScript pattern detected: {pattern}")

    return script

def analyze_dom_changes(self, browser):
    # Whitelist only safe DOM queries
    safe_script = """
        return {
            'url': window.location.href,
            'title': document.title,
            'forms': Array.from(document.forms).length,
            'scripts': document.scripts.length,
            'links': document.links.length
        }
    """
    return browser.execute_script(self._sanitize_script(safe_script))
```

### 8. Implement Certificate Verification 🔨
**Status: PENDING**
**Priority: HIGH**

**File:** `paw/intelligence/criminal_hunter.py:758`

**Issue:**
```python
response = session.request(method, url, timeout=8, allow_redirects=True, verify=False)
# ^^ INSECURE: Disables SSL certificate verification
```

**Fix:**
```python
import os
import certifi

# Use system CA bundle or certifi
response = session.request(
    method,
    url,
    timeout=8,
    allow_redirects=True,
    verify=os.environ.get('PAW_VERIFY_SSL', 'true').lower() == 'true'
)

# For self-signed certificates in testing, use custom CA bundle
# verify='/path/to/custom-ca-bundle.crt'
```

### 9. Input Validation Framework 🔨
**Status: PENDING**
**Priority: MEDIUM**

Create centralized validation module:

**File:** `paw/util/validators.py` (NEW)

```python
import validators
import ipaddress
import re
from urllib.parse import urlparse

class InputValidator:
    """Centralized input validation for PAW"""

    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and sanitize URL"""
        if not isinstance(url, str):
            raise ValueError("URL must be string")

        url = url.strip()

        if not validators.url(url):
            raise ValueError(f"Invalid URL: {url}")

        # Parse and validate components
        parsed = urlparse(url)
        if not parsed.scheme in ['http', 'https']:
            raise ValueError(f"Invalid scheme: {parsed.scheme}")

        return url

    @staticmethod
    def validate_ip(ip: str) -> str:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate domain name"""
        if not isinstance(domain, str):
            raise ValueError("Domain must be string")

        domain = domain.strip().lower()

        # Basic domain regex
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError(f"Invalid domain: {domain}")

        return domain

    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email address"""
        if not validators.email(email):
            raise ValueError(f"Invalid email: {email}")
        return email.strip().lower()

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not isinstance(filename, str):
            raise ValueError("Filename must be string")

        # Remove path separators
        filename = os.path.basename(filename)

        # Remove dangerous characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

        # Prevent directory traversal
        if '..' in filename or filename.startswith('.'):
            raise ValueError(f"Invalid filename: {filename}")

        return filename
```

**Usage throughout codebase:**
```python
from paw.util.validators import InputValidator

# Validate all user inputs
url = InputValidator.validate_url(user_input_url)
domain = InputValidator.validate_domain(user_input_domain)
ip = InputValidator.validate_ip(user_input_ip)
```

### 10. Test Files Reorganization 🔨
**Status: PENDING**
**Priority: LOW**

Move test files to proper structure:

```bash
mkdir -p tests/unit tests/integration tests/fixtures

# Move unit tests
mv test_paw.py tests/unit/
mv test_deobfuscation.py tests/unit/
mv test_deobfuscation_fixed.py tests/unit/
mv PAW/paw/intelligence/test_criminal_hunter.py tests/unit/test_criminal_hunter.py
mv PAW/paw/modules/encrypted_clicking/test_*.py tests/unit/

# Move integration tests
mv run_deob_test.py tests/integration/
mv test_real_paw_case.py tests/integration/
mv test_real_paw_case_direct.py tests/integration/

# Create test configuration
cat > tests/conftest.py << 'EOF'
import pytest
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def sample_eml():
    return os.path.join(os.path.dirname(__file__), 'fixtures', 'sample_phishing.eml')

@pytest.fixture
def crypto_password():
    return 'test_password_do_not_use_in_production'
EOF

# Create pytest configuration
cat > pytest.ini << 'EOF'
[pytest]
minversion = 7.0
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -ra -q --strict-markers --cov=paw --cov-report=html
EOF
```

### 11. Remove Dead Code 🔨
**Status: PENDING**
**Priority: LOW**

**File:** `paw/intelligence/criminal_hunter.py`

Duplicate function definitions:
- Lines 465-474: `_identify_threat_actor_patterns()` (first definition - CALLED)
- Lines 524-556: `_identify_threat_actor_patterns()` (second definition - NEVER CALLED)

**Fix:**
```bash
# Remove duplicate function (lines 524-556)
# Keep only the first definition
```

Unused functions:
- Lines 498-523: `_check_bulletproof_hosting()` - Defined but never called
- Lines 501-523: `_check_geolocation_risk()` - Defined but never called

**Fix:**
```python
# Either remove or integrate into main analysis flow
# If keeping, add calls in hunt_from_domain():

infrastructure_clusters = self._identify_infrastructure_clusters(domain, real_ips)
if self._check_bulletproof_hosting(real_ips):
    infrastructure_clusters['bulletproof_hosting_detected'] = True
if self._check_geolocation_risk(real_ips):
    infrastructure_clusters['high_risk_geolocation'] = True
```

### 12. Standardize Error Handling 🔨
**Status: PENDING**
**Priority: MEDIUM**

Create logging configuration:

**File:** `paw/util/logging_config.py` (NEW)

```python
import logging
import logging.handlers
import os
from pathlib import Path

def setup_logging(
    log_level: str = None,
    log_file: str = None,
    log_format: str = None
):
    """Configure logging for PAW"""

    # Get from environment or use defaults
    log_level = log_level or os.getenv('PAW_LOG_LEVEL', 'INFO')
    log_file = log_file or os.getenv('PAW_LOG_FILE', '/var/log/paw/paw.log')

    if log_format is None:
        log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'

    # Create logger
    logger = logging.getLogger('paw')
    logger.setLevel(getattr(logging, log_level.upper()))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler with rotation
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

# Usage in all modules:
from paw.util.logging_config import setup_logging
logger = setup_logging()

# Replace all print() statements with logger calls:
# print(f"Error: {e}")  → logger.error(f"Error: {e}")
# print(f"Info")        → logger.info("Info")
# print(f"Warning")     → logger.warning("Warning")
```

### 13. Secrets Management for Canary Server 🔨
**Status: PENDING**
**Priority: HIGH**

**File:** `paw/canary/server.py`

**Current issue (lines 18-23):**
```python
smtp_pass = os.environ.get("PAW_SMTP_PASS")  # PASSWORD IN ENV VAR - visible in ps aux
```

**Fix with secrets management:**

```python
import keyring
from cryptography.fernet import Fernet
import base64

class SecretsManager:
    """Secure secrets management for PAW"""

    def __init__(self):
        self.master_key = self._load_or_generate_master_key()
        self.fernet = Fernet(self.master_key)

    def _load_or_generate_master_key(self) -> bytes:
        """Load master key from secure storage"""
        key_file = os.path.expanduser('~/.paw/master.key')

        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True, mode=0o700)
            with open(key_file, 'wb') as f:
                os.chmod(key_file, 0o600)
                f.write(key)
            return key

    def store_secret(self, name: str, value: str):
        """Encrypt and store secret"""
        encrypted = self.fernet.encrypt(value.encode())
        keyring.set_password('paw', name, base64.b64encode(encrypted).decode())

    def retrieve_secret(self, name: str) -> str:
        """Retrieve and decrypt secret"""
        encrypted_b64 = keyring.get_password('paw', name)
        if not encrypted_b64:
            raise ValueError(f"Secret '{name}' not found")

        encrypted = base64.b64decode(encrypted_b64)
        return self.fernet.decrypt(encrypted).decode()

# Usage in canary server:
secrets_mgr = SecretsManager()
smtp_pass = secrets_mgr.retrieve_secret('smtp_password')

# Setup script:
# python -m paw.util.setup_secrets --name smtp_password --value "your_password"
```

### 14. Consolidate PAW/SAVE Directories 🔨
**Status: PENDING**
**Priority: MEDIUM**

**WARNING:** This is destructive. Backup first!

```bash
# 1. Backup SAVE directory
cd /path/to/SentinelV1_paw
cp -r SAVE SAVE_BACKUP_$(date +%Y%m%d)

# 2. Create comparison report
find PAW -type f -name "*.py" | sort > paw_files.txt
find SAVE -type f -name "*.py" | sort > save_files.txt
diff paw_files.txt save_files.txt > files_diff.txt

# 3. Identify unique files in SAVE
grep "^>" files_diff.txt | sed 's/^> //' > save_unique_files.txt

# 4. Copy unique files from SAVE to PAW
while read file; do
    target_file="PAW/${file#SAVE/}"
    mkdir -p "$(dirname "$target_file")"
    cp "$file" "$target_file"
    echo "Copied: $file -> $target_file"
done < save_unique_files.txt

# 5. Identify modified files and review manually
find PAW -name "*.py" | while read paw_file; do
    save_file="${paw_file/PAW/SAVE}"
    if [ -f "$save_file" ]; then
        if ! diff -q "$paw_file" "$save_file" > /dev/null 2>&1; then
            echo "MODIFIED: $paw_file"
            diff -u "$paw_file" "$save_file" > "diffs/$(basename $paw_file).diff"
        fi
    fi
done

# 6. After manual review and merge, remove SAVE
# rm -rf SAVE/  # ONLY after verification!
```

## TESTING CHECKLIST

After completing all fixes, run comprehensive tests:

```bash
# 1. Unit tests
pytest tests/unit/ -v --cov=paw --cov-report=html

# 2. Integration tests (requires Docker)
pytest tests/integration/ -v --docker

# 3. Security audit
bandit -r paw/ -f json -o security_audit.json
safety check -r requirements.txt --json

# 4. Code quality
flake8 paw/ --max-line-length=100 --count
black --check paw/
mypy paw/ --ignore-missing-imports

```

Use the [offline container instructions](QUICKSTART.md#analyze-offline-in-a-linux-container)
for the current build and analysis check.

## DEPLOYMENT CHECKLIST

Before production deployment:

- [ ] All CRITICAL fixes applied
- [ ] All HIGH priority fixes applied
- [ ] Docker image built and tested
- [ ] .env configured with secure passwords
- [ ] SSL certificates valid
- [ ] Log rotation configured
- [ ] Backup strategy in place
- [ ] Monitoring/alerting configured
- [ ] Incident response plan documented
- [ ] Security audit completed
- [ ] Penetration testing performed (optional but recommended)

## POST-DEPLOYMENT MONITORING

Monitor these metrics:

1. **Analysis success rate**: % of phishing emails successfully analyzed
2. **False positive rate**: % of legitimate emails flagged as phishing
3. **Container crashes**: Docker container restart count
4. **SSL errors**: Certificate verification failures
5. **Storage usage**: Vault directory size growth
6. **Memory usage**: Container memory consumption
7. **CPU usage**: Analysis processing time

## SUPPORT

For issues during migration:
1. Check logs: `docker-compose logs paw-analyzer`
2. Verify environment: `docker-compose config`
3. Test individual modules: `python -m pytest tests/unit/test_<module>.py -v`
4. Review security audit: `bandit -r paw/`

---

**Version:** 2.0.0
**Last Updated:** 2025-11-03
**Status:** In Progress (65% complete)
