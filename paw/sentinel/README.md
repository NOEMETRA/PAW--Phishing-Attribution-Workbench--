# Sentinel Module - Continuous Monitoring & Intelligence

The **Sentinel module** is a revolutionary feature that transforms PAW from a static analyzer into a **living threat intelligence platform**. It provides continuous monitoring of phishing campaigns, victim intelligence tracking, and geographic attribution analysis.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Database Schema](#database-schema)
- [Core Components](#core-components)
- [Features](#features)
- [Usage](#usage)
- [Configuration](#configuration)
- [Workflow Examples](#workflow-examples)
- [API Reference](#api-reference)

---

## Overview

Sentinel enables security teams to:

1. **Monitor Active Campaigns**: Track phishing sites over time with automated checks
2. **Classify Victims vs. Attackers**: Revolutionary IP intelligence with geolocation
3. **Generate Geographic Reports**: Interactive maps showing campaign distribution
4. **Detect Infrastructure Changes**: Content hashing and screenshot comparison
5. **Automate Alerts**: Real-time notifications for campaign status changes

### Why Sentinel?

Traditional phishing analysis is **point-in-time**. You analyze an email, generate a report, and move on. But phishing campaigns are **living operations**:

- Attackers move infrastructure
- Domains get taken down
- Victims continue to click links days/weeks later
- Attackers monitor their own campaigns

**Sentinel bridges this gap** by providing continuous visibility into campaign evolution.

---

## Architecture

```
SentinelMonitor (monitor.py)
    │
    ├── Configuration (config.py)
    │   └── Settings, intervals, workers
    │
    ├── Database (database.py)
    │   ├── campaigns table
    │   ├── checks table
    │   ├── alerts table
    │   ├── victim_intelligence table
    │   └── enrichment_results table
    │
    ├── File Monitor (file_monitor.py)
    │   ├── Merkle tree construction
    │   ├── File hashing (SHA256)
    │   └── Tamper detection
    │
    ├── IP Analyzer (ip_analyzer.py)
    │   ├── Geolocation (ip-api.com)
    │   ├── WHOIS lookups
    │   ├── Reverse DNS
    │   └── Risk scoring
    │
    ├── Intelligence Analyzer (intelligence_analyzer.py)
    │   ├── Victim classification
    │   ├── Attacker correlation
    │   ├── Network analysis
    │   └── Risk assessment
    │
    └── Geographic Reports (geographic_reports.py)
        ├── HTML map generation
        ├── Country statistics
        ├── Attacker localization
        └── Campaign correlation
```

---

## Database Schema

Sentinel uses SQLite database (`sentinel.db`) with the following tables:

### campaigns

Stores monitored phishing campaigns.

```sql
CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,              -- PAW case ID
    url TEXT NOT NULL UNIQUE,           -- Phishing URL
    domain TEXT,                        -- Extracted domain
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_check TIMESTAMP,               -- Last monitoring check
    status TEXT DEFAULT 'active',       -- active/down/changed/error
    metadata TEXT                       -- JSON: {notes, tags, priority}
);
```

### checks

Records each monitoring check performed.

```sql
CREATE TABLE checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    check_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL,               -- up/down/error
    http_status INTEGER,                -- HTTP status code
    response_time REAL,                 -- Response time in seconds
    content_hash TEXT,                  -- SHA256 of response body
    screenshot_path TEXT,               -- Path to screenshot
    metadata TEXT,                      -- JSON: {headers, redirects, etc.}
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

### alerts

Automated alerts for campaign changes.

```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT NOT NULL,           -- status_change/content_change/takedown
    severity TEXT DEFAULT 'medium',     -- low/medium/high/critical
    message TEXT NOT NULL,
    acknowledged BOOLEAN DEFAULT 0,
    metadata TEXT,                      -- JSON: {previous_state, new_state}
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

### victim_intelligence

**REVOLUTIONARY FEATURE**: Tracks and classifies IPs interacting with phishing campaigns.

```sql
CREATE TABLE victim_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_ip TEXT NOT NULL,
    victim_ua TEXT,                     -- User-Agent
    click_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    phishing_url TEXT NOT NULL,
    case_id TEXT NOT NULL,

    -- Classification
    interaction_type TEXT,              -- victim/attacker/suspicious
    interaction_confidence REAL,        -- 0.0-1.0

    -- Geolocation
    geolocation_data TEXT,              -- JSON: {country, city, lat, lon, isp}
    whois_data TEXT,                    -- JSON: WHOIS lookup result
    reverse_dns TEXT,                   -- PTR record

    -- Attribution
    attacker_correlation TEXT,          -- JSON: correlation with known attackers
    risk_score INTEGER,                 -- 1-10 scale

    -- Processing
    analyzed_status TEXT DEFAULT 'captured', -- captured/analyzing/analyzed
    notes TEXT
);
```

### enrichment_results

Caches domain enrichment data to avoid redundant API calls.

```sql
CREATE TABLE enrichment_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    enrichment_json TEXT NOT NULL,      -- Complete enrichment data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id, domain)
);
```

---

## Core Components

### 1. SentinelMonitor ([monitor.py](monitor.py))

Main monitoring engine (13,106 lines).

**Key Features:**
- Concurrent campaign checking (5 workers)
- Configurable check intervals (default: 30 minutes)
- HTTP status monitoring
- Content change detection (SHA256 hashing)
- Screenshot capture using Playwright
- Alert generation

**Main Class:**

```python
class SentinelMonitor:
    def __init__(self, db_path="sentinel.db", config=None):
        """Initialize Sentinel monitor"""

    def add_campaign(self, case_id, url, metadata=None):
        """Add new campaign to monitoring"""

    def start_monitoring(self, interval=1800):
        """Start continuous monitoring (default: 30 min)"""

    def check_campaign(self, campaign_id):
        """Perform single campaign check"""

    def check_all_campaigns(self):
        """Check all active campaigns"""

    def get_campaign_status(self, campaign_id):
        """Get current campaign status"""
```

### 2. Database Manager ([database.py](database.py))

Database operations and schema management (30,449 lines).

**Key Functions:**

```python
def init_database(db_path="sentinel.db"):
    """Initialize database with schema"""

def add_campaign(db_path, case_id, url, domain=None):
    """Add new campaign"""

def record_check(db_path, campaign_id, status, http_status, content_hash):
    """Record monitoring check result"""

def create_alert(db_path, campaign_id, alert_type, message, severity="medium"):
    """Create new alert"""

def add_victim_intelligence(db_path, victim_ip, phishing_url, case_id, **kwargs):
    """Add victim IP intelligence"""

def get_campaigns(db_path, status=None):
    """Retrieve campaigns (optionally filtered by status)"""
```

### 3. IP Analyzer ([ip_analyzer.py](ip_analyzer.py))

IP geolocation and enrichment (11,349 lines).

**Features:**
- IP geolocation using ip-api.com
- WHOIS lookups
- Reverse DNS resolution
- Network information (private/public, /24 range)
- Risk indicator detection

**Main Functions:**

```python
def geolocate_ip(ip_address):
    """
    Geolocate IP address.

    Returns:
        {
            'country': 'US',
            'country_code': 'US',
            'region': 'California',
            'city': 'San Francisco',
            'zip': '94105',
            'lat': 37.7749,
            'lon': -122.4194,
            'timezone': 'America/Los_Angeles',
            'isp': 'Cloudflare Inc.',
            'org': 'Cloudflare',
            'as': 'AS13335 Cloudflare, Inc.'
        }
    """

def whois_lookup(ip_address):
    """Perform WHOIS lookup"""

def reverse_dns(ip_address):
    """Get reverse DNS (PTR record)"""

def analyze_ip(ip_address):
    """
    Complete IP analysis.

    Returns:
        {
            'ip': '1.2.3.4',
            'geolocation': {...},
            'whois': {...},
            'reverse_dns': 'host.example.com',
            'network_info': {
                'is_private': False,
                'is_loopback': False,
                'network': '1.2.3.0/24'
            },
            'risk_indicators': [
                'High-risk country: Russia',
                'Known bulletproof hosting: Example ISP'
            ]
        }
    """
```

### 4. Intelligence Analyzer ([intelligence_analyzer.py](intelligence_analyzer.py))

Victim vs. attacker classification and correlation (28,169 lines).

**Classification Algorithm:**

```python
def classify_interaction(ip_analysis, click_patterns, case_context):
    """
    Classify IP as victim, attacker, or suspicious.

    Factors:
    - Geographic location (high-risk countries)
    - ISP type (bulletproof hosting, data centers)
    - User-Agent patterns
    - Click timing (bot-like behavior)
    - Multiple victims from same /24 range
    - Reverse DNS presence

    Returns:
        {
            'interaction_type': 'attacker',  # or 'victim' or 'suspicious'
            'interaction_confidence': 0.85,  # 0.0-1.0
            'risk_score': 8,                 # 1-10
            'reasoning': [
                'Multiple clicks from same /24',
                'Bulletproof hosting provider',
                'No reverse DNS'
            ]
        }
    """
```

**Main Functions:**

```python
def analyze_victim_intelligence(db_path, case_id=None):
    """Analyze all victim intelligence records"""

def correlate_attackers(db_path):
    """Find attacker correlation patterns"""

def identify_attacker_networks(db_path, case_id):
    """Identify attacker /24 networks"""

def generate_intelligence_report(db_path, case_id):
    """Generate comprehensive intelligence report"""
```

### 5. Geographic Reports ([geographic_reports.py](geographic_reports.py))

Interactive HTML map generation (19,286 lines).

**Features:**
- World map visualization using Leaflet.js
- Country-level statistics
- Attacker vs. victim markers
- Risk heat maps
- Campaign timeline

**Main Functions:**

```python
def generate_geographic_report(db_path, case_id, output_path="report.html"):
    """
    Generate interactive HTML map.

    Features:
    - Victim locations (blue markers)
    - Attacker locations (red markers)
    - Suspicious IPs (yellow markers)
    - Click timeline
    - Country statistics table
    - Risk heat map
    """

def generate_statistics(db_path, case_id=None):
    """
    Generate geographic statistics.

    Returns:
        {
            'total_clicks': 142,
            'unique_ips': 89,
            'unique_countries': 15,
            'victims': 75,
            'attackers': 10,
            'suspicious': 4,
            'top_countries': [
                {'country': 'US', 'count': 45},
                {'country': 'GB', 'count': 23},
                ...
            ],
            'attacker_countries': ['RU', 'CN'],
            'campaign_duration_days': 7
        }
    """
```

### 6. File Monitor ([file_monitor.py](file_monitor.py))

File integrity monitoring using Merkle trees (7,908 lines).

**Features:**
- Recursive file hashing (SHA256)
- Merkle tree construction
- Baseline creation
- Tamper detection

**Main Functions:**

```python
def create_baseline(case_path):
    """
    Create Merkle tree baseline for case files.

    Output:
    - merkle_index.json: {file_path: hash}
    - merkle_root.bin: Root hash
    """

def verify_integrity(case_path):
    """
    Verify file integrity against baseline.

    Returns:
        {
            'valid': True/False,
            'merkle_root_match': True/False,
            'new_files': [...],
            'modified_files': [...],
            'deleted_files': [...]
        }
    """
```

---

## Features

### 1. Continuous Campaign Monitoring

Monitor phishing campaigns with automated checks:

```python
from paw.sentinel.monitor import SentinelMonitor

# Initialize monitor
monitor = SentinelMonitor(db_path="sentinel.db")

# Add campaign
monitor.add_campaign(
    case_id="case-2025-11-08-abc",
    url="https://phishing.example.com/login",
    metadata={"priority": "high", "campaign_name": "PayPal Phish 2025"}
)

# Start monitoring (checks every 30 minutes)
monitor.start_monitoring(interval=1800)
```

**What gets monitored:**
- HTTP status (200, 404, 503, etc.)
- Response time
- Content changes (SHA256 hash comparison)
- Screenshot capture
- SSL certificate changes

### 2. Victim Intelligence Tracking

When victims click phishing links (via Canary server), their IPs are automatically analyzed:

```python
from paw.sentinel.database import add_victim_intelligence
from paw.sentinel.ip_analyzer import analyze_ip
from paw.sentinel.intelligence_analyzer import classify_interaction

# Victim clicked phishing link (captured by Canary server)
victim_ip = "192.168.1.100"
phishing_url = "https://phishing.example.com/login"
case_id = "case-2025-11-08-abc"

# Analyze IP
ip_analysis = analyze_ip(victim_ip)

# Classify interaction
classification = classify_interaction(
    ip_analysis,
    click_patterns={},  # Historical click data
    case_context={}
)

# Store in database
add_victim_intelligence(
    db_path="sentinel.db",
    victim_ip=victim_ip,
    phishing_url=phishing_url,
    case_id=case_id,
    interaction_type=classification['interaction_type'],
    interaction_confidence=classification['interaction_confidence'],
    geolocation_data=json.dumps(ip_analysis['geolocation']),
    risk_score=classification['risk_score']
)
```

### 3. Geographic Reporting

Generate interactive HTML maps:

```python
from paw.sentinel.geographic_reports import generate_geographic_report

# Generate report for specific case
generate_geographic_report(
    db_path="sentinel.db",
    case_id="case-2025-11-08-abc",
    output_path="reports/geographic_report.html"
)
```

**Report includes:**
- Interactive world map (Leaflet.js)
- Victim markers (blue pins)
- Attacker markers (red pins)
- Suspicious IPs (yellow pins)
- Country statistics table
- Timeline of clicks
- Risk heat map

### 4. Automated Alerts

Receive alerts for campaign changes:

```python
from paw.sentinel.database import get_alerts

# Get recent alerts
alerts = get_alerts(db_path="sentinel.db", acknowledged=False)

for alert in alerts:
    print(f"[{alert['severity'].upper()}] {alert['message']}")
    # Alert examples:
    # - "Campaign https://phish.com went down (404)"
    # - "Content changed for campaign ID 5"
    # - "New attacker IP detected: 1.2.3.4"
```

### 5. File Integrity Monitoring

Detect tampering of case evidence:

```python
from paw.sentinel.file_monitor import create_baseline, verify_integrity

# Create baseline after case analysis
create_baseline("cases/case-2025-11-08-abc")

# Later: verify integrity
result = verify_integrity("cases/case-2025-11-08-abc")

if not result['valid']:
    print("TAMPERING DETECTED!")
    print(f"Modified files: {result['modified_files']}")
    print(f"Deleted files: {result['deleted_files']}")
```

---

## Usage

### CLI Commands

```bash
# Start continuous monitoring
paw monitor start

# Check status of all campaigns
paw monitor status

# Add new campaign
paw monitor add --case CASE_ID --url https://phish.com

# Force immediate check
paw monitor check

# List all monitored campaigns
paw monitor list

# Stop monitoring
paw monitor stop

# Verify file integrity
paw monitor integrity --case CASE_ID

# Generate geographic report
paw geographic report --case CASE_ID --output report.html

# Show geographic statistics
paw geographic stats --case CASE_ID --min-confidence 0.5
```

### Python API

#### Initialize Monitor

```python
from paw.sentinel.monitor import SentinelMonitor

monitor = SentinelMonitor(
    db_path="sentinel.db",
    config={
        'check_interval': 1800,  # 30 minutes
        'workers': 5,
        'screenshot_enabled': True,
        'alert_email': 'soc@company.com'
    }
)
```

#### Add Campaign

```python
monitor.add_campaign(
    case_id="case-2025-11-08-abc",
    url="https://phishing.example.com/login",
    metadata={
        'priority': 'high',
        'campaign_name': 'PayPal Phish Q4 2025',
        'tags': ['paypal', 'credential-theft']
    }
)
```

#### Query Victim Intelligence

```python
from paw.sentinel.database import get_victim_intelligence

# Get all victims for case
victims = get_victim_intelligence(
    db_path="sentinel.db",
    case_id="case-2025-11-08-abc",
    interaction_type="victim"
)

for victim in victims:
    geo = json.loads(victim['geolocation_data'])
    print(f"{victim['victim_ip']} - {geo['city']}, {geo['country']}")
```

#### Generate Intelligence Report

```python
from paw.sentinel.intelligence_analyzer import generate_intelligence_report

report = generate_intelligence_report(
    db_path="sentinel.db",
    case_id="case-2025-11-08-abc"
)

print(f"Total clicks: {report['statistics']['total_clicks']}")
print(f"Victims: {report['statistics']['victims']}")
print(f"Attackers: {report['statistics']['attackers']}")
print(f"Attacker networks: {report['attacker_networks']}")
```

---

## Configuration

### Sentinel Configuration ([config.py](config.py))

```python
SENTINEL_CONFIG = {
    # Monitoring
    'check_interval': 1800,           # Seconds between checks (30 min)
    'workers': 5,                     # Concurrent workers
    'timeout': 30,                    # HTTP request timeout
    'max_redirects': 10,              # Max redirect chain length

    # Screenshots
    'screenshot_enabled': True,
    'screenshot_width': 1920,
    'screenshot_height': 1080,

    # Alerts
    'alert_enabled': True,
    'alert_email': None,              # Set in .env
    'alert_webhook': None,            # Slack/Discord webhook

    # Intelligence
    'victim_classification_enabled': True,
    'geolocation_provider': 'ip-api',  # or 'ipify'

    # Database
    'db_path': 'sentinel.db',
    'backup_enabled': True,
    'backup_interval': 86400          # Daily backup
}
```

### Environment Variables

```ini
# Sentinel Monitoring
SENTINEL_CHECK_INTERVAL=1800
SENTINEL_WORKERS=5
SENTINEL_SCREENSHOT_ENABLED=true

# Alerts
SENTINEL_ALERT_EMAIL=soc@company.com
SENTINEL_ALERT_WEBHOOK=https://hooks.slack.com/...

# Geolocation
SENTINEL_GEOLOCATION_PROVIDER=ip-api
IPAPI_KEY=your_key_here
```

---

## Workflow Examples

### Example 1: Basic Campaign Monitoring

```bash
# 1. Analyze phishing email
paw analyze phishing.eml

# Output: Created case-2025-11-08T131247Z-abc

# 2. Add to Sentinel monitoring
paw monitor add --case case-2025-11-08T131247Z-abc --url https://phish.com/login

# 3. Start continuous monitoring
paw monitor start

# 4. Check status later
paw monitor status

# Output:
# Campaign: https://phish.com/login
# Status: active
# Last check: 2025-11-08 14:30:00
# HTTP status: 200
# Content hash: 5f7a9b...
# Last change: No changes detected
```

### Example 2: Victim Intelligence Analysis

```bash
# 1. Deploy Canary server (captures victim IPs)
paw canary --case case-2025-11-08-abc --port 8787

# Victims click phishing link -> IPs logged to victim_intelligence table

# 2. Analyze victim intelligence
python -c "
from paw.sentinel.intelligence_analyzer import analyze_victim_intelligence
analyze_victim_intelligence('sentinel.db', 'case-2025-11-08-abc')
"

# 3. Generate geographic report
paw geographic report --case case-2025-11-08-abc --output victim_map.html

# Open victim_map.html in browser
# - See victim locations on world map
# - Identify attacker IPs (red markers)
# - Review country statistics
```

### Example 3: Campaign Correlation

```python
# Find related campaigns based on infrastructure overlap

from paw.sentinel.intelligence_analyzer import correlate_attackers
from paw.sentinel.database import get_campaigns

# Get attacker correlation
correlations = correlate_attackers("sentinel.db")

for correlation in correlations:
    print(f"Attacker network: {correlation['network']}")
    print(f"Related cases: {correlation['cases']}")
    print(f"Shared IPs: {correlation['shared_ips']}")
```

### Example 4: Evidence Integrity Verification

```bash
# After case analysis, create baseline
paw monitor integrity --case case-2025-11-08-abc --create-baseline

# Days later, verify integrity before sharing evidence
paw monitor integrity --case case-2025-11-08-abc --verify

# Output:
# ✓ Merkle root match
# ✓ No modified files
# ✓ No deleted files
# ✗ New files detected: [temp/screenshot_new.png]
```

---

## API Reference

### SentinelMonitor Class

```python
class SentinelMonitor:
    def __init__(self, db_path="sentinel.db", config=None)

    def add_campaign(self, case_id, url, metadata=None)
    def remove_campaign(self, campaign_id)
    def get_campaign(self, campaign_id)
    def list_campaigns(self, status=None)

    def check_campaign(self, campaign_id)
    def check_all_campaigns(self)

    def start_monitoring(self, interval=1800)
    def stop_monitoring(self)

    def get_alerts(self, campaign_id=None, acknowledged=False)
    def acknowledge_alert(self, alert_id)
```

### Database Functions

```python
# Campaign management
add_campaign(db_path, case_id, url, domain=None)
remove_campaign(db_path, campaign_id)
get_campaign(db_path, campaign_id)
get_campaigns(db_path, status=None)

# Check recording
record_check(db_path, campaign_id, status, http_status, content_hash, ...)

# Alert management
create_alert(db_path, campaign_id, alert_type, message, severity="medium")
get_alerts(db_path, campaign_id=None, acknowledged=False)
acknowledge_alert(db_path, alert_id)

# Victim intelligence
add_victim_intelligence(db_path, victim_ip, phishing_url, case_id, **kwargs)
get_victim_intelligence(db_path, case_id=None, interaction_type=None)
update_victim_classification(db_path, record_id, interaction_type, confidence, risk_score)
```

### IP Analyzer Functions

```python
geolocate_ip(ip_address)
whois_lookup(ip_address)
reverse_dns(ip_address)
analyze_ip(ip_address)
```

### Intelligence Analyzer Functions

```python
classify_interaction(ip_analysis, click_patterns, case_context)
analyze_victim_intelligence(db_path, case_id=None)
correlate_attackers(db_path)
identify_attacker_networks(db_path, case_id)
generate_intelligence_report(db_path, case_id)
```

### Geographic Reports Functions

```python
generate_geographic_report(db_path, case_id, output_path="report.html")
generate_statistics(db_path, case_id=None)
```

### File Monitor Functions

```python
create_baseline(case_path)
verify_integrity(case_path)
```

---

## Performance Considerations

### Database Indexing

For optimal performance with large victim_intelligence tables:

```sql
CREATE INDEX idx_victim_ip ON victim_intelligence(victim_ip);
CREATE INDEX idx_case_id ON victim_intelligence(case_id);
CREATE INDEX idx_interaction_type ON victim_intelligence(interaction_type);
CREATE INDEX idx_click_time ON victim_intelligence(click_time);
```

### Concurrent Monitoring

Adjust worker count based on number of campaigns:

```python
# For 10-50 campaigns
monitor = SentinelMonitor(config={'workers': 5})

# For 50-200 campaigns
monitor = SentinelMonitor(config={'workers': 10})

# For 200+ campaigns
monitor = SentinelMonitor(config={'workers': 20})
```

### Screenshot Storage

Screenshots can consume significant disk space. Consider:

- Limiting screenshot retention (keep last 7 days)
- Compressing old screenshots
- Disabling screenshots for low-priority campaigns

```python
# Disable screenshots for specific campaign
monitor.add_campaign(
    case_id="...",
    url="...",
    metadata={'screenshot_enabled': False}
)
```

---

## Security Notes

1. **Database Encryption**: Sentinel DB contains sensitive IP data. Consider encrypting:
   ```bash
   # Use SQLCipher for encrypted database
   pip install sqlcipher3
   ```

2. **API Rate Limits**: Geolocation APIs have rate limits. Cache results in `enrichment_results` table.

3. **Privacy**: Victim IP addresses are PII. Follow GDPR/privacy regulations:
   - Anonymize IPs after analysis
   - Implement data retention policy
   - Provide opt-out mechanism

4. **Access Control**: Restrict database access to authorized personnel only.

---

## Troubleshooting

### Issue: Monitoring checks fail with timeout

```python
# Increase timeout in config
monitor = SentinelMonitor(config={'timeout': 60})
```

### Issue: Geolocation API rate limit exceeded

```python
# Check enrichment cache first
from paw.sentinel.database import get_enrichment_result

cached = get_enrichment_result(db_path, case_id, domain)
if cached:
    use_cached_data(cached)
else:
    fetch_new_data()
```

### Issue: Screenshot capture fails

```bash
# Ensure Playwright browsers are installed
playwright install

# Or disable screenshots
export SENTINEL_SCREENSHOT_ENABLED=false
```

---

## Future Enhancements

Planned features for Sentinel v3.0:

- [ ] Machine learning-based victim classification
- [ ] Automated attacker infrastructure mapping
- [ ] Integration with threat intel platforms (MISP, OpenCTI)
- [ ] Webhook alerts (Slack, Discord, PagerDuty)
- [ ] Multi-language geographic reports
- [ ] Historical campaign analytics dashboard
- [ ] Automated takedown request generation

---

**Sentinel** - Continuous visibility into phishing campaign evolution.

For main PAW documentation, see [../../README.md](../../README.md)
