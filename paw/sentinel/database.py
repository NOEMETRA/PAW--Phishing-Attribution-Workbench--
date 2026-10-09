# paw/sentinel/database.py
"""
Database management for Sentinel monitoring campaigns.
"""
import sqlite3
from contextlib import contextmanager, closing
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from ..util.fsutil import ensure_dir
from ..util.timeutil import utc_now_iso


class CampaignDatabase:
    """SQLite database for managing monitored phishing campaigns."""

    def __init__(self, db_path: str = "sentinel.db"):
        self.db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:  # Only create directory if there's a directory path
            ensure_dir(db_dir)
        self._init_db()

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                yield conn

    def _init_db(self) -> None:
        """Initialize database tables."""
        with self.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_check TEXT,
                    status TEXT DEFAULT 'active',
                    url TEXT NOT NULL,
                    domain TEXT,
                    title TEXT,
                    description TEXT,
                    risk_level TEXT DEFAULT 'unknown',
                    metadata TEXT,  -- JSON metadata
                    UNIQUE(case_id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    check_time TEXT NOT NULL,
                    status TEXT NOT NULL,  -- 'up', 'down', 'error'
                    response_time REAL,
                    http_status INTEGER,
                    content_hash TEXT,
                    screenshot_path TEXT,
                    error_message TEXT,
                    metadata TEXT,  -- JSON additional data
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    alert_time TEXT NOT NULL,
                    alert_type TEXT NOT NULL,  -- 'down', 'up', 'changed', 'error'
                    severity TEXT DEFAULT 'info',
                    message TEXT NOT NULL,
                    metadata TEXT,  -- JSON alert details
                    acknowledged INTEGER DEFAULT 0,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
                )
            """)

            # VICTIM INTELLIGENCE TABLE - Revolutionary feature for attacker localization
            conn.execute("""
                CREATE TABLE IF NOT EXISTS victim_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_ip TEXT NOT NULL,
                    victim_ua TEXT,  -- User Agent string
                    click_time TEXT NOT NULL,
                    phishing_url TEXT NOT NULL,
                    case_id TEXT,  -- Link to PAW case
                    attacker_correlation TEXT,  -- JSON: correlated attacker IPs/servers
                    risk_score INTEGER DEFAULT 0,  -- 1-10 risk score
                    analyzed_status TEXT DEFAULT 'captured',  -- 'captured', 'analyzing', 'analyzed'
                    geolocation_data TEXT,  -- JSON: country, city, ISP
                    whois_data TEXT,  -- JSON: WHOIS lookup results
                    related_ips TEXT,  -- JSON: correlated IPs from same attack
                    interaction_type TEXT DEFAULT 'unknown',  -- 'victim', 'attacker', 'suspicious'
                    interaction_confidence REAL DEFAULT 0.0,  -- 0.0-1.0 confidence score
                    interaction_indicators TEXT,  -- JSON: indicators that led to classification
                    metadata TEXT,  -- JSON: additional analysis data
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Migrate existing databases to add new columns
            self._migrate_database(conn)
            conn.commit()

    def _migrate_database(self, conn: sqlite3.Connection) -> None:
        """Migrate database schema to add new columns if they don't exist."""
        # Check if interaction_type column exists, if not add the new columns
        cursor = conn.execute("PRAGMA table_info(victim_intelligence)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'interaction_type' not in columns:
            conn.execute("ALTER TABLE victim_intelligence ADD COLUMN interaction_type TEXT DEFAULT 'unknown'")
        if 'interaction_confidence' not in columns:
            conn.execute("ALTER TABLE victim_intelligence ADD COLUMN interaction_confidence REAL DEFAULT 0.0")
        if 'interaction_indicators' not in columns:
            conn.execute("ALTER TABLE victim_intelligence ADD COLUMN interaction_indicators TEXT")

    def _safe_load_json(self, s: str, default):
        """Safely load JSON from a string field; return default on failure or empty input."""
        try:
            if not s:
                return default
            return json.loads(s)
        except Exception:
            return default

    def add_campaign(self, case_id: str, url: str, metadata: Dict[str, Any] = None) -> str:
        """Add a new campaign to monitor."""
        campaign_id = f"sentinel_{case_id}_{int(datetime.now().timestamp())}"

        with self.connection() as conn:
            conn.execute("""
                INSERT INTO campaigns (id, case_id, created_at, url, domain, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                campaign_id,
                case_id,
                utc_now_iso(),
                url,
                self._extract_domain(url),
                json.dumps(metadata or {})
            ))
            conn.commit()

        return campaign_id

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get campaign details by ID."""
        with self.connection() as conn:
            row = conn.execute("""
                SELECT * FROM campaigns WHERE id = ?
            """, (campaign_id,)).fetchone()

            if row:
                return {
                    'id': row[0],
                    'case_id': row[1],
                    'created_at': row[2],
                    'last_check': row[3],
                    'status': row[4],
                    'url': row[5],
                    'domain': row[6],
                    'title': row[7],
                    'description': row[8],
                    'risk_level': row[9],
                    'metadata': self._safe_load_json(row[10], {})
                }
        return None

    def get_active_campaigns(self) -> List[Dict[str, Any]]:
        """Get all active campaigns."""
        campaigns = []
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT * FROM campaigns WHERE status = 'active'
            """).fetchall()

            for row in rows:
                campaigns.append({
                    'id': row[0],
                    'case_id': row[1],
                    'created_at': row[2],
                    'last_check': row[3],
                    'status': row[4],
                    'url': row[5],
                    'domain': row[6],
                    'title': row[7],
                    'description': row[8],
                    'risk_level': row[9],
                    'metadata': self._safe_load_json(row[10], {})
                })
        return campaigns

    def update_campaign_status(self, campaign_id: str, status: str) -> None:
        """Update campaign status."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE campaigns SET status = ? WHERE id = ?
            """, (status, campaign_id))
            conn.commit()

    def record_check(self, campaign_id: str, status: str, response_time: float = None,
                    http_status: int = None, content_hash: str = None,
                    screenshot_path: str = None, error_message: str = None,
                    metadata: Dict[str, Any] = None) -> None:
        """Record a monitoring check result."""
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO checks (campaign_id, check_time, status, response_time,
                                  http_status, content_hash, screenshot_path,
                                  error_message, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign_id,
                utc_now_iso(),
                status,
                response_time,
                http_status,
                content_hash,
                screenshot_path,
                error_message,
                json.dumps(metadata or {})
            ))

            # Update last_check timestamp
            conn.execute("""
                UPDATE campaigns SET last_check = ? WHERE id = ?
            """, (utc_now_iso(), campaign_id))

            conn.commit()

    def record_alert(self, campaign_id: str, alert_type: str, message: str,
                    severity: str = "info", metadata: Dict[str, Any] = None) -> None:
        """Record an alert."""
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO alerts (campaign_id, alert_time, alert_type, severity,
                                  message, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                campaign_id,
                utc_now_iso(),
                alert_type,
                severity,
                message,
                json.dumps(metadata or {})
            ))
            conn.commit()

    def get_recent_checks(self, campaign_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent checks for a campaign."""
        checks = []
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT * FROM checks WHERE campaign_id = ?
                ORDER BY check_time DESC LIMIT ?
            """, (campaign_id, limit)).fetchall()

            for row in rows:
                checks.append({
                    'id': row[0],
                    'campaign_id': row[1],
                    'check_time': row[2],
                    'status': row[3],
                    'response_time': row[4],
                    'http_status': row[5],
                    'content_hash': row[6],
                    'screenshot_path': row[7],
                    'error_message': row[8],
                    'metadata': self._safe_load_json(row[9], {})
                })
        return checks

    def get_unacknowledged_alerts(self) -> List[Dict[str, Any]]:
        """Get unacknowledged alerts."""
        alerts = []
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT * FROM alerts WHERE acknowledged = 0
                ORDER BY alert_time DESC
            """).fetchall()

            for row in rows:
                alerts.append({
                    'id': row[0],
                    'campaign_id': row[1],
                    'alert_time': row[2],
                    'alert_type': row[3],
                    'severity': row[4],
                    'message': row[5],
                    'metadata': json.loads(row[6]) if row[6] else {},
                    'acknowledged': bool(row[7])
                })
        return alerts

    def acknowledge_alert(self, alert_id: int) -> None:
        """Mark an alert as acknowledged."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE alerts SET acknowledged = 1 WHERE id = ?
            """, (alert_id,))
            conn.commit()

    def cleanup_old_data(self, retention_days: int = 90) -> None:
        """Clean up old check data and screenshots."""
        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()

        with self.connection() as conn:
            # Delete old checks
            conn.execute("""
                DELETE FROM checks WHERE check_time < ?
            """, (cutoff_date,))

            # Delete old alerts
            conn.execute("""
                DELETE FROM alerts WHERE alert_time < ?
            """, (cutoff_date,))

            conn.commit()

    # ===== VICTIM INTELLIGENCE METHODS =====

    def add_victim_intelligence(self, victim_ip: str, victim_ua: str, phishing_url: str,
                               case_id: str = None, metadata: Dict[str, Any] = None) -> int:
        """Add victim intelligence data when a phishing click is detected."""
        with self.connection() as conn:
            cursor = conn.execute("""
                INSERT INTO victim_intelligence
                (victim_ip, victim_ua, click_time, phishing_url, case_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                victim_ip,
                victim_ua,
                utc_now_iso(),
                phishing_url,
                case_id,
                json.dumps(metadata or {})
            ))
            victim_id = cursor.lastrowid
            conn.commit()
            return victim_id

    def get_victim_intelligence(self, victim_id: int = None, victim_ip: str = None) -> List[Dict[str, Any]]:
        """Get victim intelligence data."""
        with self.connection() as conn:
            if victim_id:
                rows = conn.execute("""
                    SELECT * FROM victim_intelligence WHERE id = ?
                """, (victim_id,)).fetchall()
            elif victim_ip:
                rows = conn.execute("""
                    SELECT * FROM victim_intelligence WHERE victim_ip = ?
                    ORDER BY click_time DESC
                """, (victim_ip,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM victim_intelligence
                    ORDER BY click_time DESC
                    LIMIT 100
                """).fetchall()

            victims = []
            for row in rows:
                victims.append({
                    'id': row[0],
                    'victim_ip': row[1],
                    'victim_ua': row[2],
                    'click_time': row[3],
                    'phishing_url': row[4],
                    'case_id': row[5],
                    'attacker_correlation': self._safe_load_json(row[6], {}),
                    'risk_score': row[7],
                    'analyzed_status': row[8],
                    'geolocation_data': self._safe_load_json(row[9], {}),
                    'whois_data': self._safe_load_json(row[10], {}),
                    'related_ips': self._safe_load_json(row[11], []),
                    'interaction_type': row[12],
                    'interaction_confidence': row[13],
                    'interaction_indicators': self._safe_load_json(row[14], []),
                    'metadata': self._safe_load_json(row[15], {}),
                    'created_at': row[16],
                    'updated_at': row[17]
                })
            return victims

    def get_unanalyzed_victims(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get victims that haven't been fully analyzed yet."""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT * FROM victim_intelligence
                WHERE analyzed_status IN ('captured', 'analyzing')
                ORDER BY click_time DESC
                LIMIT ?
            """, (limit,)).fetchall()

            victims = []
            for row in rows:
                victims.append({
                    'id': row[0],
                    'victim_ip': row[1],
                    'victim_ua': row[2],
                    'click_time': row[3],
                    'phishing_url': row[4],
                    'case_id': row[5],
                    'attacker_correlation': self._safe_load_json(row[6], {}),
                    'risk_score': row[7],
                    'analyzed_status': row[8],
                    'geolocation_data': self._safe_load_json(row[9], {}),
                    'whois_data': self._safe_load_json(row[10], {}),
                    'related_ips': self._safe_load_json(row[11], []),
                    'metadata': self._safe_load_json(row[12], {}),
                    'created_at': row[13],
                    'updated_at': row[14]
                })
            return victims

    def get_victim_statistics(self) -> Dict[str, Any]:
        """Get statistics about victim intelligence data."""
        with self.connection() as conn:
            # Total victims
            total_victims = conn.execute("""
                SELECT COUNT(*) FROM victim_intelligence
            """).fetchone()[0]

            # Status breakdown
            status_stats = conn.execute("""
                SELECT analyzed_status, COUNT(*) as count
                FROM victim_intelligence
                GROUP BY analyzed_status
            """).fetchall()

            # Risk score distribution
            risk_stats = conn.execute("""
                SELECT risk_score, COUNT(*) as count
                FROM victim_intelligence
                WHERE risk_score > 0
                GROUP BY risk_score
                ORDER BY risk_score
            """).fetchall()

            # Recent activity (last 24 hours)
            recent_victims = conn.execute("""
                SELECT COUNT(*) FROM victim_intelligence
                WHERE click_time > datetime('now', '-1 day')
            """).fetchone()[0]

            return {
                'total_victims': total_victims,
                'status_breakdown': dict(status_stats),
                'risk_distribution': dict(risk_stats),
                'recent_victims_24h': recent_victims
            }

    def update_victim_analysis(self, victim_id: int, geolocation_data: Dict = None,
                              whois_data: Dict = None, attacker_correlation: Dict = None,
                              risk_score: int = None, analyzed_status: str = None,
                              related_ips: List[str] = None, interaction_type: str = None,
                              interaction_confidence: float = None, interaction_indicators: List[str] = None) -> bool:
        """Update victim intelligence analysis results."""
        updates = []
        params = []

        if geolocation_data is not None:
            updates.append("geolocation_data = ?")
            params.append(json.dumps(geolocation_data))

        if whois_data is not None:
            updates.append("whois_data = ?")
            params.append(json.dumps(whois_data))

        if attacker_correlation is not None:
            updates.append("attacker_correlation = ?")
            params.append(json.dumps(attacker_correlation))

        if risk_score is not None:
            updates.append("risk_score = ?")
            params.append(risk_score)

        if analyzed_status is not None:
            updates.append("analyzed_status = ?")
            params.append(analyzed_status)

        if related_ips is not None:
            updates.append("related_ips = ?")
            params.append(json.dumps(related_ips))

        if interaction_type is not None:
            updates.append("interaction_type = ?")
            params.append(interaction_type)

        if interaction_confidence is not None:
            updates.append("interaction_confidence = ?")
            params.append(interaction_confidence)

        if interaction_indicators is not None:
            updates.append("interaction_indicators = ?")
            params.append(json.dumps(interaction_indicators))

        if not updates:
            return False

        updates.append("updated_at = ?")
        params.append(utc_now_iso())

        query = f"""
            UPDATE victim_intelligence
            SET {', '.join(updates)}
            WHERE id = ?
        """
        params.append(victim_id)

        with self.connection() as conn:
            conn.execute(query, params)
            conn.commit()

        return True

    def calculate_risk_score(self, risk_indicators: List[str], geolocation: Dict[str, Any], whois: Dict[str, Any]) -> int:
        """Calculate risk score from 1-10 based on analysis data."""
        score = 1  # Base score

        # Risk indicators add points
        indicator_weights = {
            'High-risk country': 3,
            'Recently registered domain': 2,
            'Relatively new domain': 1,
            'Known bulletproof hosting': 4,
            'Private IP address': -2,  # Unusual but not necessarily malicious
            'No reverse DNS': 1
        }

        for indicator in risk_indicators:
            for pattern, weight in indicator_weights.items():
                if pattern in indicator:
                    score += weight
                    break

        # Cap at 10
        return min(max(score, 1), 10)

    def get_victims_by_risk_score(self, min_score: int = 5) -> List[Dict[str, Any]]:
        """Get victims with risk score above threshold."""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT * FROM victim_intelligence
                WHERE risk_score >= ?
                ORDER BY risk_score DESC, click_time DESC
            """, (min_score,)).fetchall()

            return [self._victim_row_to_dict(row) for row in rows]

    def get_victims_by_country(self, country: str) -> List[Dict[str, Any]]:
        """Get victims from specific country."""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT * FROM victim_intelligence
                WHERE json_extract(geolocation_data, '$.country') = ?
                ORDER BY click_time DESC
            """, (country,)).fetchall()

            return [self._victim_row_to_dict(row) for row in rows]

    def get_attacker_correlations(self) -> List[Dict[str, Any]]:
        """Get potential attacker infrastructure correlations."""
        with self.connection() as conn:
            # Find networks with multiple victims
            rows = conn.execute("""
                SELECT
                    substr(victim_ip, 1, instr(victim_ip, '.') + instr(substr(victim_ip, instr(victim_ip, '.') + 1), '.') + instr(substr(victim_ip, instr(victim_ip, '.') + instr(substr(victim_ip, instr(victim_ip, '.') + 1), '.') + 1), '.') - 1) as network,
                    COUNT(*) as victim_count,
                    GROUP_CONCAT(victim_ip) as victim_ips,
                    GROUP_CONCAT(DISTINCT json_extract(geolocation_data, '$.country')) as countries,
                    AVG(risk_score) as avg_risk
                FROM victim_intelligence
                WHERE analyzed_status = 'analyzed'
                GROUP BY network
                HAVING victim_count >= 3
                ORDER BY victim_count DESC, avg_risk DESC
            """).fetchall()

            correlations = []
            for row in rows:
                network, victim_count, victim_ips, countries, avg_risk = row
                correlations.append({
                    'network': network,
                    'victim_count': victim_count,
                    'victim_ips': victim_ips.split(','),
                    'countries': countries.split(',') if countries else [],
                    'avg_risk_score': round(avg_risk, 1) if avg_risk else 0,
                    'potential_attacker_infrastructure': victim_count >= 5
                })

            return correlations

    def _victim_row_to_dict(self, row) -> Dict[str, Any]:
        """Convert victim intelligence row to dictionary."""
        columns = ['id', 'victim_ip', 'victim_ua', 'click_time', 'phishing_url',
                  'case_id', 'attacker_correlation', 'risk_score', 'analyzed_status',
                  'geolocation_data', 'whois_data', 'related_ips', 'metadata',
                  'created_at', 'updated_at', 'interaction_type', 'interaction_confidence', 'interaction_indicators']

        victim = dict(zip(columns, row))

        # Parse JSON fields
        for json_field in ['geolocation_data', 'whois_data', 'related_ips', 'metadata', 'attacker_correlation', 'interaction_indicators']:
            if victim[json_field]:
                try:
                    victim[json_field] = json.loads(victim[json_field])
                except:
                    victim[json_field] = {}

        return victim

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url
