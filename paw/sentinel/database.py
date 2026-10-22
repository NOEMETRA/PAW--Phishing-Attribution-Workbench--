# paw/sentinel/database.py
"""
Database management for Sentinel monitoring campaigns.
"""
import sqlite3
import base64
from contextlib import contextmanager, closing
import json
import math
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from ..util.timeutil import utc_now_iso
from .config import _storage_path, _admit_storage_path, _storage_identity, _storage_opener


class _StoredJSONError(ValueError):
    """A syntactically accepted value is ambiguous or non-finite."""


class _InvalidUTF8Text(bytes):
    """Undecodable SQLite TEXT, distinct from a stored BLOB."""


class CampaignDatabase:
    """SQLite database for managing monitored phishing campaigns."""

    def __init__(self, db_path: str = "sentinel.db", *, read_only: bool = False):
        path = _storage_path(db_path)
        self.db_path = str(path)
        self.read_only = read_only
        metadata = _admit_storage_path(path, must_exist=read_only, directory_as_missing=read_only)
        created = metadata is None
        if created:
            path.parent.mkdir(parents=True, exist_ok=True)
            _admit_storage_path(path)
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try: created_identity = _storage_identity(os.fstat(descriptor))
            finally: os.close(descriptor)
            metadata = _admit_storage_path(path, must_exist=True)
            if _storage_identity(metadata) != created_identity:
                raise ValueError('New Sentinel database source replaced before initialization')
        self._source_identity = _storage_identity(metadata)
        if read_only:
            # Admit existing saved storage without CREATE TABLE or migrations.
            with self.connection() as conn:
                conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
            return
        # Construction must not recover or checkpoint a foreign saved source.
        # Failed creation leaves its target for inspection: another initializer
        # can acquire the same file after rollback, so unlink is not safe here.
        self._require_stopped_storage()
        self._init_db()

    def _admit_database(self):
        metadata = _admit_storage_path(Path(self.db_path), must_exist=True)
        if _storage_identity(metadata) != self._source_identity:
            raise ValueError('Sentinel database source replaced; reopen explicitly')
        return metadata

    @contextmanager
    def connection(self):
        self._admit_database()
        target = self._read_only_uri() if self.read_only else Path(self.db_path).as_uri() + '?mode=rw'
        with closing(sqlite3.connect(target, uri=True)) as conn:
            self._admit_database()
            if self.read_only:
                conn.execute("PRAGMA query_only = ON")
            with conn:
                yield conn

    def _require_stopped_storage(self):
        """Admit a saved rollback-journal database, without creating sidecars."""
        database = Path(self.db_path)
        self._admit_database()
        # SQLite read-only WAL opening may create/update shared-memory sidecars.
        # Do not ignore a WAL or recover a pending journal to display stale data.
        with open(database, 'rb', opener=_storage_opener) as source:
            if _storage_identity(os.fstat(source.fileno())) != self._source_identity:
                raise ValueError('Sentinel database source changed before admission')
            header = source.read(20)
        sidecars = False
        for suffix in ('-wal', '-shm', '-journal'):
            try: Path(str(database) + suffix).lstat()
            except FileNotFoundError: continue
            sidecars = True
        if (header.startswith(b'SQLite format 3\x00') and 2 in header[18:20]) or sidecars:
            raise ValueError("Sentinel passive opening requires a stopped database without WAL/journal sidecars")

    def _read_only_uri(self) -> str:
        self._require_stopped_storage()
        return Path(self.db_path).as_uri() + '?mode=ro'

    @contextmanager
    def _json_read_connection(self):
        """Defer invalid JSON TEXT decoding while keeping other TEXT strict."""
        json_columns = {'metadata', 'attacker_correlation', 'geolocation_data',
                        'whois_data', 'related_ips', 'interaction_indicators'}

        def decode_text(raw):
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return _InvalidUTF8Text(raw)

        def named_row(cursor, values):
            for column, value in zip(cursor.description, values):
                if isinstance(value, _InvalidUTF8Text) and column[0] not in json_columns:
                    raise sqlite3.OperationalError(
                        f"Could not decode to UTF-8 column '{column[0]}'")
            return sqlite3.Row(cursor, values)

        with self.connection() as conn:
            conn.text_factory = decode_text
            conn.row_factory = named_row
            yield conn

    def _init_db(self) -> None:
        """Initialize database tables."""
        with self.connection() as conn:
            # Legacy sqlite3 transaction control does not begin on CREATE/ALTER.
            conn.execute('BEGIN IMMEDIATE')
            objects = conn.execute("SELECT name, type FROM sqlite_master WHERE name IN "
                                   "('campaigns','checks','alerts','victim_intelligence')").fetchall()
            if any(kind != 'table' for name, kind in objects):
                raise sqlite3.DatabaseError('Sentinel schema requires tables for its named storage objects')
            if not objects and conn.execute("SELECT 1 FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' LIMIT 1").fetchone():
                raise sqlite3.DatabaseError('Existing database has no recognized Sentinel storage objects')
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

    def _decode_record_json(self, record: Dict[str, Any], defaults: Dict[str, Any], missing=()):
        """Keep typed stored source and decode outcome beside compatibility values."""
        fields = {}
        for field, default in defaults.items():
            if field in missing:
                record[field] = None
                fields[field] = {'status': 'missing_column', 'raw_storage': None,
                                 'default_applied': False, 'verified': False}
            else:
                record[field], fields[field] = self._decode_json_field(record[field], default)
        record['json_evidence'] = {'schema_version': 1, 'fields': fields}
        return record

    def _decode_json_field(self, raw, default):
        if raw is None:
            source = {'type': 'null', 'value': None}
        elif isinstance(raw, _InvalidUTF8Text):
            source = {'type': 'text', 'encoding': 'base64',
                      'value': base64.b64encode(raw).decode('ascii')}
        elif isinstance(raw, str):
            source = {'type': 'text', 'value': raw}
        elif isinstance(raw, bytes):
            source = {'type': 'blob', 'encoding': 'base64',
                      'value': base64.b64encode(raw).decode('ascii')}
        elif isinstance(raw, int):
            source = {'type': 'integer', 'value': raw}
        else:  # SQLite's remaining scalar storage type is REAL.
            source = {'type': 'real', 'encoding': 'float_hex', 'value': raw.hex()}
        evidence = {'status': 'decoded', 'raw_storage': source,
                    'default_applied': False, 'verified': False}

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise _StoredJSONError('duplicate_keys')
                result[key] = value
            return result

        def reject_constant(value):
            raise _StoredJSONError('non_finite_number')

        def finite_float(value):
            parsed = float(value)
            if not math.isfinite(parsed):
                raise _StoredJSONError('non_finite_number')
            return parsed

        try:
            if isinstance(raw, _InvalidUTF8Text):
                status = 'invalid_encoding'
            elif raw is None:
                status = 'sql_null'
            elif raw == '' or raw == b'':
                status = 'empty'
            elif not isinstance(raw, (str, bytes)):
                status = 'unsupported_storage_type'
            else:
                return json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=reject_constant, parse_float=finite_float), evidence
        except _StoredJSONError as error:
            status = str(error)
        except json.JSONDecodeError:
            status = 'invalid_json'
        except UnicodeDecodeError:
            status = 'invalid_encoding'
        except (ValueError, RecursionError):
            status = 'decode_error'
        evidence.update(status=status, default_applied=True)
        return default, evidence

    def add_campaign(self, case_id: str, url: str, metadata: Dict[str, Any] = None) -> str:
        """Store one literal campaign per case, without authorizing collection."""
        if not isinstance(case_id, str) or not case_id.strip() or not isinstance(url, str) or not url.strip():
            raise ValueError("case_id and url must be nonblank strings")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("Campaign metadata must be an object or None")
        encoded_metadata = json.dumps({} if metadata is None else metadata, allow_nan=False)
        domain = self._extract_domain(url)
        campaign_id = f"sentinel_{case_id}_{int(datetime.now().timestamp())}"

        with self.connection() as conn:
            # Also protect legacy tables without today's UNIQUE(case_id).
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM campaigns WHERE case_id=? LIMIT 1", (case_id,)).fetchone():
                raise ValueError(f"Campaign already exists for case: {case_id}")
            conn.execute("""
                INSERT INTO campaigns (id, case_id, created_at, url, domain, metadata, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
            """, (
                campaign_id,
                case_id,
                utc_now_iso(),
                url,
                domain,
                encoded_metadata
            ))
            conn.commit()

        return campaign_id

    def remove_campaign(self, campaign_id: str, *, case_id: str = None) -> bool:
        """Acknowledge exactly one active-to-removed transition in one transaction."""
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if case_id is None:
                rows = conn.execute("SELECT id FROM campaigns WHERE id=? AND status='active'",
                                    (campaign_id,)).fetchall()
            else:
                rows = conn.execute("SELECT id FROM campaigns WHERE case_id=? AND status='active'",
                                    (case_id,)).fetchall()
            if len(rows) > 1:
                raise ValueError("Multiple active campaigns; no campaign removed")
            if not rows or rows[0][0] != campaign_id:
                return False
            query = "UPDATE campaigns SET status='removed' WHERE id=? AND status='active'"
            values = (campaign_id,)
            if case_id is not None:
                query += " AND case_id=?"
                values += (case_id,)
            if conn.execute(query, values).rowcount != 1:
                raise RuntimeError("Campaign changed before removal; no active campaign removed")
            final_query = "SELECT status FROM campaigns WHERE id=?"
            if case_id is not None:
                final_query += " AND case_id=?"
            if conn.execute(final_query, values).fetchall() != [('removed',)]:
                raise RuntimeError("Campaign removal did not persist; transaction rolled back")
            return True

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get campaign details by ID."""
        with self._json_read_connection() as conn:
            row = conn.execute("""
                SELECT id, case_id, created_at, last_check, status, url,
                       domain, title, description, risk_level, metadata
                FROM campaigns WHERE id = ?
            """, (campaign_id,)).fetchone()

            if row:
                return self._decode_record_json({
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
                    'metadata': row[10]
                }, {'metadata': {}})
        return None

    def get_active_campaigns(self) -> List[Dict[str, Any]]:
        """Get all active campaigns."""
        campaigns = []
        with self._json_read_connection() as conn:
            rows = conn.execute("""
                SELECT id, case_id, created_at, last_check, status, url,
                       domain, title, description, risk_level, metadata
                FROM campaigns WHERE status = 'active'
            """).fetchall()

            for row in rows:
                campaigns.append(self._decode_record_json({
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
                    'metadata': row[10]
                }, {'metadata': {}}))
        return campaigns

    def get_monitor_statistics(self) -> Dict[str, int]:
        """Count stored campaigns and unacknowledged alerts in one read snapshot."""
        with self.connection() as conn:
            row = conn.execute("""
                SELECT COUNT(*), COUNT(CASE WHEN status = 'active' THEN 1 END),
                    (SELECT COUNT(*) FROM alerts WHERE acknowledged = 0)
                FROM campaigns
            """).fetchone()
        return {'total_campaigns': row[0], 'active_campaigns': row[1],
                'unacknowledged_alerts': row[2]}

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
        with self._json_read_connection() as conn:
            rows = conn.execute("""
                SELECT id, campaign_id, check_time, status, response_time, http_status,
                       content_hash, screenshot_path, error_message, metadata
                FROM checks WHERE campaign_id = ?
                ORDER BY check_time DESC LIMIT ?
            """, (campaign_id, limit)).fetchall()

            for row in rows:
                checks.append(self._decode_record_json({
                    'id': row[0],
                    'campaign_id': row[1],
                    'check_time': row[2],
                    'status': row[3],
                    'response_time': row[4],
                    'http_status': row[5],
                    'content_hash': row[6],
                    'screenshot_path': row[7],
                    'error_message': row[8],
                    'metadata': row[9]
                }, {'metadata': {}}))
        return checks

    def get_unacknowledged_alerts(self) -> List[Dict[str, Any]]:
        """Get unacknowledged alerts."""
        alerts = []
        with self._json_read_connection() as conn:
            rows = conn.execute("""
                SELECT id, campaign_id, alert_time, alert_type, severity, message,
                       metadata, acknowledged
                FROM alerts WHERE acknowledged = 0
                ORDER BY alert_time DESC
            """).fetchall()

            for row in rows:
                alerts.append(self._decode_record_json({
                    'id': row[0],
                    'campaign_id': row[1],
                    'alert_time': row[2],
                    'alert_type': row[3],
                    'severity': row[4],
                    'message': row[5],
                    'metadata': row[6],
                    'acknowledged': bool(row[7])
                }, {'metadata': {}}))
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
        with self._json_read_connection() as conn:
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

            return [self._victim_row_to_dict(row) for row in rows]

    def get_forensic_victim_intelligence(self, case_id: str = None) -> List[Dict[str, Any]]:
        """Read every selected stored row without the interactive listing cap."""
        if case_id is not None and not isinstance(case_id, str):
            raise TypeError('case_id must be a string or None')
        with self._json_read_connection() as conn:
            query = 'SELECT * FROM victim_intelligence'
            params = ()
            if case_id is not None:
                query += ' WHERE case_id COLLATE BINARY = ?'
                params = (case_id,)
            query += ' ORDER BY click_time DESC, id DESC'
            rows = conn.execute(query, params).fetchall()
            return [self._victim_row_to_dict(row) for row in rows]

    def get_unanalyzed_victims(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get victims that haven't been fully analyzed yet."""
        with self._json_read_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM victim_intelligence
                WHERE analyzed_status IN ('captured', 'analyzing')
                ORDER BY click_time DESC
                LIMIT ?
            """, (limit,)).fetchall()

            return [self._victim_row_to_dict(row) for row in rows]

    @staticmethod
    def _finite_stored_number(value):
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and (isinstance(value, int) or math.isfinite(value)))

    def get_victim_statistics(self) -> Dict[str, Any]:
        """Complete stored-row descriptions, without inferred risk or recency."""
        records = self.get_forensic_victim_intelligence()
        json.dumps(records, allow_nan=False)
        status_ids, risk_ids, unusable_statuses, unusable_scores, nonpositive = {}, {}, [], [], []
        for record in records:
            identifier, status, score = record['id'], record['analyzed_status'], record['risk_score']
            if isinstance(status, str):
                status_ids.setdefault(status, []).append(identifier)
            else:
                unusable_statuses.append(identifier)
            if not self._finite_stored_number(score):
                unusable_scores.append(identifier)
            elif score > 0:
                risk_ids.setdefault(str(score), []).append(identifier)
            else:
                nonpositive.append(identifier)
        return {
            'schema_version': 1, 'status': 'success', 'evidence_scope': 'stored_rows_unverified',
            'source_records': records, 'total_victims': len(records),
            'status_breakdown': {key: len(ids) for key, ids in status_ids.items()},
            'risk_distribution': {key: len(ids) for key, ids in risk_ids.items()},
            'aggregation_evidence': {
                'status_breakdown': {'source_field': 'analyzed_status',
                    'source_ids': status_ids, 'unusable_ids': unusable_statuses},
                'risk_distribution': {'source_field': 'risk_score', 'source_ids': risk_ids,
                    'unusable_ids': unusable_scores, 'nonpositive_ids': nonpositive,
                    'scope': 'Finite positive stored numbers, not calibrated risk.'}},
            'recent_victims_24h': None,
            'unavailable': {'recent_victims_24h': 'No validated timestamp interpretation is defined; original click_time retained.',
                'risk_assessment': 'Stored scores are not calibrated risk.',
                'identity': 'Stored IPs and labels do not identify victims or attackers.'},
            'count_scope': 'Stored rows/status labels/positive scores, not unique people or authenticated events.'}

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
        """Legacy name: select finite stored numbers, not risk conclusions."""
        if not self._finite_stored_number(min_score):
            raise ValueError('min_score must be a finite non-boolean number')
        records = self.get_forensic_victim_intelligence()
        matches = [record for record in records if self._finite_stored_number(record['risk_score'])
                   and record['risk_score'] >= min_score]
        # Stable score ties retain complete-reader click_time DESC, id DESC order.
        return sorted(matches, key=lambda record: record['risk_score'], reverse=True)

    def get_victims_by_country(self, country: str) -> List[Dict[str, Any]]:
        """Select exact unambiguous decoded country strings; retain matched sources."""
        if not isinstance(country, str) or not country.strip():
            raise ValueError('country must be a nonblank string')
        records = self.get_forensic_victim_intelligence()
        return [record for record in records
                if record['json_evidence']['fields']['geolocation_data']['status'] == 'decoded'
                and isinstance(record['geolocation_data'], dict)
                and isinstance(record['geolocation_data'].get('country'), str)
                and record['geolocation_data']['country'] == country]

    def get_attacker_correlations(self) -> List[Dict[str, Any]]:
        """Unsupported interpretation; never replace unavailability with empty success."""
        raise RuntimeError('Attacker correlations are unavailable: stored IP/location/score claims '
                           'do not establish attacker infrastructure. '
                           'Use get_forensic_victim_intelligence for complete stored sources.')

    def _victim_row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Decode known fields by name, independent of migration column order."""
        columns = ['id', 'victim_ip', 'victim_ua', 'click_time', 'phishing_url',
                  'case_id', 'attacker_correlation', 'risk_score', 'analyzed_status',
                  'geolocation_data', 'whois_data', 'related_ips', 'metadata',
                  'created_at', 'updated_at', 'interaction_type', 'interaction_confidence', 'interaction_indicators']

        available = set(row.keys())
        interaction_fields = {'interaction_type', 'interaction_confidence', 'interaction_indicators'}
        victim = {column: (None if column in interaction_fields and column not in available else row[column])
                  for column in columns}

        defaults = {'geolocation_data': {}, 'whois_data': {}, 'metadata': {},
                    'attacker_correlation': {}, 'related_ips': [], 'interaction_indicators': []}
        return self._decode_record_json(victim, defaults, missing=set(defaults) - available)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url
