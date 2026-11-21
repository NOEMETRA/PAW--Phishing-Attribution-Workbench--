# paw/sentinel/database.py
"""
Database management for Sentinel monitoring campaigns.
"""
import sqlite3
import base64
from contextlib import contextmanager, closing, nullcontext
import json
import math
import re
import weakref
import uuid
from contextvars import ContextVar
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from ..util.timeutil import utc_now_iso
from .config import (_storage_path, _admit_storage_path, _storage_identity, _storage_opener,
                     _resource_limits, _json_tree, _json_chunks, _encode_writer_json, _bounded_report, _require_active)


_AUTOMATIC_ATTEMPT_LIMIT = 6

# SQLite matches the indexed expression to the lookup as written. Guard
# legacy metadata before calling any JSON function that requires valid input.
# Skip confirmed alerts early to keep index creation within the SQL budget
# on archives dominated by completed deliveries.
_AUTOMATIC_QUEUE_RECEIVER = f"""
    CASE WHEN json_valid(metadata) THEN
        CASE json_extract(metadata,'$.webhook_delivery.status')
            WHEN 'receipt_confirmed' THEN NULL
            ELSE CASE WHEN json_type(metadata,'$.webhook_delivery.automatic') = 'true'
                AND json_extract(metadata,'$.webhook_delivery.attempts') BETWEEN 0 AND {_AUTOMATIC_ATTEMPT_LIMIT - 1}
                AND json_extract(metadata,'$.webhook_delivery.status') IN ('queued','pending','receipt_unconfirmed')
            THEN json_extract(metadata,'$.webhook_delivery.destination_sha256') END
        END
    END
"""


def _automatic_retry_cutoff():
    # Stored timestamps omit fractions. A retry must wait five seconds
    # beyond the entire recorded second, including its unknown fraction.
    before = datetime.now(timezone.utc) - timedelta(seconds=6)
    return before.strftime('%Y-%m-%dT%H:%M:%SZ')


class _StoredJSONError(ValueError):
    """A syntactically accepted value is ambiguous or non-finite."""


class _InvalidUTF8Text(bytes):
    """Undecodable SQLite TEXT, distinct from a stored BLOB."""


class AlertDeliveryMissing(ValueError):
    """An alert disappeared before its delivery attempt could be stored."""


class CampaignDatabase:
    """SQLite database for managing monitored phishing campaigns."""

    def __init__(self, db_path: str = "sentinel.db", *, read_only: bool = False, limits=None, initialize: bool = True):
        if type(read_only) is not bool or type(initialize) is not bool:
            raise ValueError('read_only and initialize must be booleans')
        self.limits = _resource_limits(limits)
        self._json_budget = ContextVar('sentinel_json_budget', default=None)
        path = _storage_path(db_path)
        self.db_path = str(path)
        self.read_only = read_only
        existing_only = read_only or not initialize
        metadata = _admit_storage_path(path, must_exist=existing_only, directory_as_missing=existing_only)
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
        if initialize:
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
            self._bound_connection(conn)
            if self.read_only:
                conn.execute("PRAGMA query_only = ON")
                conn.execute('BEGIN')
            with conn:
                yield conn
                if self.read_only: self._admit_database()

    def _bound_connection(self, conn):
        limits = self.limits
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, limits['max_row_bytes'])
        counters = weakref.WeakKeyDictionary()
        def bounded_row(cursor, values):
            count, size = counters.get(cursor, (0, 0))
            size += sum(len(v.encode('utf-8', errors='surrogatepass')) if isinstance(v, str)
                        else len(v) if isinstance(v, bytes) else 8 for v in values)
            if count+1 > limits['max_rows'] or size > limits['max_result_bytes']:
                raise ValueError('Sentinel selected-result row/byte limit exceeded; no complete result')
            counters[cursor] = (count+1, size)
            return values
        conn.row_factory = bounded_row
        steps = 0; interval = min(100, limits['max_sql_steps'])
        def progress():
            nonlocal steps
            steps += interval
            return steps >= limits['max_sql_steps']
        conn.set_progress_handler(progress, interval)

    def check_report(self, value):
        if isinstance(value, dict):
            value['read_contract'] = {'sqlite_view': 'one_read_transaction_per_connection',
                'atomic_filesystem_snapshot': False, 'limits': dict(self.limits),
                'scope': 'Selected stored rows; no source history or authenticity established'}
        for _ in _json_chunks(value, self.limits['max_output_bytes']): pass
        return value

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
            if not self.read_only: conn.execute('BEGIN')
            budget = conn.row_factory
            def bounded_named(cursor, values):
                budget(cursor, values)
                return named_row(cursor, values)
            conn.text_factory = decode_text
            conn.row_factory = bounded_named
            token = self._json_budget.set([self.limits['max_json_nodes']])
            try: yield conn
            finally: self._json_budget.reset(token)

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
            elif ((self._json_budget.get() is not None and self._json_budget.get()[0] <= 0) or
                    (len(raw.encode('utf-8')) if isinstance(raw,str) else len(raw)) > self.limits['max_json_bytes']):
                status = 'resource_limit'
            else:
                decoded = json.loads(raw, object_pairs_hook=unique_object,
                                     parse_constant=reject_constant, parse_float=finite_float)
                try:
                    decoded = _json_tree(decoded, depth=self.limits['max_json_depth'], nodes=self.limits['max_json_nodes'],
                                         budget=self._json_budget.get())
                except ValueError:
                    evidence.update(status='resource_limit', default_applied=True)
                    return default, evidence
                return decoded, evidence
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

    @staticmethod
    def _encode_writer_json(value, field, expected=dict):
        return _encode_writer_json(value, field, expected)

    @staticmethod
    def _writer_text(value, field, *, optional=False, nonblank=False):
        if optional and value is None: return
        if type(value) is not str or nonblank and not value.strip():
            raise ValueError(f'{field} must be a literal string')

    @staticmethod
    def _writer_number(value, field, *, minimum=None, maximum=None, integer=False):
        if (type(value) not in ((int,) if integer else (int, float)) or
                type(value) is float and not math.isfinite(value) or
                type(value) is int and not -(2**63) <= value < 2**63 or
                minimum is not None and value < minimum or maximum is not None and value > maximum):
            raise ValueError(f'{field} requires an admitted finite number')

    @staticmethod
    def _insert_writer_record(conn, table, columns, values):
        # Names come exclusively from fixed internal call sites, never callers.
        cursor = conn.execute(f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})", values)
        if cursor.rowcount != 1:
            raise RuntimeError('Sentinel record was not inserted; transaction rolled back')
        CampaignDatabase._assert_writer_record(conn, table, columns, values, cursor.lastrowid)
        return cursor.lastrowid

    @staticmethod
    def _assert_writer_record(conn, table, columns, values, rowid):
        rows = conn.execute(f"SELECT {', '.join(columns)} FROM {table} WHERE rowid=?", (rowid,)).fetchall()
        if rows != [tuple(values)]:
            raise RuntimeError('Sentinel record did not persist as supplied; transaction rolled back')

    @staticmethod
    def _require_writer_campaign(conn, campaign_id):
        if conn.execute('SELECT id FROM campaigns WHERE id=? COLLATE BINARY', (campaign_id,)).fetchall() != [(campaign_id,)]:
            raise ValueError('Exactly one existing literal campaign is required')

    def add_campaign(self, case_id: str, url: str, metadata: Dict[str, Any] = None) -> str:
        """Store one literal campaign per case, without authorizing collection."""
        if not isinstance(case_id, str) or not case_id.strip() or not isinstance(url, str) or not url.strip():
            raise ValueError("case_id and url must be nonblank strings")
        encoded_metadata = self._encode_writer_json({} if metadata is None else metadata, 'metadata')
        domain = self._extract_domain(url)
        campaign_id = f"sentinel_{case_id}_{int(datetime.now().timestamp())}"

        with self.connection() as conn:
            # Also protect legacy tables without today's UNIQUE(case_id).
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM campaigns WHERE case_id=? LIMIT 1", (case_id,)).fetchone():
                raise ValueError(f"Campaign already exists for case: {case_id}")
            self._insert_writer_record(conn, 'campaigns',
                ('id', 'case_id', 'created_at', 'url', 'domain', 'metadata', 'status'), (
                campaign_id,
                case_id,
                utc_now_iso(),
                url,
                domain,
                encoded_metadata,
                'active'
            ))
            conn.commit()

        return campaign_id

    def remove_campaign(self, campaign_id: str, *, case_id: str = None) -> bool:
        """Acknowledge exactly one active-to-removed transition in one transaction."""
        self._writer_text(campaign_id, 'campaign_id')
        self._writer_text(case_id, 'case_id', optional=True)
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
        self._writer_text(campaign_id, 'campaign_id')
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

    def update_campaign_status(self, campaign_id: str, status: str) -> bool:
        """Update campaign status."""
        self._writer_text(campaign_id, 'campaign_id', nonblank=True)
        self._writer_text(status, 'status', optional=True, nonblank=True)
        return self._transition('campaigns', campaign_id, 'status', status) == 'updated'

    def _transition(self, table, identifier, column, value, *, campaign_id=None):
        # Table and column names come from fixed internal callers.
        where = 'id=? COLLATE BINARY'
        keys = (identifier,)
        if campaign_id is not None:
            where += ' AND campaign_id=? COLLATE BINARY'
            keys += (campaign_id,)
        select = f'SELECT {column} FROM {table} WHERE {where}'
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            kind = conn.execute('SELECT type FROM sqlite_master WHERE name=? COLLATE NOCASE',
                                (table,)).fetchone()
            if kind != ('table',):
                raise ValueError('Sentinel transition requires a saved table')
            rows = conn.execute(select, keys).fetchall()
            if len(rows) > 1:
                raise ValueError('Ambiguous Sentinel transition target')
            if not rows:
                return 'missing'
            if rows == [(value,)]:
                return 'unchanged'
            cursor = conn.execute(f'UPDATE {table} SET {column}=? WHERE {where}', (value, *keys))
            if cursor.rowcount == 0:
                conn.rollback()
                return 'rejected'
            if cursor.rowcount != 1 or conn.execute(select, keys).fetchall() != [(value,)]:
                raise RuntimeError('Sentinel transition did not persist; transaction rolled back')
            return 'updated'

    def record_check(self, campaign_id: str, status: str, response_time: float = None,
                    http_status: int = None, content_hash: str = None,
                    screenshot_path: str = None, error_message: str = None,
                    metadata: Dict[str, Any] = None) -> None:
        """Record one admitted result and its parent timestamp together."""
        self._writer_text(campaign_id, 'campaign_id', nonblank=True)
        self._writer_text(status, 'status', nonblank=True)
        for field, value in (('content_hash', content_hash), ('screenshot_path', screenshot_path), ('error_message', error_message)):
            self._writer_text(value, field, optional=True)
        if response_time is not None: self._writer_number(response_time, 'response_time', minimum=0)
        if http_status is not None: self._writer_number(http_status, 'http_status', minimum=100, maximum=599, integer=True)
        encoded = self._encode_writer_json({} if metadata is None else metadata, 'metadata')
        columns = ('campaign_id', 'check_time', 'status', 'response_time', 'http_status',
                   'content_hash', 'screenshot_path', 'error_message', 'metadata')
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            self._require_writer_campaign(conn, campaign_id)
            timestamp = utc_now_iso()
            values = (campaign_id, timestamp, status, response_time, http_status,
                      content_hash, screenshot_path, error_message, encoded)
            rowid = self._insert_writer_record(conn, 'checks', columns, values)

            # Update last_check timestamp
            cursor = conn.execute("""
                UPDATE campaigns SET last_check = ? WHERE id = ?
            """, (timestamp, campaign_id))
            if (cursor.rowcount != 1 or conn.execute('SELECT last_check FROM campaigns WHERE id=?',
                    (campaign_id,)).fetchall() != [(timestamp,)]):
                raise RuntimeError('Sentinel check timestamp did not persist; transaction rolled back')
            self._assert_writer_record(conn, 'checks', columns, values, rowid)
            conn.commit()

    def _stored_monitor_comparison(self, raw):
        metadata, evidence = self._decode_json_field(raw, {})
        comparison = metadata.get('monitor_comparison') if isinstance(metadata, dict) else None
        if evidence['status'] != 'decoded' or not isinstance(comparison, dict):
            return {}
        version = comparison.get('schema_version')
        return comparison if type(version) is int and version == 1 else {}

    def _record_monitor_result(self, result, flags, *, commit_guard=None, webhook_fingerprint=None):
        """Compare, record and alert in one actual SQLite write transaction."""
        _require_active()
        if self.read_only: raise RuntimeError('Read-only saved storage cannot publish monitor observations')
        if commit_guard is not None and not callable(commit_guard): raise ValueError('Callable monitor commit guard required')
        if webhook_fingerprint is not None and (type(webhook_fingerprint) is not str
                or not re.fullmatch('[0-9a-f]{64}', webhook_fingerprint)):
            raise ValueError('Invalid queued webhook destination')
        if type(result) is not dict or type(flags) is not dict:
            raise ValueError('Native monitor result and alert flags required')
        result = _json_tree(result); flags = _json_tree(flags)
        allowed = {'campaign_id','url','status','http_status','content_hash','response_time','error_message','metadata','screenshot_path'}
        if set(result)-allowed or result.get('screenshot_path') is not None:
            raise ValueError('Unknown monitor fields or unavailable screenshot publication')
        for key in ('enabled','alert_on_down','alert_on_up','alert_on_changes'):
            if type(flags.get(key)) is not bool: raise ValueError('Native boolean alert flags required')
        campaign_id = result.get('campaign_id'); status = result.get('status')
        self._writer_text(campaign_id,'campaign_id',nonblank=True)
        self._writer_text(result.get('url'),'url',nonblank=True)
        if status not in ('up','down','error'): raise ValueError('Unknown monitor status')
        code = result.get('http_status'); digest = result.get('content_hash')
        if code is not None: self._writer_number(code,'http_status',minimum=100,maximum=599,integer=True)
        if status != 'error' and (code is None or status != ('up' if code < 400 else 'down')):
            raise ValueError('Monitor status must match its HTTP status policy')
        if digest is not None and (type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None):
            raise ValueError('A complete SHA256 observation is required')
        if status == 'error' and digest is not None: raise ValueError('Failed collection cannot assert a complete digest')
        elapsed = result.get('response_time')
        if elapsed is not None: self._writer_number(elapsed,'response_time',minimum=0)
        self._writer_text(result.get('error_message'),'error_message',optional=True)
        source_metadata = result.get('metadata',{})
        if type(source_metadata) is not dict: raise ValueError('Native monitor metadata object required')
        observation = source_metadata.get('http_observation')
        representation = ('http_entity_bytes_no_content_decoding_v1' if type(observation) is dict and
            observation.get('body_representation') == 'HTTP entity bytes, without content decoding'
            else 'caller_supplied_digest_unverified')
        receipt = {'check_id':None,'events':[],'alerts':[],'previous_check_id':None,
                   'digest_reference_check_id':None,'content_changed':False}
        columns = ('campaign_id','check_time','status','response_time','http_status','content_hash',
                   'screenshot_path','error_message','metadata')
        alert_columns = ('campaign_id','alert_time','alert_type','severity','message','metadata')
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            parent = conn.execute('SELECT status,url FROM campaigns WHERE id=? COLLATE BINARY',(campaign_id,)).fetchall()
            if parent != [('active',result['url'])]:
                raise RuntimeError('Campaign removed or changed before monitor publication')
            previous = conn.execute('SELECT id,status,http_status,content_hash,metadata FROM checks WHERE campaign_id=? COLLATE BINARY '
                                    'ORDER BY id DESC LIMIT 1',(campaign_id,)).fetchone()
            prior_status = None; same_source = False; same_representation = False
            reference = None
            if previous:
                receipt['previous_check_id'] = previous[0]
                prior = self._stored_monitor_comparison(previous[4])
                same_source = prior.get('observation_url') == result['url']
                same_representation = same_source and prior.get('content_representation') == representation
                if same_source and type(previous[2]) is int and 100 <= previous[2] <= 599:
                    expected = 'up' if previous[2] < 400 else 'down'
                    if previous[1] == expected: prior_status = expected
                if same_representation and prior_status is not None:
                    reference = previous
                elif same_representation and previous[1] == 'error' and previous[3] is None:
                    # Carry a source ID across transport failures only. Resolve
                    # it again inside this transaction to respect expiry.
                    source_id = prior.get('digest_reference_check_id')
                    if type(source_id) is int and 0 < source_id < previous[0]:
                        candidate = conn.execute(
                            'SELECT id,status,http_status,content_hash,metadata FROM checks '
                            'WHERE campaign_id=? COLLATE BINARY AND id=?',
                            (campaign_id, source_id),
                        ).fetchone()
                        if (candidate and type(candidate[2]) is int and 100 <= candidate[2] <= 599
                                and candidate[1] == ('up' if candidate[2] < 400 else 'down')):
                            saved = self._stored_monitor_comparison(candidate[4])
                            if (saved.get('observation_url') == result['url']
                                    and saved.get('content_representation') == representation):
                                reference = candidate
                if reference and isinstance(reference[3], str) and re.fullmatch('[0-9a-f]{64}', reference[3]):
                    receipt['digest_reference_check_id'] = reference[0]
                    receipt['content_changed'] = digest is not None and digest != reference[3]
            if status in ('up','down') and prior_status in ('up','down') and status != prior_status:
                receipt['events'].append(status)
            if receipt['content_changed']: receipt['events'].append('changed')
            timestamp = utc_now_iso()
            comparison = {'schema_version':1,'observation_url':result['url'],
                'content_representation':representation,'same_source':same_source,
                'same_representation':same_representation,'previous_check_id':receipt['previous_check_id'],
                'digest_reference_check_id':receipt['digest_reference_check_id'],
                'scope':'HTTP class compared to previous check; digest compared to referenced complete observation. Change time and campaign liveness are unverified.',
                'verified':False}
            metadata = self._encode_writer_json({'source_metadata':result.get('metadata',{}),
                                                 'monitor_comparison':comparison},'metadata')
            values = (campaign_id,timestamp,status,elapsed,code,digest,None,result.get('error_message'),metadata)
            rowid = self._insert_writer_record(conn,'checks',columns,values); receipt['check_id'] = rowid
            if conn.execute('UPDATE campaigns SET last_check=? WHERE id=? COLLATE BINARY',(timestamp,campaign_id)).rowcount != 1:
                raise RuntimeError('Monitor parent timestamp did not persist')
            inserted = []
            for event in receipt['events']:
                enabled = flags['enabled'] and flags['alert_on_changes' if event == 'changed' else 'alert_on_'+event]
                if not enabled: continue
                message = ('Stored content digest differs' if event == 'changed' else 'HTTP status class transitioned to '+event)
                level = 'warning' if event == 'down' else 'info'
                alert_data = {**comparison, 'check_id':rowid, 'external_delivery_at_commit':'not_attempted'}
                if webhook_fingerprint is not None:
                    alert_data['webhook_delivery'] = {
                        'event_id':uuid.uuid4().hex, 'destination_sha256':webhook_fingerprint,
                        'automatic':True, 'status':'queued', 'attempts':0, 'http_status':None,
                        'error':None, 'updated_at':timestamp,
                    }
                alert_metadata = self._encode_writer_json(alert_data, 'metadata')
                alert_values = (campaign_id,timestamp,event,level,message,alert_metadata)
                alert_id = self._insert_writer_record(conn,'alerts',alert_columns,alert_values)
                inserted.append((alert_id,alert_values))
                receipt['alerts'].append({'id':alert_id,'campaign_id':campaign_id,'type':event,
                    'message':message,'severity':level,'timestamp':timestamp,'check_id':rowid,'verified':False})
            self._assert_writer_record(conn,'checks',columns,values,rowid)
            for alert_id,alert_values in inserted:
                self._assert_writer_record(conn,'alerts',alert_columns,alert_values,alert_id)
            if conn.execute('SELECT status,url,last_check FROM campaigns WHERE id=? COLLATE BINARY',(campaign_id,)).fetchall() != [('active',result['url'],timestamp)]:
                raise RuntimeError('Monitor parent changed or timestamp reverted; transaction rolled back')
            sources = [previous] if previous else []
            if reference is not None and reference is not previous:
                sources.append(reference)
            for source in sources:
                rows = conn.execute('SELECT id,status,http_status,content_hash,metadata FROM checks '
                                    'WHERE id=? AND campaign_id=? COLLATE BINARY', (source[0], campaign_id)).fetchall()
                if rows != [source]:
                    raise RuntimeError('Monitor comparison source changed; transaction rolled back')
            for _ in _json_chunks(receipt,self.limits['max_output_bytes']): pass
            with commit_guard() if commit_guard is not None else nullcontext():
                conn.commit()
        return receipt

    def record_alert(self, campaign_id: str, alert_type: str, message: str,
                    severity: str = "info", metadata: Dict[str, Any] = None) -> None:
        """Record an alert."""
        self._writer_text(campaign_id, 'campaign_id', nonblank=True)
        self._writer_text(alert_type, 'alert_type', nonblank=True)
        self._writer_text(message, 'message')
        self._writer_text(severity, 'severity', nonblank=True)
        encoded = self._encode_writer_json({} if metadata is None else metadata, 'metadata')
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            self._require_writer_campaign(conn, campaign_id)
            self._insert_writer_record(conn, 'alerts',
                ('campaign_id', 'alert_time', 'alert_type', 'severity', 'message', 'metadata'), (
                campaign_id,
                utc_now_iso(),
                alert_type,
                severity,
                message,
                encoded
            ))
            self._require_writer_campaign(conn, campaign_id)
            conn.commit()

    @_bounded_report
    def get_campaign_history(self, campaign_id: str) -> Dict[str, Any]:
        """Read a bounded summary from one SQLite snapshot, including removed campaigns."""
        self._writer_text(campaign_id, 'campaign_id', nonblank=True)
        limit = 10
        with self._json_read_connection() as conn:
            campaign = conn.execute(
                "SELECT id, case_id, status FROM campaigns WHERE id = ? COLLATE BINARY",
                (campaign_id,),
            ).fetchone()
            if campaign is None:
                raise ValueError("Unknown stored campaign ID")
            checks = conn.execute("""
                SELECT id, check_time, status, http_status, content_hash
                FROM checks WHERE campaign_id = ? COLLATE BINARY ORDER BY id DESC LIMIT ?
            """, (campaign_id, limit)).fetchall()
            has_metadata = conn.execute(
                "SELECT 1 FROM pragma_table_info('alerts') WHERE name = 'metadata' COLLATE NOCASE"
            ).fetchone()
            # Some legacy alert tables contain only summary columns. Keep the
            # same read-only view and cap the bytes read from optional metadata.
            source = ("CASE WHEN length(CAST(metadata AS BLOB)) <= ? THEN metadata END"
                      if has_metadata else "NULL")
            parameters = [self.limits['max_json_bytes']] if has_metadata else []
            rows = conn.execute(f"""
                SELECT id, alert_time, alert_type, severity, acknowledged, {source} AS metadata
                FROM alerts WHERE campaign_id = ? COLLATE BINARY ORDER BY id DESC LIMIT ?
            """, [*parameters, campaign_id, limit]).fetchall()
            alerts = []
            for row in rows:
                alert = dict(row)
                metadata, _ = self._decode_json_field(alert.pop('metadata'), {})
                check_id = metadata.get('check_id') if isinstance(metadata, dict) else None
                if type(check_id) is not int or not 1 <= check_id <= 2**63 - 1:
                    check_id = None
                alert['external_delivery_at_commit'] = (
                    'not_attempted' if isinstance(metadata, dict)
                    and metadata.get('external_delivery_at_commit') == 'not_attempted' else 'unknown'
                )
                reference_id = metadata.get('digest_reference_check_id') if isinstance(metadata, dict) else None
                alert['digest_reference_check_id'] = (
                    reference_id if alert['alert_type'] == 'changed' and type(reference_id) is int
                    and check_id is not None and 0 < reference_id < check_id else None
                )
                delivery = metadata.get('webhook_delivery') if isinstance(metadata, dict) else None
                if self._valid_delivery_state(delivery):
                    alert['webhook_delivery'] = delivery
                alert['recorded_check_id'] = check_id
                alert['source_check_available'] = None if check_id is None else bool(conn.execute(
                    "SELECT 1 FROM checks WHERE id = ? AND campaign_id = ? COLLATE BINARY LIMIT 1",
                    (check_id, campaign_id),
                ).fetchone())
                alerts.append(alert)
        return {
            'campaign': dict(campaign), 'limit_per_kind': limit, 'order': 'id_desc',
            'checks': [dict(row) for row in checks],
            'alerts': alerts,
        }

    def get_recent_checks(self, campaign_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent checks for a campaign."""
        self._writer_text(campaign_id, 'campaign_id')
        self._writer_number(limit, 'limit', minimum=0, integer=True)
        checks = []
        with self._json_read_connection() as conn:
            rows = conn.execute("""
                SELECT id, campaign_id, check_time, status, response_time, http_status,
                       content_hash, screenshot_path, error_message, metadata
                FROM checks WHERE campaign_id = ?
                ORDER BY check_time DESC, id DESC LIMIT ?
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
                ORDER BY alert_time DESC, id DESC
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

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged."""
        self._writer_number(alert_id, 'alert_id', minimum=1, integer=True)
        return self._transition('alerts', alert_id, 'acknowledged', 1) == 'updated'

    def acknowledge_campaign_alert(self, campaign_id: str, alert_id: int) -> str:
        """Acknowledge the selected campaign alert in one transaction."""
        self._writer_text(campaign_id, 'campaign_id', nonblank=True)
        self._writer_number(alert_id, 'alert_id', minimum=1, integer=True)
        result = self._transition('alerts', alert_id, 'acknowledged', 1, campaign_id=campaign_id)
        if result == 'missing':
            raise ValueError('Alert not found for the selected campaign')
        if result == 'rejected':
            raise RuntimeError('Sentinel acknowledgment did not persist; transaction rolled back')
        return 'acknowledged' if result == 'updated' else 'already_acknowledged'

    @staticmethod
    def _valid_delivery_state(state):
        required = {'event_id','destination_sha256','status','attempts','http_status','error','updated_at'}
        if not isinstance(state, dict) or set(state) - {'automatic'} != required:
            return False
        if 'automatic' in state and state['automatic'] is not True:
            return False
        event_id, target = state['event_id'], state['destination_sha256']
        return (isinstance(event_id, str) and re.fullmatch('[0-9a-f]{32}', event_id) is not None
                and isinstance(target, str) and re.fullmatch('[0-9a-f]{64}', target) is not None
                and state['status'] in ('queued','pending','receipt_confirmed','receipt_unconfirmed')
                and type(state['attempts']) is int and 0 <= state['attempts'] < 2**63
                and (state['attempts'] > 0 if state['status'] != 'queued'
                     else state['attempts'] == 0 and state.get('automatic') is True)
                and (state['http_status'] is None or
                     type(state['http_status']) is int and 100 <= state['http_status'] <= 599)
                and state['error'] in (None,'http_status','receipt_missing','transport_error','deadline_exceeded')
                and isinstance(state['updated_at'], str)
                and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', state['updated_at']) is not None
                and (state['status'] != 'receipt_confirmed' or
                     state['http_status'] is not None and 200 <= state['http_status'] < 300
                     and state['error'] is None))

    def prepare_automatic_delivery(self):
        """Index the eligible queue when the foreground sender is enabled."""
        _require_active()
        with self.connection() as conn:
            conn.execute(f"""
                CREATE INDEX IF NOT EXISTS sentinel_automatic_queue_receiver
                ON alerts (({_AUTOMATIC_QUEUE_RECEIVER}), id)
                WHERE ({_AUTOMATIC_QUEUE_RECEIVER}) IS NOT NULL
            """)

    def next_automatic_alert(self, fingerprint):
        """Select one due event from the durable queue for the configured receiver."""
        _require_active()
        with self.connection() as conn:
            return conn.execute(f"""
                SELECT campaign_id, id FROM alerts
                WHERE ({_AUTOMATIC_QUEUE_RECEIVER}) = ?
                    AND CASE WHEN json_valid(metadata) THEN
                        json_extract(metadata,'$.webhook_delivery.attempts') = 0
                        OR json_extract(metadata,'$.webhook_delivery.updated_at') <= ?
                    END
                ORDER BY id LIMIT 1
            """, (fingerprint, _automatic_retry_cutoff())).fetchone()

    @contextmanager
    def _alert_delivery_row(self, campaign_id, alert_id):
        self._writer_text(campaign_id, 'campaign_id', nonblank=True)
        self._writer_number(alert_id, 'alert_id', minimum=1, integer=True)
        keys = (alert_id, campaign_id)
        select = ('SELECT alert_type,metadata FROM alerts '
                  'WHERE id=? AND campaign_id=? COLLATE BINARY')
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if conn.execute("SELECT type FROM sqlite_master WHERE name='alerts' COLLATE NOCASE").fetchone() != ('table',):
                raise ValueError('Sentinel delivery requires a saved alert table')
            rows = conn.execute(select, keys).fetchall()
            if not rows:
                raise AlertDeliveryMissing('Alert not found for the selected campaign')
            if len(rows) != 1:
                raise ValueError('Expected one saved alert for the selected campaign')
            alert_type, raw = rows[0]
            metadata, evidence = self._decode_json_field(raw, {})
            if evidence['status'] not in ('decoded','sql_null') or not isinstance(metadata, dict):
                raise ValueError('Unreadable alert metadata; delivery state cannot be saved')
            before = self._encode_writer_json(metadata, 'metadata')
            yield alert_type, metadata
            encoded = self._encode_writer_json(metadata, 'metadata')
            if encoded != before:
                cursor = conn.execute('UPDATE alerts SET metadata=? WHERE id=? AND campaign_id=? COLLATE BINARY',
                                      (encoded,*keys))
                if cursor.rowcount != 1 or conn.execute(select, keys).fetchall() != [(alert_type,encoded)]:
                    raise RuntimeError('Sentinel delivery state did not persist')
            conn.commit()

    def start_alert_delivery(self, campaign_id, alert_id, destination_hash, *, automatic=False):
        _require_active()
        with self._alert_delivery_row(campaign_id, alert_id) as (alert_type, metadata):
            if type(alert_type) is not str or not 0 < len(alert_type) <= 128:
                raise ValueError('A short text alert type is required for webhook delivery')
            if 'webhook_delivery' in metadata:
                state = metadata['webhook_delivery']
                if not self._valid_delivery_state(state):
                    raise ValueError('Unreadable saved webhook state')
            else:
                if automatic:
                    return None
                state = {'event_id':uuid.uuid4().hex, 'destination_sha256':destination_hash,
                         'attempts':0, 'status':'pending'}
                metadata['webhook_delivery'] = state
            if state['destination_sha256'] != destination_hash:
                raise ValueError('Saved alert delivery is already bound to another recipient')
            # A manual delivery may have changed eligibility after the queue lookup.
            if automatic and (not state.get('automatic') or state['status'] == 'receipt_confirmed'
                              or state['attempts'] >= _AUTOMATIC_ATTEMPT_LIMIT
                              or (state['attempts'] > 0 and state['updated_at'] > _automatic_retry_cutoff())):
                return None
            if state['status'] != 'receipt_confirmed':
                state.update(status='pending', attempts=state['attempts']+1,
                             http_status=None, error=None, updated_at=utc_now_iso())
            return dict(state), alert_type

    def finish_alert_delivery(self, campaign_id, alert_id, attempt, outcome, code):
        _require_active()
        with self._alert_delivery_row(campaign_id, alert_id) as (_, metadata):
            state = metadata.get('webhook_delivery', {})
            if (not self._valid_delivery_state(state) or state['event_id'] != attempt['event_id']
                    or state['destination_sha256'] != attempt['destination_sha256']):
                raise RuntimeError('Saved alert delivery changed before its result could be recorded')
            if state['status'] != 'receipt_confirmed' and (
                    outcome == 'receipt_confirmed' or state['attempts'] == attempt['attempts']):
                state.update(status='receipt_confirmed' if outcome == 'receipt_confirmed' else 'receipt_unconfirmed',
                             http_status=code, error=None if outcome == 'receipt_confirmed' else outcome,
                             updated_at=utc_now_iso())
            return dict(state)

    def _expire_check_body(self, conn, identifier):
        # Only rewrite text metadata in the format emitted by the monitor.
        # Reading bytes keeps invalid legacy TEXT from aborting SQLite decoding.
        kind, raw = conn.execute(
            "SELECT typeof(metadata), CASE WHEN length(CAST(metadata AS BLOB)) <= ? "
            "THEN CAST(metadata AS BLOB) END FROM checks WHERE id = ?",
            (self.limits['max_json_bytes'], identifier),
        ).fetchone()
        if kind == 'null':
            return 'absent'
        if kind != 'text' or raw is None:
            return 'uninterpretable'
        try:
            original = raw.decode('utf-8')
        except UnicodeDecodeError:
            return 'uninterpretable'
        metadata, evidence = self._decode_json_field(original, {})
        if evidence['status'] != 'decoded' or not isinstance(metadata, dict):
            return 'uninterpretable'
        source = metadata.get('source_metadata')
        observation = source.get('http_observation') if isinstance(source, dict) else None
        if not isinstance(observation, dict) or 'body_base64' not in observation:
            return 'absent'
        comparison = metadata.get('monitor_comparison')
        version = comparison.get('schema_version') if isinstance(comparison, dict) else None
        if type(version) is not int or version != 1:
            return 'uninterpretable'
        del observation['body_base64']
        source.update(retained_body_bytes=0, body_retention_status='expired')
        encoded = self._encode_writer_json(metadata, 'metadata')
        changed = conn.execute('UPDATE checks SET metadata=? WHERE id=?', (encoded, identifier))
        stored = conn.execute('SELECT metadata FROM checks WHERE id=?', (identifier,)).fetchone()
        if changed.rowcount != 1 or stored != (encoded,):
            raise RuntimeError('Sentinel body expiry did not persist; transaction rolled back')
        return 'expired'

    def _retention_pages(self, conn, snapshot):
        limit = min(self.limits['max_rows'], 500)
        select = f'SELECT id, recorded_at FROM temp.{snapshot}'
        rows = conn.execute(f'{select} ORDER BY id LIMIT ?', (limit,)).fetchall()
        while rows:
            yield rows
            rows = conn.execute(f'{select} WHERE id > ? ORDER BY id LIMIT ?',
                                (rows[-1][0], limit)).fetchall()

    @staticmethod
    def _retention_time(raw):
        if not isinstance(raw, str) or len(raw) > 64 or not re.fullmatch(
                r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)', raw):
            return None
        try:
            return datetime.fromisoformat(raw.replace('Z', '+00:00')).astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return None

    def cleanup_old_data(self, retention_days: int = 90, *, alert_retention_days: int | None = None,
                         body_retention_days: int | None = None):
        """Delete only interpretable expired check/alert rows; never case files."""
        self._writer_number(retention_days, 'retention_days', minimum=0, maximum=365_000, integer=True)
        if body_retention_days is not None:
            self._writer_number(body_retention_days, 'body_retention_days', minimum=0, maximum=365_000, integer=True)
        if alert_retention_days is None:
            alert_retention_days = retention_days
        self._writer_number(alert_retention_days, 'alert_retention_days', minimum=0, maximum=365_000, integer=True)
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            now = datetime.fromisoformat(utc_now_iso().replace('Z', '+00:00'))
            cutoffs = {'checks': now - timedelta(days=retention_days),
                       'alerts': now - timedelta(days=alert_retention_days)}
            if body_retention_days is not None:
                cutoffs['bodies'] = now - timedelta(days=body_retention_days)
            result = {'complete': True, 'cutoff_utc': cutoffs['checks'].strftime('%Y-%m-%dT%H:%M:%SZ'),
                      'cutoffs_utc': {table: value.strftime('%Y-%m-%dT%H:%M:%SZ') for table, value in cutoffs.items()},
                      'deleted': {}, 'retained_uninterpretable': {},
                      'expired_bodies': 0, 'uninterpretable_body_ids': []}
            sources = (('checks', 'check_time', 'retention_checks'),
                       ('alerts', 'alert_time', 'retention_alerts'))
            # Keep the expected ID/time pairs in SQLite, including rows whose
            # timestamps cannot be interpreted. Compare both tables after all
            # writes so a trigger cannot silently change the other table.
            for table, field, snapshot in sources:
                conn.execute(f'CREATE TEMP TABLE {snapshot} (id PRIMARY KEY, recorded_at) WITHOUT ROWID')
                try:
                    conn.execute(f'INSERT INTO temp.{snapshot} SELECT id, {field} FROM main.{table}')
                except sqlite3.IntegrityError as exc:
                    raise ValueError('Ambiguous retention identifiers') from exc
            for table, _, snapshot in sources:
                deleted = 0
                unusable = []
                for rows in self._retention_pages(conn, snapshot):
                    expired = []
                    for identifier, raw in rows:
                        self._writer_number(identifier, 'retention identifier', integer=True)
                        parsed = self._retention_time(raw)
                        if parsed is None:
                            unusable.append(identifier)
                        elif parsed < cutoffs[table]:
                            expired.append(identifier)
                        elif table == 'checks' and 'bodies' in cutoffs and parsed < cutoffs['bodies']:
                            outcome = self._expire_check_body(conn, identifier)
                            if outcome == 'expired':
                                result['expired_bodies'] += 1
                            elif outcome == 'uninterpretable':
                                result['uninterpretable_body_ids'].append(identifier)
                    if expired:
                        selection = f"WHERE id IN ({','.join('?' for _ in expired)})"
                        count = conn.execute(f'DELETE FROM main.{table} {selection}', expired).rowcount
                        if count != len(expired):
                            raise RuntimeError('Sentinel retention did not persist exactly; transaction rolled back')
                        conn.execute(f'DELETE FROM temp.{snapshot} {selection}', expired)
                        deleted += count
                result['deleted'][table] = deleted
                result['retained_uninterpretable'][table] = unusable
            for table, field, snapshot in sources:
                actual, expected, matching = conn.execute(f'''
                    SELECT (SELECT count(*) FROM main.{table}),
                           (SELECT count(*) FROM temp.{snapshot}),
                           (SELECT count(*) FROM (
                               SELECT id, {field} COLLATE BINARY FROM main.{table}
                               INTERSECT SELECT id, recorded_at FROM temp.{snapshot}
                           ))
                ''').fetchone()
                if actual != expected or matching != expected:
                    raise RuntimeError('Sentinel retention did not persist exactly; transaction rolled back')
            self.check_report(result)
        return result

    # ===== VICTIM INTELLIGENCE METHODS =====

    def add_victim_intelligence(self, victim_ip: str, victim_ua: str, phishing_url: str,
                               case_id: str = None, metadata: Dict[str, Any] = None) -> int:
        """Persist supplied interaction fields, without verifying their claims."""
        self._writer_text(victim_ip, 'victim_ip', nonblank=True)
        self._writer_text(victim_ua, 'victim_ua', optional=True)
        self._writer_text(phishing_url, 'phishing_url', nonblank=True)
        self._writer_text(case_id, 'case_id', optional=True)
        encoded = self._encode_writer_json({} if metadata is None else metadata, 'metadata')
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            victim_id = self._insert_writer_record(conn, 'victim_intelligence',
                ('victim_ip', 'victim_ua', 'click_time', 'phishing_url', 'case_id', 'metadata'), (
                victim_ip,
                victim_ua,
                utc_now_iso(),
                phishing_url,
                case_id,
                encoded
            ))
            conn.commit()
            return victim_id

    def get_victim_intelligence(self, victim_id: int = None, victim_ip: str = None) -> List[Dict[str, Any]]:
        """Get victim intelligence data."""
        if victim_id is not None and victim_ip is not None: raise ValueError('Choose one literal selector')
        if victim_id is not None: self._writer_number(victim_id, 'victim_id', integer=True)
        self._writer_text(victim_ip, 'victim_ip', optional=True)
        with self._json_read_connection() as conn:
            if victim_id is not None:
                rows = conn.execute("""
                    SELECT * FROM victim_intelligence WHERE id = ?
                """, (victim_id,)).fetchall()
            elif victim_ip is not None:
                rows = conn.execute("""
                    SELECT * FROM victim_intelligence WHERE victim_ip COLLATE BINARY = ?
                    ORDER BY click_time DESC, id DESC
                """, (victim_ip,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM victim_intelligence
                    ORDER BY click_time DESC, id DESC
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
        self._writer_number(limit, 'limit', minimum=0, integer=True)
        with self._json_read_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM victim_intelligence
                WHERE analyzed_status IN ('captured', 'analyzing')
                ORDER BY click_time DESC, id DESC
                LIMIT ?
            """, (limit,)).fetchall()

            return [self._victim_row_to_dict(row) for row in rows]

    @staticmethod
    def _finite_stored_number(value):
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and (isinstance(value, int) or math.isfinite(value)))

    @_bounded_report
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
        self._writer_number(victim_id, 'victim_id', minimum=1, integer=True)
        for field, value in (('risk_score', risk_score), ('interaction_confidence', interaction_confidence)):
            if value is not None:
                self._writer_number(value, field, minimum=0 if field == 'interaction_confidence' else None,
                                    maximum=1 if field == 'interaction_confidence' else None)
        for field, value in (('analyzed_status', analyzed_status), ('interaction_type', interaction_type)):
            self._writer_text(value, field, optional=True)
        updates = []
        params = []

        if geolocation_data is not None:
            updates.append("geolocation_data = ?")
            params.append(self._encode_writer_json(geolocation_data, 'geolocation_data'))

        if whois_data is not None:
            updates.append("whois_data = ?")
            params.append(self._encode_writer_json(whois_data, 'whois_data'))

        if attacker_correlation is not None:
            updates.append("attacker_correlation = ?")
            params.append(self._encode_writer_json(attacker_correlation, 'attacker_correlation'))

        if risk_score is not None:
            updates.append("risk_score = ?")
            params.append(risk_score)

        if analyzed_status is not None:
            updates.append("analyzed_status = ?")
            params.append(analyzed_status)

        if related_ips is not None:
            updates.append("related_ips = ?")
            params.append(self._encode_writer_json(related_ips, 'related_ips', list))

        if interaction_type is not None:
            updates.append("interaction_type = ?")
            params.append(interaction_type)

        if interaction_confidence is not None:
            updates.append("interaction_confidence = ?")
            params.append(interaction_confidence)

        if interaction_indicators is not None:
            updates.append("interaction_indicators = ?")
            params.append(self._encode_writer_json(interaction_indicators, 'interaction_indicators', list))

        if not updates:
            return False

        updates.append("updated_at = ?")

        query = f"""
            UPDATE victim_intelligence
            SET {', '.join(updates)}
            WHERE id = ?
        """
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            params.extend((utc_now_iso(), victim_id))
            cursor = conn.execute(query, params)
            if cursor.rowcount == 0:
                # An ignored target update may still have run BEFORE triggers.
                conn.rollback()
                return False
            columns = ', '.join(update.split(' = ')[0] for update in updates)
            if (cursor.rowcount != 1 or conn.execute(f'SELECT {columns} FROM victim_intelligence WHERE id=?',
                    (victim_id,)).fetchall() != [tuple(params[:-1])]):
                raise RuntimeError('Sentinel analysis update did not persist; transaction rolled back')
            conn.commit()

        return True

    def calculate_risk_score(self, risk_indicators, geolocation, whois):
        """Risk attribution has no independently validated model."""
        _require_active()
        raise NotImplementedError("Sentinel risk scoring is unavailable; stored numeric claims are not calibrated risk")

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
        if any(record['json_evidence']['fields']['geolocation_data']['status']=='resource_limit' for record in records):
            raise ValueError('Country selection JSON resource limit exceeded; no complete selection')
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
