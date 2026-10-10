import sqlite3
import os
import hashlib
import re
import unicodedata
from collections import Counter
from contextlib import closing
from pathlib import Path
from .domain_age import usable_age_days
from .job_registry import require_stopped_case
from .runtime import read_progress

SIMHASH_METHOD = 'simhash64_sha256_unicode_word_frequency_v1_ucd' + unicodedata.unidata_version
SIMHASH_SCOPE = 'selected_subject_from_received_headers'
SIMHASH_MAX_CHARS = 65536

_db = None

def db():
    """Singleton database connection."""
    global _db
    if _db is None:
        db_path = os.path.join(os.getcwd(), "cases", "index.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        connection = sqlite3.connect(db_path)
        try:
            _init_db(connection)
        except Exception:
            connection.close()
            raise
        _db = connection
    return _db

def _init_db(conn):
    """Initialize database schema."""
    # Serialize schema inspection and additive migration across CLI workers.
    conn.execute('BEGIN IMMEDIATE')
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            created_utc TEXT,
            origin_ip TEXT,
            asn INTEGER,
            org TEXT,
            cc TEXT,
            from_domain TEXT,
            nrd_days INTEGER,
            score REAL,
            simhash TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            case_id TEXT,
            type TEXT,
            value TEXT,
            PRIMARY KEY (case_id, type, value)
        )
    """)
    columns = {row[1] for row in conn.execute('PRAGMA table_info(cases)')}
    for name in ('simhash_method', 'simhash_status'):
        if name not in columns:
            conn.execute(f'ALTER TABLE cases ADD COLUMN {name} TEXT')
    conn.commit()

def upsert_case(case_dir: str, origin: dict, headers: dict, dominfo: dict, score: dict) -> None:
    """Insert or update case in index."""
    conn = db()
    case_id = os.path.basename(case_dir).replace("case-", "")
    
    # Extract data
    origin_ip = origin.get("ip", "")
    asn = origin.get("asn")
    org = origin.get("org", "")
    cc = origin.get("cc", "")
    from_domain = dominfo.get("domain", "")
    nrd_days = usable_age_days(dominfo.get("nrd_days"))
    case_score = score.get("score", 0.0)
    
    # Descriptive selected-header fingerprint, not body/campaign/actor evidence.
    subject = headers.get("subject", "")
    received_lines = " ".join(headers.get("received", []))
    content = f"{subject} {headers.get('from', '')} {received_lines}"
    if len(content) > SIMHASH_MAX_CHARS:
        simhash_val, simhash_status = None, 'unavailable_input_limit'
    else:
        simhash_val = simhash(content)
        simhash_status = 'observed' if simhash_val is not None else 'not_evaluated_no_features'
    
    # Insert/update case
    conn.execute("""
        INSERT OR REPLACE INTO cases 
        (id, created_utc, origin_ip, asn, org, cc, from_domain, nrd_days, score,
         simhash, simhash_method, simhash_status)
        VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, origin_ip, asn, org, cc, from_domain, nrd_days, case_score,
          simhash_val, SIMHASH_METHOD, simhash_status))
    
    # Insert indicators
    indicators = [
        ("ip", origin_ip),
        ("domain", from_domain),
        ("asn", str(asn) if asn else ""),
        ("org", org),
    ]
    
    for ind_type, value in indicators:
        if value:
            conn.execute("""
                INSERT OR IGNORE INTO indicators (case_id, type, value)
                VALUES (?, ?, ?)
            """, (case_id, ind_type, value))
    
    conn.commit()

def query_recent(by: str, value: str, days: int = 30) -> list:
    """Read existing index rows only after their owner confirms shutdown."""
    database = Path.cwd() / 'cases' / 'index.db'
    if not database.exists(): return []
    query = """
        SELECT c.* FROM cases c
        JOIN indicators i ON c.id = i.case_id
        WHERE i.type = ? AND i.value = ? 
        AND c.created_utc >= datetime('now', ?)
        ORDER BY c.created_utc DESC
    """
    # Reader admission must not create/migrate the index or acquire a write lock.
    with closing(sqlite3.connect(f'{database.as_uri()}?mode=ro', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        matches = [dict(row) for row in conn.execute(query, (by, value, f'-{days} days'))]
    stable = []
    for row in matches:
        identifier = 'case-' + row['id']
        if Path(identifier).name != identifier: continue
        directory = database.parent / identifier
        try:
            require_stopped_case(directory)
        except (RuntimeError, FileNotFoundError, ValueError):
            continue  # Unknown/missing owner acknowledgment also fails closed.
        if read_progress(directory/'execution.json').get('status') in {'queued','running','recovery_blocked'}:
            continue
        stable.append(describe_fingerprint(row))
    return stable

def simhash(text: str) -> str | None:
    """64-bit weighted word-feature SimHash; no features means unavailable.

    Unicode word tokens (Python Unicode \\w+, including underscores) are casefolded.
    Each token's first 64 SHA-256 bits votes +/- its frequency per bit. Positive
    totals set the result bit; ties are zero. This version performs no Unicode
    normalization, body comparison, thresholding or attribution.
    """
    if not isinstance(text, str):
        raise TypeError('SimHash input must be text')
    if len(text) > SIMHASH_MAX_CHARS:
        raise ValueError('SimHash input exceeds 65536 characters')
    features = Counter(token.casefold() for token in re.findall(r'\w+', text))
    if not features:
        return None
    votes = [0] * 64
    for token, weight in features.items():
        hashed = int.from_bytes(hashlib.sha256(token.encode('utf-8')).digest()[:8], 'big')
        for bit in range(64):
            votes[bit] += weight if hashed & (1 << bit) else -weight
    value = sum(1 << bit for bit, vote in enumerate(votes) if vote > 0)
    return f'{value:016x}'


def describe_fingerprint(row: dict) -> dict:
    """Annotate query results without rewriting legacy rows or sealed cases."""
    result = dict(row)
    method = result.get('simhash_method')
    if method is None:
        result['simhash_method'] = 'legacy_md5_prefix_64'
        result['simhash_status'] = 'legacy_not_similarity_fingerprint'
    result['simhash_scope'] = SIMHASH_SCOPE
    result['similarity_validation'] = 'not_validated'
    return result
