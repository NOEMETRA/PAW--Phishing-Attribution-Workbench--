import sqlite3
import os
import hashlib

_db = None

def db():
    """Singleton database connection."""
    global _db
    if _db is None:
        db_path = os.path.join(os.getcwd(), "cases", "index.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        _db = sqlite3.connect(db_path)
        _init_db(_db)
    return _db

def _init_db(conn):
    """Initialize database schema."""
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
    nrd_days = dominfo.get("nrd_days", 0)
    case_score = score.get("score", 0.0)
    
    # Generate simhash from subject + from + received content
    subject = headers.get("subject", "")
    received_lines = " ".join(headers.get("received", []))
    content = f"{subject} {headers.get('from', '')} {received_lines}".encode()
    # Use SHA-256 instead of MD5 (cryptographically broken)
    simhash_val = hashlib.sha256(content).hexdigest()[:16]  # Store first 16 chars as hex string
    
    # Insert/update case
    conn.execute("""
        INSERT OR REPLACE INTO cases 
        (id, created_utc, origin_ip, asn, org, cc, from_domain, nrd_days, score, simhash)
        VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, origin_ip, asn, org, cc, from_domain, nrd_days, case_score, simhash_val))
    
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
    """Query recent cases by indicator."""
    conn = db()
    query = f"""
        SELECT c.* FROM cases c
        JOIN indicators i ON c.id = i.case_id
        WHERE i.type = ? AND i.value = ? 
        AND c.created_utc >= datetime('now', '-{days} days')
        ORDER BY c.created_utc DESC
    """
    cursor = conn.execute(query, (by, value))
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

def simhash(text: str) -> str:
    """Generate 64-bit simhash from text as hex string."""
    # Use SHA-256 instead of MD5 (cryptographically broken)
    h = hashlib.sha256(text.encode())
    return h.hexdigest()[:16]