#!/usr/bin/env python3
"""
Import enrichment.json files from cases into the central SQLite DB (sentinel.db).

Creates table `enrichment_results(case_id, domain, enrichment_json, inserted_at)` if missing.
If a record for the same (case_id, domain) exists it will be updated.
"""
import argparse
import json
import sqlite3
from datetime import datetime
from pathlib import Path


def import_enrichment(db_path: Path, cases_dir: Path):
    db_path = Path(db_path)
    cases_dir = Path(cases_dir)

    if not cases_dir.exists():
        print(f"Cases directory not found: {cases_dir}")
        return

    # Connect and ensure table exists
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrichment_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            enrichment_json TEXT,
            inserted_at TEXT NOT NULL,
            UNIQUE(case_id, domain)
        )
    """)
    conn.commit()

    inserted = 0
    updated = 0

    for case_dir in sorted(cases_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        enrichment_file = case_dir / 'enrichment.json'
        if not enrichment_file.exists():
            continue
        try:
            data = json.loads(enrichment_file.read_text(encoding='utf-8'))
        except Exception as e:
            print(f"Failed to load {enrichment_file}: {e}")
            continue

        case_id = data.get('case_id') or case_dir.name
        generated = data.get('generated', [])

        for entry in generated:
            domain = entry.get('domain')
            if not domain:
                continue

            enrichment_text = json.dumps(entry, ensure_ascii=False)
            now = datetime.utcnow().isoformat() + 'Z'
            cur = conn.execute("SELECT id FROM enrichment_results WHERE case_id = ? AND domain = ?", (case_id, domain)).fetchone()
            if cur:
                conn.execute("UPDATE enrichment_results SET enrichment_json = ?, inserted_at = ? WHERE id = ?", (enrichment_text, now, cur[0]))
                updated += 1
            else:
                conn.execute("INSERT INTO enrichment_results (case_id, domain, enrichment_json, inserted_at) VALUES (?, ?, ?, ?)", (case_id, domain, enrichment_text, now))
                inserted += 1

    conn.commit()
    conn.close()

    print(f"Import complete: inserted={inserted}, updated={updated}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='sentinel.db', help='SQLite DB path (default: sentinel.db)')
    p.add_argument('--cases', default=str(Path(__file__).parent.parent / 'cases'), help='Cases directory')
    args = p.parse_args()

    import_enrichment(Path(args.db), Path(args.cases))


if __name__ == '__main__':
    main()
