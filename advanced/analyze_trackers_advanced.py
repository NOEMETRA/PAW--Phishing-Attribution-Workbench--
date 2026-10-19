#!/usr/bin/env python3
"""Legacy tracker case publication is unavailable; saved sources and outputs are preserved.

Internal prototype readers/interpretations remain unvalidated. The separately
tested package tracker extractor provides supplied static observations.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Any


UNAVAILABLE = ('Standalone tracker publication unavailable: saved case '
               'sources and prior outputs are preserved')


TRACKER_ROLES = {
    'linkedin.com': 'b2b_social',
    'licdn.com': 'b2b_social',
    'demdex.net': 'dmp',
    'everesttech.net': 'ad',
    'doubleclick.net': 'ad',
    'googletagmanager.com': 'tag_manager',
    'googlesyndication.com': 'ad',
    'rlcdn.com': 'identity',
    'onetrust.com': 'consent',
    'demandbase.com': 'abm',
}


def load_trackers(case_dir: Path):
    derived = case_dir / 'derived'
    tcsv = derived / 'trackers.csv'
    tids = derived / 'tracker_ids.json'
    trackers = []
    if tcsv.exists():
        with tcsv.open('r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            for r in reader:
                trackers.append(r)
    ids = {}
    if tids.exists():
        try:
            ids = json.loads(tids.read_text(encoding='utf-8') or '{}')
        except Exception:
            ids = {}
    return trackers, ids


def behavioral_fingerprint(trackers, ids_map) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        'total_domains': 0,
        'top_domains': [],
        'roles': {},
        'domains': {},
    }
    counts = {}
    for r in trackers:
        dom = (r.get('domain') or r.get('host') or '').lower()
        try:
            c = int(r.get('count') or 1)
        except Exception:
            c = 1
        counts[dom] = counts.get(dom, 0) + c
        role = TRACKER_ROLES.get(dom, 'unknown')
        summary['roles'][role] = summary['roles'].get(role, 0) + c
        if dom not in summary['domains']:
            summary['domains'][dom] = {'count': 0, 'role': role, 'ids': ids_map.get(dom, {})}
        summary['domains'][dom]['count'] += c
    summary['total_domains'] = len(counts)
    summary['top_domains'] = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return summary


def campaign_intel(ids_map) -> Dict[str, Any]:
    # Flatten known IDs and group by type
    intel = {'by_type': {}, 'all_ids': []}
    for dom, sub in ids_map.items():
        if isinstance(sub, dict):
            for k, v in sub.items():
                intel['by_type'].setdefault(k, []).append({'domain': dom, 'value': v})
                intel['all_ids'].append({'domain': dom, 'type': k, 'value': v})
    return intel


def audience_targeting(summary) -> Dict[str, Any]:
    categories = []
    roles = summary.get('roles', {})
    if roles.get('b2b_social', 0) + roles.get('abm', 0) >= 2:
        categories.append('B2B_focus')
    if roles.get('ad', 0) >= 2 and roles.get('tag_manager', 0) >= 1:
        categories.append('Marketing_optimized')
    if roles.get('identity', 0) >= 1:
        categories.append('Identity_graph_leverage')
    if not categories:
        categories.append('Unclear')
    return {'categories': categories, 'evidence_roles': roles}


def write_outputs(case_dir: Path, behav, intel, aud):
    """Reject the former in-place writer before inspecting its arguments."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved request logs, case files and prior outputs are preserved. '
               'Standalone tracker publication requires a separate source/output '
               'admission and versioning contract; no case files are accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
