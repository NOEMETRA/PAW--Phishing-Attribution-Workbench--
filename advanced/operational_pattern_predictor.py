#!/usr/bin/env python3
"""Legacy operational prediction is unavailable; saved sources and outputs are preserved.

Internal prototype helpers remain unvalidated and are not a predictive model.
No actor forecast, calibrated confidence or intervention recommendation is supported.
"""
from __future__ import annotations
import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Dict, List, Any, Tuple


UNAVAILABLE = ('Legacy operational prediction unavailable: saved case '
               'sources and prior outputs are preserved')


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def load_enriched_hosts(case_dir: Path) -> List[Dict[str, Any]]:
    src = case_dir / 'derived' / 'threat_intel_enriched.csv'
    rows: List[Dict[str, Any]] = []
    if not src.exists():
        return rows
    with src.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def asn_diversity(rows: List[Dict[str, Any]]) -> int:
    return len({(r.get('asn') or '').strip() for r in rows if r.get('asn')})


def avg_risk(rows: List[Dict[str, Any]]) -> float:
    vals: List[float] = []
    for r in rows:
        try:
            score = float(r.get('risk_score') or 0.0)
        except Exception:
            score = 0.0
        vals.append(score)
    if not vals:
        return 0.0
    # Normalize by a conservative max 6.0 (from our heuristics range)
    return min(sum(vals) / len(vals) / 6.0, 1.0)


def classify_actor(rows: List[Dict[str, Any]]) -> str:
    diversity = asn_diversity(rows)
    risk = avg_risk(rows)
    if diversity > 3 and risk > 0.7:
        return 'bulletproof_rotation'
    if diversity <= 2 and risk > 0.5:
        return 'apt_stealth'
    return 'unknown_organized'


def rotation_schedule(actor: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if actor == 'bulletproof_rotation':
        days_pattern = [7, 14, 30]
    elif actor == 'apt_stealth':
        days_pattern = [30, 60, 90]
    else:
        days_pattern = [30]

    current_asns = sorted({(r.get('asn') or '').strip() for r in rows if r.get('asn')})
    base_conf = 0.8 if actor != 'unknown_organized' else 0.6
    out = []
    for i, d in enumerate(days_pattern):
        when = datetime.now(UTC) + timedelta(days=d)
        out.append({
            'predicted_rotation_date': when.isoformat(),
            'days_from_now': d,
            'likely_new_asns': predict_new_asns(current_asns),
            'rotation_confidence': max(base_conf - i * 0.15, 0.3)
        })
    return out


def predict_new_asns(current_asns: List[str]) -> List[str]:
    # Heuristic migration paths (offline, generic)
    common = {
        '13335': ['16509', '15169'],  # Cloudflare -> AWS/Google
        '16509': ['13335', '8075'],   # AWS -> Cloudflare/Microsoft
        '8075': ['13335', '16509'],   # Microsoft -> Cloudflare/AWS
    }
    pred: List[str] = []
    for asn in current_asns:
        pred.extend(common.get(asn, []))
    return sorted(set(pred))


def likely_new_providers(rows: List[Dict[str, Any]]) -> List[str]:
    orgs = {(r.get('org') or r.get('organization') or '').lower() for r in rows}
    hints = []
    if any('cloudflare' in o for o in orgs):
        hints += ['AWS', 'Google Cloud']
    if any('amazon' in o or 'aws' in o for o in orgs):
        hints += ['Cloudflare', 'Microsoft']
    if any('microsoft' in o for o in orgs):
        hints += ['Cloudflare', 'AWS']
    return sorted(set(hints)) or ['Cloud/Hosting (generic)']


def expansion_probability(rows: List[Dict[str, Any]]) -> float:
    # More domains + waf blocks indicates likely expansion/pivot attempts
    domains = {(r.get('host') or '').split(':')[0] for r in rows}
    waf = sum(1 for r in rows if 'waf_' in (r.get('http_block') or '').lower())
    base = min(len(domains) / 50.0, 1.0)
    bonus = min(waf / 100.0, 0.2)
    return round(min(base + bonus, 1.0), 2)


def takedown_resistance(rows: List[Dict[str, Any]]) -> str:
    # CDN usage and WAF blocks increase resistance
    cdn = sum(1 for r in rows if (r.get('provider_type') or '').startswith('cdn:'))
    waf = sum(1 for r in rows if 'waf_' in (r.get('http_block') or '').lower())
    score = 0
    if cdn > 0:
        score += 2
    if waf > 0:
        score += 1
    return 'HIGH' if score >= 3 else 'MEDIUM' if score == 2 else 'LOW'


def build_evolution(case_dir: Path) -> Dict[str, Any]:
    """Unavailable before inspecting prediction/publication inputs."""
    raise RuntimeError(UNAVAILABLE)


def build_actor_timeline(case_dir: Path) -> List[Dict[str, Any]]:
    """Unavailable before inspecting prediction/publication inputs."""
    raise RuntimeError(UNAVAILABLE)


def predict_targets(case_dir: Path) -> Dict[str, Any]:
    """Unavailable before inspecting prediction/publication inputs."""
    raise RuntimeError(UNAVAILABLE)


def countermeasure_effectiveness(case_dir: Path) -> Dict[str, Any]:
    """Unavailable before inspecting prediction/publication inputs."""
    raise RuntimeError(UNAVAILABLE)


def write_outputs(case_dir: Path, evolution: Dict[str, Any], timeline: List[Dict[str, Any]], targets: Dict[str, Any], cm: Dict[str, Any]):
    """Unavailable before inspecting prediction/publication inputs."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Operational '
               'prediction needs independently validated evidence/model and '
               'versioned publication; no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
