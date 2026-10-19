#!/usr/bin/env python3
"""Legacy host/IP/ASN case publication is unavailable; saved sources and outputs are preserved.

Internal prototype readers/heuristics remain unvalidated. No lookup or source
conversion is performed by these unavailable publication entry points.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Any, List


UNAVAILABLE = ('Legacy host/IP/ASN publication unavailable: saved case '
               'sources and prior outputs are preserved')


CDN_ASNS = {
    '13335': 'Cloudflare',
    '15169': 'Google',
    '14618': 'AWS',
    '16509': 'AWS',
    '8075': 'Microsoft',
    '32934': 'Facebook',
}

BRAND_TOKENS = [
    'microsoft', 'office', 'o365', 'paypal', 'apple', 'google', 'facebook', 'poste', 'banque',
    'bank', 'login', 'secure', 'verification', 'verify', 'update', 'password', 'support'
]


def provider_type(asn: str, org: str) -> str:
    if asn in CDN_ASNS:
        return f"cdn:{CDN_ASNS[asn]}"
    if org:
        orgl = org.lower()
        if 'cloud' in orgl or 'hosting' in orgl or 'vps' in orgl:
            return 'cloud/hosting'
    return 'unknown'


def compute_risk(row: Dict[str, str]) -> Dict[str, Any]:
    score = 0
    notes: List[str] = []

    http_block = (row.get('http_block') or '').lower()
    http_status = row.get('http_status') or ''
    host = (row.get('host') or '').lower()
    asn = (row.get('asn') or '')
    org = row.get('org') or row.get('organization') or ''

    if 'waf_cloudflare_403' in http_block or 'waf_cloudfront_403' in http_block:
        score += 2
        notes.append('provider_waf_block_403')
    if 'legal_denied_451' in http_block or http_status == '451':
        score += 3
        notes.append('legal_denied_451')
    if any(tok in host for tok in BRAND_TOKENS):
        score += 1
        notes.append('brandlike_host_token')

    ptype = provider_type(asn, org)
    if ptype.startswith('cdn:'):
        notes.append('via_cdn_visibility_limited')

    level = 'LOW'
    if score >= 5:
        level = 'HIGH'
    elif score >= 3:
        level = 'MEDIUM'

    return {'risk_score': score, 'risk_level': level, 'notes': ';'.join(notes), 'provider_type': ptype}


def enrich(case_dir: Path) -> Dict[str, Any]:
    """Reject the former case writer before inspecting its argument."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Legacy host/IP/ASN '
               'publication requires source/output admission and versioning; '
               'no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
