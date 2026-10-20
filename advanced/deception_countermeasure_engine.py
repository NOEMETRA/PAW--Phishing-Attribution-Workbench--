#!/usr/bin/env python3
"""Legacy conclusion prototype: publication and principal APIs are unavailable.

Saved sources and prior outputs are preserved. Remaining helper algorithms are
unvalidated research code, not supported attribution, deployment or provenance
verification. See docs/legacy-conclusion-publication.md for the exact boundary.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Any

UNAVAILABLE = 'Legacy conclusion publication unavailable: saved case sources and prior outputs are preserved'


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def load_hosts(case_dir: Path) -> List[Dict[str, Any]]:
    src = case_dir / 'derived' / 'threat_intel_enriched.csv'
    rows: List[Dict[str, Any]] = []
    if not src.exists():
        return rows
    with src.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    return rows


def create_honeytokens(profile: Dict[str, Any], case_dir: Path) -> List[Dict[str, Any]]:
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def design_deception_network(hosts: List[Dict[str, Any]], case_dir: Path) -> Dict[str, Any]:
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def counter_intel_ops(behav: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def adversary_manipulation() -> Dict[str, Any]:
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def write_outputs(case_dir: Path, tokens, net, ops, manip):
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Attribution, '
               'countermeasures and dossier publication need validated source '
               'and publication contracts; no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
