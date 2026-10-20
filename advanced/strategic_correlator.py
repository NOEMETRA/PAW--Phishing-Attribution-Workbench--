#!/usr/bin/env python3
"""Legacy conclusion prototype: publication and principal APIs are unavailable.

Saved sources and prior outputs are preserved. Remaining helper algorithms are
unvalidated research code, not supported attribution, deployment or provenance
verification. See docs/legacy-conclusion-publication.md for the exact boundary.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

UNAVAILABLE = 'Legacy conclusion publication unavailable: saved case sources and prior outputs are preserved'


def read_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def earliest_request(case_dir: Path) -> Dict[str, Any]:
    req = case_dir / 'detonation' / 'requests.jsonl'
    earliest = None
    if not req.exists():
        return {'note': 'requests.jsonl missing'}
    try:
        with req.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ts = obj.get('ts') or obj.get('time') or obj.get('timestamp')
                if earliest is None or (ts and str(ts) < str(earliest.get('ts'))):
                    earliest = obj
    except Exception:
        pass
    return earliest or {'note': 'no parsable entries'}


def find_place_signals(case_dir: Path) -> List[Dict[str, Any]]:
    # Backwards-compatible placeholder.
    # Historically this code attempted to surface country-specific tokens.
    # That hard-coded approach is incorrect for a global forensic pipeline.
    # Keep compatibility: this function now delegates to the general place-mention
    # extractor when called explicitly by newer logic. By default it returns an
    # empty list so older runs remain unchanged.
    return []


def load_place_tokens(tokens_path: Path) -> Union[List[str], Dict[str, str]]:
    """Load place tokens from a JSON file.

    Accepts either a list of tokens (e.g. ["city_name", "country_name"]) or a map
    token->country (e.g. {"city_name": "COUNTRY_CODE"}). This function does not
    perform attribution; it only provides tokens used for extraction.
    """
    if not tokens_path or not tokens_path.exists():
        return []
    try:
        data = json.loads(tokens_path.read_text(encoding='utf-8'))
        if isinstance(data, dict) or isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def find_place_mentions(case_dir: Path, tokens: Union[List[str], Dict[str, str]]) -> List[Dict[str, Any]]:
    """Search case detonation artifacts for mentions of place tokens.

    This function only extracts textual mentions and records file/offset
    context. It does NOT perform automatic country attribution. If a tokens
    mapping is provided (token->country) the mapping is returned alongside the
    mention as a suggestion for manual review.
    """
    if not tokens:
        return []
    # normalize tokens to list and lowercase
    mapping: Dict[str, str] = {}
    token_list: List[str] = []
    if isinstance(tokens, dict):
        mapping = {k.lower(): v for k, v in tokens.items()}
        token_list = list(mapping.keys())
    else:
        token_list = [t.lower() for t in tokens]

    det_dir = case_dir / 'detonation'
    mentions: List[Dict[str, Any]] = []
    if not det_dir.exists():
        return mentions

    # walk text files and search for tokens (case-insensitive, word boundaries)
    for p in det_dir.rglob('*'):
        if p.is_file():
            try:
                text = p.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            lower = text.lower()
            for token in token_list:
                if not token:
                    continue
                # simple whole-word search
                if re.search(r"\b" + re.escape(token) + r"\b", lower, flags=re.I):
                    # capture a short snippet for context
                    m = re.search(r"(.{0,60}" + re.escape(token) + r".{0,60})", lower, flags=re.I)
                    snippet = m.group(1) if m else ''
                    # count simple occurrences in this file for basic heuristics
                    occ = lower.count(token)
                    mention: Dict[str, Any] = {
                        'token': token,
                        'file': str(p.relative_to(case_dir)),
                        'snippet': snippet,
                        'occurrence_count': occ,
                        'provenance': ['text_search'],
                    }
                    if token in mapping:
                        mention['suggested_country'] = mapping[token]
                        mention['suggestion_note'] = 'suggested by token->country mapping; requires manual review'
                        mention['provenance'].append('token_map')
                    mentions.append(mention)
    # post-process mentions to compute a lightweight confidence and add
    # multi-file / co-occurrence provenance hints.
    if mentions:
        # counts per token
        token_files: Dict[str, set] = {}
        token_total_occ: Dict[str, int] = {}
        for m in mentions:
            t = m['token']
            token_files.setdefault(t, set()).add(m['file'])
            token_total_occ[t] = token_total_occ.get(t, 0) + int(m.get('occurrence_count', 1))

        for m in mentions:
            t = m['token']
            files_count = len(token_files.get(t, []))
            total_occ = token_total_occ.get(t, 0)

            # base confidence: higher if token->country mapping exists
            base = 0.4 if (isinstance(tokens, dict) and t in mapping) else 0.15

            # heuristics: multi-file presence is a strong signal, multiple occurrences moderate
            conf = base
            if files_count >= 2:
                conf += 0.35
                if 'multi_file_cooccurrence' not in m['provenance']:
                    m['provenance'].append('multi_file_cooccurrence')
            elif total_occ >= 5:
                conf += 0.2
                if 'high_occurrence' not in m['provenance']:
                    m['provenance'].append('high_occurrence')

            # clamp and round
            conf = min(conf, 0.95)
            m['confidence'] = round(conf, 2)

    return mentions


def provider_blocks(summary_json: Path, enriched_csv: Path) -> Dict[str, Any]:
    # Prefer advanced report
    s = read_json(summary_json, {}) if summary_json.exists() else {}
    if s:
        return {
            'counts': s.get('provider_blocks', {}),
            'by_risk': s.get('by_risk', {}),
            'high_risk_examples': s.get('high_risk_examples', []),
            'note': 'from threat_assessment_report.json',
        }
    # Fallback minimal
    return {'note': 'no advanced report available'}


def build_dossier(case_dir: Path, enable_country_detection: bool = True, place_tokens_file: Optional[Path] = None) -> Dict[str, Any]:
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def write_markdown(case_dir: Path, dossier: Dict[str, Any]):
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Attribution, '
               'countermeasures and dossier publication need validated source '
               'and publication contracts; no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.add_argument('--disable-country-detection', action='store_true', help='Legacy flag; no extraction will run')
    parser.add_argument('--place-tokens-file', help='Legacy token path; no file will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
