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
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any

UNAVAILABLE = 'Legacy conclusion publication unavailable: saved case sources and prior outputs are preserved'


@dataclass
class AttributionEvidence:
    evidence_type: str
    confidence: float
    scientific_basis: str
    cross_reference: List[str]
    reproducibility_score: float


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def analyze_linguistic_fingerprint(kit_dir: Path) -> List[AttributionEvidence]:
    ev: List[AttributionEvidence] = []
    tokens = {'colour', 'behaviour', 'optimise'}  # en-GB markers
    matches = []
    for p in kit_dir.rglob('*') if kit_dir.exists() else []:
        if p.is_file() and p.suffix.lower() in {'.js', '.html', '.css'}:
            try:
                t = p.read_text(encoding='utf-8', errors='replace').lower()
            except Exception:
                continue
            if any(tok in t for tok in tokens):
                matches.append(str(p))
    if matches:
        ev.append(AttributionEvidence(
            evidence_type='linguistic_fingerprint',
            confidence=0.55,
            scientific_basis='Presence of en-GB lexical markers across kit files',
            cross_reference=matches[:10],
            reproducibility_score=0.85
        ))
    return ev


def analyze_code_style(kit_dir: Path) -> List[AttributionEvidence]:
    ev: List[AttributionEvidence] = []
    camel_case = 0
    snake_case = 0
    minified = 0
    files = 0
    for p in kit_dir.rglob('*.js') if kit_dir.exists() else []:
        files += 1
        try:
            t = p.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        if len(t) > 20000 and '\n' not in t[:2000]:
            minified += 1
        camel_case += len(re.findall(r'[a-z]+[A-Z][a-zA-Z0-9]*', t))
        snake_case += len(re.findall(r'[a-z]+_[a-z0-9]+', t))
    if files:
        style = 'minified_bias' if minified / files > 0.5 else 'mixed'
        ev.append(AttributionEvidence(
            evidence_type='code_style_dna',
            confidence=0.6 if style == 'minified_bias' else 0.45,
            scientific_basis=f'JS minification ratio {minified}/{files}; camelCase vs snake_case balance',
            cross_reference=[f'{minified} minified of {files} files', f'camel:{camel_case}', f'snake:{snake_case}'],
            reproducibility_score=0.9
        ))
    return ev


def analyze_infrastructure_dna(derived_dir: Path) -> List[AttributionEvidence]:
    ev: List[AttributionEvidence] = []
    ttp = load_json(derived_dir / 'ttp_analysis.json', [])
    cf = load_json(derived_dir / 'criminal_fingerprint.json', {})
    if any(x.get('technique_id') == 'T1059.007' for x in ttp):
        ev.append(AttributionEvidence(
            evidence_type='ttp_profile',
            confidence=0.5,
            scientific_basis='Use of extensive JavaScript instrumentation consistent with known campaigns',
            cross_reference=['T1059.007', 'T1071.001', 'T1573'],
            reproducibility_score=0.88
        ))
    if cf.get('c2_protocols_detected'):
        ev.append(AttributionEvidence(
            evidence_type='c2_behaviour',
            confidence=0.4,
            scientific_basis='Possible C2-like indicators present in static kit',
            cross_reference=[str(x) for x in cf.get('c2_protocols_detected', [])[:5]],
            reproducibility_score=0.8
        ))
    return ev


def confidence_matrix(evidences: List[AttributionEvidence]) -> Dict[str, Any]:
    """Unavailable pending sourced, validated capability and publication contracts."""
    raise RuntimeError(UNAVAILABLE)


def evidence_chain(case_dir: Path) -> Dict[str, Any]:
    derived = case_dir / 'derived'
    files = [
        'dossier.json', 'ttp_analysis.json', 'criminal_fingerprint.json', 'deobfuscation_cascade.json'
    ]
    blocks = []
    for i, name in enumerate(files):
        p = derived / name
        try:
            size = p.stat().st_size
        except Exception:
            size = 0
        blocks.append({'index': i, 'file': str(p), 'size': size})
    return {'chain': blocks, 'note': 'Logical chain for human-verifiable provenance (no external trust)'}


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
