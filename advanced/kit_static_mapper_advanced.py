#!/usr/bin/env python3
"""Legacy kit case publication is unavailable; saved sources and outputs are preserved.

Internal prototype scanners/interpretations remain unvalidated. The separately
tested package kit analyzer provides supplied static observations.
"""
from __future__ import annotations
import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Set
from urllib.parse import unquote


UNAVAILABLE = ('Legacy kit publication unavailable: saved case '
               'sources and prior outputs are preserved')


# Patterns
CRYPTO_PATTERNS = {
    'bitcoin': re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'),
    'ethereum': re.compile(r'0x[a-fA-F0-9]{40}'),
    'monero': re.compile(r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}'),
    'litecoin': re.compile(r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}'),
}

DARK_WEB_PATTERNS = {
    'onion': re.compile(r'\b[a-z2-7]{16,56}\.onion\b'),
    'i2p': re.compile(r'\b[a-z0-9]{52}\.i2p\b'),
}

C2_PROTOCOLS = {
    'beacon': re.compile(r'\bsetTimeout\b|\bsetInterval\b|\bsetImmediate\b', re.I),
    'dns_tunnel': re.compile(r'String\.fromCharCode.*substr.*split', re.I),
    'webhook': re.compile(r'discord\.com/api/webhooks|webhook\.office|slack\.com', re.I),
    'telegram_bot': re.compile(r'api\.telegram\.org/bot[0-9]{8,10}', re.I),
    'pastebin': re.compile(r'pastebin\.com/raw/[a-zA-Z0-9]{8}', re.I),
}

URL_RE = re.compile(r"https?://[\w\-._~%:/?#\[\]@!$&'()*+,;=]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b([a-z0-9-]{1,63}\.)+[a-z]{2,24}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
BASE64_CANDIDATE_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def safe_read_text(p: Path, max_bytes: int = 1024 * 1024) -> str:
    try:
        data = p.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


class AdvancedDeobfuscator:
    @staticmethod
    def xor_decrypt_bytes(data: bytes, keys: List[int]) -> List[str]:
        outs: List[str] = []
        for k in keys:
            try:
                dec = bytes(b ^ k for b in data)
                # Heuristic printable ratio
                printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in dec)
                if printable / max(len(dec), 1) > 0.7:
                    outs.append(dec.decode('utf-8', errors='ignore'))
            except Exception:
                continue
        return outs

    @staticmethod
    def recursive_base64_decode(text: str, max_depth: int = 5) -> List[str]:
        outs: List[str] = []
        current = text
        for depth in range(max_depth):
            try:
                decoded = base64.b64decode(current).decode('utf-8', errors='ignore')
                outs.append(f"depth_{depth}:{decoded[:2000]}")
                current = decoded
            except Exception:
                break
        return outs

    @staticmethod
    def decode_embedded_base64(text: str) -> List[str]:
        outs: List[str] = []
        for m in BASE64_CANDIDATE_RE.finditer(text):
            s = m.group(0)
            try:
                raw = base64.b64decode(s, validate=False)
                ascii_ratio = sum(32 <= b < 127 or b in (9,10,13) for b in raw) / max(len(raw),1)
                if ascii_ratio >= 0.85:
                    outs.append(raw.decode('utf-8', errors='ignore'))
            except Exception:
                continue
        return outs

    @staticmethod
    def decode_string_concats(text: str) -> List[str]:
        outs: List[str] = []
        # 'a' + 'b' -> ab (no eval)
        concat_re = re.compile(r"(['\"][^'\"]*['\"]\s*\+\s*)+['\"][^'\"]*['\"]")
        for m in concat_re.finditer(text):
            chunk = m.group(0)
            parts = [p.strip() for p in re.split(r"\+", chunk)]
            norm = ''.join(p.strip()[1:-1] if len(p.strip())>=2 and p.strip()[0] in ('"', "'") and p.strip()[-1]==p.strip()[0] else p for p in parts)
            outs.append(norm[:2000])

        # String.fromCharCode(....)
        for m in re.finditer(r'String\.fromCharCode\s*\(([^)]+)\)', text):
            try:
                codes = [int(x.strip()) for x in m.group(1).split(',') if x.strip().isdigit()]
                outs.append(''.join(chr(c) for c in codes))
            except Exception:
                pass
        # atob("...")
        for m in re.finditer(r'atob\(["\']([^"\']+)["\']\)', text):
            try:
                outs.append(base64.b64decode(m.group(1)).decode('utf-8', errors='ignore'))
            except Exception:
                pass
        # decodeURIComponent("...")
        for m in re.finditer(r'decodeURIComponent\(["\']([^"\']+)["\']\)', text):
            try:
                outs.append(unquote(m.group(1)))
            except Exception:
                pass
        return outs


def extract_indicators(text: str) -> Dict[str, Set[str]]:
    inds: Dict[str, Set[str]] = {"urls": set(), "domains": set(), "ips": set(), "emails": set()}
    for u in URL_RE.findall(text):
        inds["urls"].add(unquote(u))
    for d in DOMAIN_RE.findall(text.lower()):
        if d.endswith('.'):
            continue
        inds["domains"].add(d)
    for ip in IP_RE.findall(text):
        try:
            if all(0 <= int(o) <= 255 for o in ip.split('.')):
                inds["ips"].add(ip)
        except Exception:
            pass
    for em in EMAIL_RE.findall(text):
        inds["emails"].add(em)
    return inds


def map_to_mitre(artifacts: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    t: List[Dict[str, Any]] = []
    files = artifacts.get('files', [])
    urls = artifacts.get('urls', [])

    if any(s.endswith('.js') for s in files):
        t.append({
            'technique_id': 'T1059.007',
            'technique_name': 'Command and Scripting Interpreter: JavaScript',
            'confidence': 0.9,
            'artifacts': [f for f in files if f.endswith('.js')][:10]
        })
    if urls:
        t.append({
            'technique_id': 'T1071.001',
            'technique_name': 'Application Layer Protocol: Web Protocols',
            'confidence': 0.7,
            'artifacts': urls[:10]
        })
    if any(u.lower().startswith('https://') for u in urls):
        t.append({
            'technique_id': 'T1573',
            'technique_name': 'Encrypted Channel',
            'confidence': 0.6,
            'artifacts': [u for u in urls if u.lower().startswith('https://')][:10]
        })
    return t


def analyze_criminal_infra(artifacts: Dict[str, List[str]]) -> Dict[str, Any]:
    analysis = {
        'bulletproof_hosting_indicators': [],
        'dark_web_infrastructure': [],
        'cryptocurrency_operations': [],
        'c2_protocols_detected': [],
        'threat_actor_confidence': 0.0,
    }

    def scan_str(s: str):
        for name, pat in DARK_WEB_PATTERNS.items():
            if pat.search(s):
                analysis['dark_web_infrastructure'].append({'type': name, 'artifact': s[:200]})
        for name, pat in CRYPTO_PATTERNS.items():
            m = pat.search(s)
            if m:
                analysis['cryptocurrency_operations'].append({'type': name, 'address': m.group(0)})
        for name, pat in C2_PROTOCOLS.items():
            if pat.search(s):
                analysis['c2_protocols_detected'].append({'protocol': name, 'evidence': s[:150]})

    for k, vals in artifacts.items():
        if isinstance(vals, list):
            for v in vals:
                scan_str(str(v))

    indicators = len(analysis['dark_web_infrastructure']) + len(analysis['cryptocurrency_operations']) + len(analysis['c2_protocols_detected'])
    analysis['threat_actor_confidence'] = min(indicators * 0.2, 1.0)
    return analysis


def sophistication_level(deob_chains: List[Dict], criminal: Dict, ttp: List[Dict]) -> str:
    score = 0
    if deob_chains:
        score += 2
    if criminal.get('dark_web_infrastructure'):
        score += 3
    if criminal.get('cryptocurrency_operations'):
        score += 1
    if len(ttp) > 2:
        score += 2
    if score >= 5:
        return 'HIGH'
    if score >= 3:
        return 'MEDIUM'
    return 'LOW'


def scan_case(case_dir: Path) -> Dict[str, Any]:
    kit_dir = case_dir / 'detonation' / 'phishing_kit'
    artifacts: Dict[str, List[str]] = {'urls': [], 'domains': [], 'ips': [], 'emails': [], 'files': []}
    deobfuscation_chains: List[Dict[str, Any]] = []

    dec = AdvancedDeobfuscator()

    def add_inds(inds: Dict[str, Set[str]]):
        for k, s in inds.items():
            if k == 'urls':
                artifacts['urls'].extend(sorted(s))
            elif k == 'domains':
                artifacts['domains'].extend(sorted(s))
            elif k == 'ips':
                artifacts['ips'].extend(sorted(s))
            elif k == 'emails':
                artifacts['emails'].extend(sorted(s))

    if kit_dir.exists():
        for p in kit_dir.rglob('*'):
            if not p.is_file():
                continue
            rel = str(p.relative_to(case_dir))
            artifacts['files'].append(rel)
            text = safe_read_text(p)
            if not text:
                continue
            # Indicators in file
            add_inds(extract_indicators(text))
            # Embedded b64 and simple concat decodes
            decoded_blobs = []
            decoded_blobs += dec.decode_embedded_base64(text)
            decoded_blobs += dec.decode_string_concats(text)
            # XOR against a few keys on raw bytes
            try:
                decoded_blobs += dec.xor_decrypt_bytes(text.encode('utf-8', errors='ignore'), [0xAA, 0x55, 0x13, 0x37])
            except Exception:
                pass
            # If any decode yielded text, record chain and extract indicators
            if decoded_blobs:
                deobfuscation_chains.append({'file': rel, 'decodes': [b[:500] for b in decoded_blobs[:10]]})
                for blob in decoded_blobs:
                    add_inds(extract_indicators(blob))

    # Optional additional sources
    for optional in (case_dir / 'deobfuscation_results.json', case_dir / 'input.eml') ,:
        pass  # kept minimal to avoid double counting; base tools already parse them

    # Deduplicate
    for k in ('urls','domains','ips','emails','files'):
        artifacts[k] = sorted(dict.fromkeys(artifacts[k]))

    ttp = map_to_mitre(artifacts)
    criminal = analyze_criminal_infra(artifacts)
    threat_actor = {
        'sophistication_level': sophistication_level(deobfuscation_chains, criminal, ttp),
        'infrastructure_scale': (
            'LARGE' if len(artifacts['domains']) + len(artifacts['ips']) > 20 else
            'MEDIUM' if len(artifacts['domains']) + len(artifacts['ips']) > 8 else 'SMALL'
        ),
        'attribution_clues': []
    }

    return {
        'artifacts': artifacts,
        'deobfuscation_chains': deobfuscation_chains,
        'ttp_analysis': ttp,
        'criminal_infrastructure': criminal,
        'threat_actor_profile': threat_actor,
    }


def write_outputs(case_dir: Path, res: Dict[str, Any]):
    """Reject the former case writer before inspecting any argument."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved kit sources, case files and prior outputs are preserved. '
               'Legacy kit publication requires source/output admission and '
               'versioning; no case files are accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
