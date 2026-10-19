#!/usr/bin/env python3
"""Legacy kit case publication is unavailable; saved sources and outputs are preserved.

Internal prototype scanners/interpretations remain unvalidated. The separately
tested package kit analyzer provides supplied static observations.
"""
from __future__ import annotations
import argparse
import base64
import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


UNAVAILABLE = ('Legacy kit publication unavailable: saved case '
               'sources and prior outputs are preserved')


URL_RE = re.compile(r"https?://[\w\-._~%:/?#\[\]@!$&'()*+,;=]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def safe_read_text(p: Path, max_bytes: int = 1024 * 1024) -> str:
    try:
        data = p.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def b64_candidates(text: str) -> list[str]:
    cands = []
    for m in BASE64_RE.finditer(text):
        s = m.group(0)
        # Heuristic: length multiple of 4 and decodes to mostly printable
        if len(s) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(s, validate=False)
            if not raw:
                continue
            ascii_ratio = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw)
            if ascii_ratio >= 0.85:
                cands.append(raw.decode("utf-8", errors="replace"))
        except Exception:
            continue
    return cands


def extract_indicators(text: str) -> dict[str, set[str]]:
    inds: dict[str, set[str]] = {
        "url": set(),
        "domain": set(),
        "ip": set(),
        "email": set(),
    }
    for u in URL_RE.findall(text):
        inds["url"].add(unquote(u))
    for d in DOMAIN_RE.findall(text):
        # Heuristics to reduce code-token noise: must be lowercase and not end with a dot
        if d.endswith("."):
            continue
        if d.lower() != d:
            continue
        inds["domain"].add(d)
    for ip in IP_RE.findall(text):
        # filter out obviously invalid octets >255
        try:
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                inds["ip"].add(ip)
        except Exception:
            pass
    for em in EMAIL_RE.findall(text):
        inds["email"].add(em)
    return inds


def scan_case(case_dir: Path) -> tuple[list[dict], dict]:
    kit_dir = case_dir / "detonation" / "phishing_kit"
    results: list[dict] = []
    graph = {"nodes": {}, "edges": []}  # nodes: id->{label,type}

    def add_node(node_id: str, label: str, ntype: str):
        graph["nodes"].setdefault(node_id, {"label": label, "type": ntype})

    def add_edge(src: str, dst: str, etype: str):
        graph["edges"].append({"from": src, "to": dst, "type": etype})

    # Scan kit files
    if kit_dir.exists():
        for p in kit_dir.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(case_dir))
            text = safe_read_text(p)
            if not text:
                continue
            inds = extract_indicators(text)
            decoded_texts = b64_candidates(text)
            for dt in decoded_texts:
                di = extract_indicators(dt)
                for k, vs in di.items():
                    inds[k].update(vs)

            # record indicators
            if any(inds.values()):
                add_node(rel, rel, "file")
            for typ, vals in inds.items():
                for v in sorted(vals):
                    results.append({"type": typ, "value": v, "file": rel, "context": "kit"})
                    node_id = f"{typ}:{v}"
                    add_node(node_id, v, typ)
                    add_edge(rel, node_id, "mentions")

    # input.eml
    eml = case_dir / "input.eml"
    if eml.exists():
        text = safe_read_text(eml)
        inds = extract_indicators(text)
        if any(inds.values()):
            rel = str(eml.relative_to(case_dir))
            add_node(rel, rel, "file")
            for typ, vals in inds.items():
                for v in sorted(vals):
                    results.append({"type": typ, "value": v, "file": rel, "context": "eml"})
                    node_id = f"{typ}:{v}"
                    add_node(node_id, v, typ)
                    add_edge(rel, node_id, "mentions")

    # deobfuscation_results.json
    deob = case_dir / "deobfuscation_results.json"
    if deob.exists():
        try:
            data = json.loads(safe_read_text(deob))
            blob = json.dumps(data)
            inds = extract_indicators(blob)
            rel = str(deob.relative_to(case_dir))
            if any(inds.values()):
                add_node(rel, rel, "file")
                for typ, vals in inds.items():
                    for v in sorted(vals):
                        results.append({"type": typ, "value": v, "file": rel, "context": "deob"})
                        node_id = f"{typ}:{v}"
                        add_node(node_id, v, typ)
                        add_edge(rel, node_id, "mentions")
        except Exception:
            pass

    return results, graph


def write_outputs(case_dir: Path, indicators: list[dict], graph: dict):
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


if __name__ == "__main__":
    raise SystemExit(main())
