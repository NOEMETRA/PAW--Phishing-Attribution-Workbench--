#!/usr/bin/env python3
"""Legacy host/IP/ASN case publication is unavailable; saved sources and outputs are preserved.

Internal prototype readers/heuristics remain unvalidated. No lookup or source
conversion is performed by these unavailable publication entry points.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path


UNAVAILABLE = ('Legacy host/IP/ASN publication unavailable: saved case '
               'sources and prior outputs are preserved')


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_ip_index(hunt_enrichments: list[dict]) -> dict[str, dict]:
    idx = {}
    for entry in hunt_enrichments:
        ip = entry.get("ip")
        if not ip:
            continue
        idx[ip] = entry
    return idx


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Legacy host/IP/ASN '
               'publication requires source/output admission and versioning; '
               'no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.add_argument('--out', help='Legacy output path; no file will be created or overwritten')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == "__main__":
    raise SystemExit(main())
