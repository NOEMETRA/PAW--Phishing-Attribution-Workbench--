#!/usr/bin/env python3
"""Legacy tracker case publication is unavailable; saved sources and outputs are preserved.

Internal prototype readers/interpretations remain unvalidated. The separately
tested package tracker extractor provides supplied static observations.
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs


UNAVAILABLE = ('Standalone tracker publication unavailable: saved case '
               'sources and prior outputs are preserved')


TRACKER_PATTERNS = [
    (re.compile(r"(^|\.)px\.ads\.linkedin\.com$"), "linkedin"),
    (re.compile(r"(^|\.)snap\.licdn\.com$"), "linkedin"),
    (re.compile(r"(^|\.)demdex\.net$"), "adobe_demdex"),
    (re.compile(r"(^|\.)assets\.adobedtm\.com$"), "adobe_launch"),
    (re.compile(r"(^|\.)doubleclick\.net$|(^|\.)g\.doubleclick\.net$"), "google_doubleclick"),
    (re.compile(r"(^|\.)rlcdn\.com$"), "live_ramp"),
    (re.compile(r"(^|\.)demandbase\.com$|(^|\.)company-target\.com$"), "demandbase"),
    (re.compile(r"(^|\.)cookielaw\.org$|(^|\.)onetrust\.com$"), "onetrust"),
    (re.compile(r"(^|\.)datadoghq\.(com|eu)$"), "datadog"),
    (re.compile(r"(^|\.)tremorhub\.com$"), "tremor"),
    (re.compile(r"(^|\.)rubiconproject\.com$"), "rubicon"),
    (re.compile(r"(^|\.)eyeota\.net$"), "eyeota"),
    (re.compile(r"(^|\.)pardot\.com$"), "pardot"),
    (re.compile(r"(^|\.)googletagmanager\.com$|(^|\.)gtm\.js$"), "gtm"),
]

ID_KEYS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "msclkid", "li_fat_id", "pid", "orgid", "tuuid", "d_uuid"}


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def classify_tracker(host: str) -> str | None:
    for pat, label in TRACKER_PATTERNS:
        if pat.search(host):
            return label
    return None


def analyze(case_dir: Path):
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


if __name__ == "__main__":
    raise SystemExit(main())
