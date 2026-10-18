#!/usr/bin/env python3
"""Prototype forensic proof publication is unavailable; saved case evidence is preserved."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Any


UNAVAILABLE = ('Prototype forensic proof publication unavailable: saved case '
               'evidence and prior outputs are preserved')


def sha3_512_hex(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()


def blake2b_hex(data: bytes) -> str:
    return hashlib.blake2b(data).hexdigest()


def file_hashes(p: Path) -> Dict[str, Any]:
    raise RuntimeError(UNAVAILABLE)


def quantum_safe_hashes(derived: Path) -> Dict[str, Any]:
    raise RuntimeError(UNAVAILABLE)


def calculate_block_hash(block: Dict[str, Any]) -> str:
    s = json.dumps(block, sort_keys=True).encode('utf-8')
    return sha3_512_hex(s)


def immutable_chain(derived: Path, hashes: Dict[str, Any]) -> Dict[str, Any]:
    raise RuntimeError(UNAVAILABLE)


def zero_knowledge_proofs(hashes: Dict[str, Any]) -> Dict[str, Any]:
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Original case files and prior outputs are preserved. '
               'Use the existing paw verify/export commands for case integrity; '
               'they do not establish cryptographic proofs or post-quantum guarantees.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
