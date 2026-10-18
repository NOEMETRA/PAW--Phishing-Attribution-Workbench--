#!/usr/bin/env python3
"""Prototype forensic proof publication is unavailable; saved case evidence is preserved."""
import argparse

UNAVAILABLE = ('Prototype forensic proof publication unavailable: saved case '
               'evidence and prior outputs are preserved')


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
