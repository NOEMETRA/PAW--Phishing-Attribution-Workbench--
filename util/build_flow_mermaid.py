#!/usr/bin/env python3
"""Standalone request-flow publication is unavailable; saved case evidence is preserved."""
import argparse

UNAVAILABLE = ('Standalone request-flow publication unavailable: existing case '
               'evidence and request logs are preserved')


def build(case_dir):
    """Reject the former in-place writer before inspecting its path argument."""
    raise RuntimeError(UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Preserve saved detonation/requests.jsonl and existing case outputs. '
               'Standalone request-flow publication needs a separate validated '
               'source/output and versioning contract.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == "__main__":
    main()
