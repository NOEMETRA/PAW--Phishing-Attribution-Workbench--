"""Legacy checkout launcher for supervised, offline full email analysis.

Usage: python tools/analyze_inbox.py INPUT [full-command options]
INPUT must be an explicit EML/MSG path or directory. Network access is disabled.
"""
from pathlib import Path
import sys


def main():
    # Direct execution from tools/ must work without a host PYTHONPATH or install.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from paw.__main__ import main as cli_main

    sys.argv = ['paw', 'full', '--no-egress', *sys.argv[1:]]
    cli_main()


if __name__ == '__main__':
    main()
