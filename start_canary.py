#!/usr/bin/env python3
"""Legacy launcher: explicit arguments and the canonical canary status."""
from pathlib import Path
import sys


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from paw.canary.server import main as canary_main
    canary_main()


if __name__ == '__main__':
    main()
