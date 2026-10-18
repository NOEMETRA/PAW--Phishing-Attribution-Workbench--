#!/usr/bin/env python3
"""Legacy checkout alias for the passive `paw geographic report` command."""
import sys

def main():
    from paw.__main__ import main as cli_main

    sys.argv = ['paw', 'geographic', 'report', *sys.argv[1:]]
    cli_main()


if __name__ == '__main__':
    main()
