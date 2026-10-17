#!/usr/bin/env python3
"""Legacy abuse-template generation is unavailable; case evidence is preserved."""
import argparse


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Use paw full INPUT --no-egress to create a separate analysis case '
               'with local, unsent review drafts. A draft does not establish abuse.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.parse_args(argv)
    parser.exit(1, 'Legacy abuse-template generation unavailable: use supervised '
                   'analysis review drafts; existing case evidence is preserved\n')


if __name__ == '__main__':
    main()
