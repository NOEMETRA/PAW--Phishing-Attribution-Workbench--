"""Legacy standalone IP analysis is unavailable; saved Sentinel data are preserved."""
import argparse

UNAVAILABLE = ('Legacy standalone IP analysis unavailable: saved Sentinel data '
               'are preserved')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, allow_abbrev=False,
        epilog='Use check_victims.py for passive saved-row inspection. '
               'Active IP collection and updates require separately validated '
               'isolation, supervision and source/result semantics.')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == '__main__':
    main()
