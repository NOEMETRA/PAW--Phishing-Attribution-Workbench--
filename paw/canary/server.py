"""Compatibility entry points for unavailable legacy canary deployment.

A live collector needs separate, owned observation storage. Appending requests
to an analysis case would invalidate its sealed evidence inventory.
"""


def run_canary(case_id: str, port: int = 8787):
    """Reject deployment before touching case files, opening sockets or sending mail."""
    raise RuntimeError(
        'Canary deployment unavailable: collection requires separate observation '
        'storage and the isolated lab; existing case evidence is preserved'
    )


def main():
    """Keep legacy console/module invocation on the canonical CLI error path."""
    import sys
    from ..__main__ import main as cli_main
    sys.argv = ['paw', 'canary', *sys.argv[1:]]
    cli_main()


if __name__ == '__main__':
    main()
