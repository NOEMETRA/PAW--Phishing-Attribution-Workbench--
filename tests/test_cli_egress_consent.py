"""Exercise the CLI dispatcher without launching a network-enabled worker."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from paw import __main__ as cli


class EgressConsentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / "fixture.eml"
        self.source.write_bytes(b"Subject: policy dispatch\r\n\r\nLocal fixture\r\n")

    def dispatch(self, command, options, expected):
        source = ["--src", str(self.source)] if command == "trace" else [str(self.source)]
        with patch.object(sys, "argv", ["paw", command, *source, *options]), \
             patch.object(cli, "trace_sources") as run:
            if expected is None:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    cli.main()
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()
            else:
                cli.main()
                run.assert_called_once()
                self.assertIs(run.call_args.args[5], expected)

    def test_network_capable_presets_require_consent(self):
        for command in ("analyze", "trace", "full", "forensic"):
            for options, expected in (([], True), (["--no-egress"], True),
                                      (["--allow-egress"], False),
                                      (["--allow-egress", "--no-egress"], None),
                                      (["--no-egress", "--allow-egress"], None)):
                with self.subTest(command=command, options=options):
                    self.dispatch(command, options, expected)

    def test_quick_stays_offline(self):
        self.dispatch("quick", [], True)
        self.dispatch("quick", ["--allow-egress"], None)


if __name__ == "__main__":
    unittest.main()
