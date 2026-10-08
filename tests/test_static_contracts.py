"""Static preflight only. Does not prove email analysis or offline isolation."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/Northguard-Security/PAW--Phishing-Attribution-Workbench--"


class PublicContractTests(unittest.TestCase):
    def test_pyproject_is_parseable_and_links_are_real(self):
        meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        urls = meta["project"]["urls"]
        self.assertEqual(urls["Homepage"], REPO)
        self.assertEqual(urls["Repository"], REPO)
        self.assertEqual(urls["Bug Tracker"], REPO + "/issues")
        self.assertFalse(any("yourusername" in value for value in urls.values()))
        self.assertFalse(any("readthedocs.io" in value for value in urls.values()))

    def test_maturity_is_not_misrepresented(self):
        meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertIn("Development Status :: 3 - Alpha", meta["project"]["classifiers"])

    def test_cli_does_not_promise_offline_isolation(self):
        cli = (ROOT / "paw" / "__main__.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("Use --no-egress flag to skip network operations", cli)
        self.assertIn("--no-egress flag does not currently enforce network isolation", cli)
        self.assertIn("must not be treated as a reliable network kill switch", readme)

    def test_readme_preserves_evidence_boundaries(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("not a calibrated probability", readme)
        self.assertIn("not proof of the original human sender", readme)


if __name__ == "__main__":
    unittest.main()
