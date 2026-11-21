"""Exercise the retired deployment entry points without real system tools."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "paw/modules/encrypted_clicking"
BASH = shutil.which("bash") if os.name == "posix" else None


@unittest.skipUnless(BASH, "Requires a POSIX shell")
class RetiredDeploymentEntrypoints(unittest.TestCase):
    def test_shell_launchers_exit_before_configuration_or_commands(self):
        for launcher in (ROOT / "deploy.sh", MODULE / "init_crypto.sh"):
            with self.subTest(launcher=launcher.name), tempfile.TemporaryDirectory() as raw:
                directory = Path(raw)
                tools = directory / "bin"
                tools.mkdir()
                marker = directory / "command-ran"
                config = directory / ".env"
                config.write_text(': > "$PAW_TEST_MARKER"\n', encoding="utf-8")
                evidence = directory / "evidence.eml"
                original = b"From: fixture@example.invalid\r\n\r\nOriginal evidence\r\n"
                evidence.write_bytes(original)
                for name in ("python3", "docker", "docker-compose", "openssl", "sudo", "cp", "mkdir", "awk", "sort"):
                    stub = tools / name
                    stub.write_text(f'#!{BASH}\n: > "$PAW_TEST_MARKER"\nexit 99\n', encoding="utf-8")
                    stub.chmod(0o700)
                result = subprocess.run(
                    [BASH, str(launcher)], cwd=directory, capture_output=True, text=True, timeout=10,
                    env={"PATH": str(tools), "PAW_TEST_MARKER": str(marker)},
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("retired", result.stderr)
                self.assertEqual({p.name for p in directory.iterdir()}, {"bin", ".env", "evidence.eml"})
                self.assertEqual(config.read_text(encoding="utf-8"), ': > "$PAW_TEST_MARKER"\n')
                self.assertEqual(evidence.read_bytes(), original)

    def test_legacy_image_builder_exits_before_case_directory_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(MODULE / "paw_integration.py"),
                 "https://example.invalid/", "--build"],
                cwd=directory, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertIn("image build is retired", result.stderr)
            self.assertEqual(list(directory.iterdir()), [])
