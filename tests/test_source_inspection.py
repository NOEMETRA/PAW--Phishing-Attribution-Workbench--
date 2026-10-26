"""Owned byte acquisition tests; no execution or egress."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paw.core import source_inspection as source
from paw.core.network_policy import offline_policy, violations


class SourceInspection(unittest.TestCase):
    def test_empty_binary_invalid_utf8_and_misleading_suffix_remain_exact_bytes(self):
        fixtures = [b'', b'\x00\xff\xfe\x80not text', bytes(range(256)), b'not MIME\r\n\x00raw bytes']
        with tempfile.TemporaryDirectory() as folder, offline_policy():
            root = Path(folder)
            for number, raw in enumerate(fixtures):
                path = root/(str(number)+'.py'); path.write_bytes(raw)
                captured = source.acquire_source(path); report = source.inspect_capture(captured)
                self.assertEqual(captured.raw, raw); self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(report['source']['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(report['source']['bytes'], len(raw)); self.assertFalse(report['source']['origin_verified'])
                self.assertEqual(report['coverage']['classification'], 'not_evaluated')
                self.assertEqual(report['coverage']['execution_authority'], 'none')
                self.assertEqual(len(list(root.iterdir())), number+1)

    def test_synthetic_code_and_url_strings_never_import_execute_fetch_or_resolve(self):
        with tempfile.TemporaryDirectory() as folder, offline_policy():
            root = Path(folder); marker = root/'must-not-exist'
            raw = ('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n# https://owned.fixture.invalid/payload\n').encode()
            path = root/'program.py'; path.write_bytes(raw); count = len(violations())
            with (patch('socket.getaddrinfo', side_effect=AssertionError('DNS reached')),
                  patch('subprocess.Popen', side_effect=AssertionError('Execution reached'))):
                report = source.inspect_capture(source.acquire_source(path))
            self.assertFalse(marker.exists()); self.assertEqual(len(violations()), count)
            self.assertEqual(report['observations']['utf8']['status'], 'strictly_decodable')

    def test_uri_unc_blank_nul_and_nontext_paths_refuse_before_io(self):
        paths = ['https://owned.fixture.invalid/x', 'file:///tmp/source', 'data://opaque',
                 r'\\owned.fixture.invalid\share\file', '//owned.fixture.invalid/share/file',
                 r'\/owned.fixture.invalid\share', r'/\owned.fixture.invalid/share', '', ' ', 'bad\x00file', b'bytes', None]
        with (patch.object(source.os, 'open', side_effect=AssertionError('I/O reached')),
              patch.object(source.os, 'stat', side_effect=AssertionError('I/O reached'))):
            for path in paths:
                with self.subTest(path=path), self.assertRaises(source.SourceError): source.acquire_source(path)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO admission')
    def test_fifo_and_directory_refuse_without_blocking(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); fifo = root/'input'; os.mkfifo(fifo)
            for path in [fifo, root]:
                with self.subTest(path=path), self.assertRaisesRegex(source.SourceError, 'source_not_regular'):
                    source.acquire_source(path)

    def test_input_budget_refuses_before_read_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'source'; path.write_bytes(b'12345')
            with (patch.object(source.os, 'read', side_effect=AssertionError('Oversize source read')),
                  self.assertRaisesRegex(source.SourceError, 'source_input_budget')):
                source.acquire_source(path, source.SourceLimits(input_bytes=4))
            self.assertEqual(path.read_bytes(), b'12345')

    def test_same_length_content_change_during_read_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'source'; path.write_bytes(b'owned1')
            original = os.read; changed = False
            def mutates(fd, count):
                nonlocal changed
                value = original(fd, count)
                if not changed:
                    changed = True; before = path.stat(); path.write_bytes(b'owned2')
                    # Restore mtime: ctime must independently detect this change.
                    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                return value
            with (patch.object(source.os, 'read', side_effect=mutates),
                  self.assertRaisesRegex(source.SourceError, 'source_changed_during_read')):
                source.acquire_source(path)

    def test_named_inode_replacement_is_not_hidden_by_stable_open_descriptor(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root/'source'; path.write_bytes(b'original')
            replacement = root/'replacement'; replacement.write_bytes(b'newbytes')
            original = os.read; changed = False
            def replaces(fd, count):
                nonlocal changed
                value = original(fd, count)
                if not changed:
                    changed = True; replacement.replace(path)
                return value
            with patch.object(source.os, 'read', side_effect=replaces), self.assertRaises(source.SourceError): source.acquire_source(path)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink admission')
    def test_last_component_symlink_refuses_and_does_not_modify_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root/'target'; target.write_bytes(b'owned')
            link = root/'link'; link.symlink_to(target)
            with self.assertRaises(source.SourceError): source.acquire_source(link)
            self.assertEqual(target.read_bytes(), b'owned')

    def test_strict_utf8_keeps_bom_crlf_nul_and_invalid_bytes_are_not_repaired(self):
        for raw in [b'\xef\xbb\xbftext\r\n\x00', '\u03b1\U0001f4e7'.encode(), b'']:
            with self.subTest(raw=raw):
                value = source.inspect_bytes(raw)['observations']['utf8']
                self.assertEqual(value['status'], 'strictly_decodable')
                self.assertEqual(value['roundtrip_sha256'], hashlib.sha256(raw).hexdigest())
        value = source.inspect_bytes(b'valid\xffbad')['observations']['utf8']
        self.assertEqual(value['status'], 'invalid'); self.assertEqual(value['error_offset'], 5)
        self.assertNotIn('roundtrip_sha256', value)

    def test_text_and_preview_budgets_have_explicit_coverage_without_dropping_source(self):
        limits = source.SourceLimits(input_bytes=16, text_observation_bytes=4, preview_bytes=3)
        raw = b'\xff'*8; report = source.inspect_bytes(raw, limits=limits)
        self.assertEqual(report['source']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(report['observations']['utf8']['status'], 'omitted_budget')
        self.assertEqual(report['observations']['prefix']['data'], 'ffffff')
        self.assertEqual(report['observations']['prefix']['bytes'], 3)

    def test_prefix_hints_cannot_become_format_validity_execution_or_classification(self):
        for raw, expected in [(b'\x7fELFjunk', 'elf_prefix'), (b'MZjunk', 'dos_mz_prefix'),
                              (b'PK\x03\x04not an archive', 'zip_local_header_prefix'), (b'#!/bin/sh\nexit', 'shebang_prefix')]:
            value = source.inspect_bytes(raw)
            self.assertEqual(value['observations']['prefix_hints'][0]['kind'], expected)
            self.assertEqual(value['coverage']['format_interpretation'], 'not_performed')
            self.assertEqual(value['coverage']['execution_authority'], 'none')

    def test_exact_byte_distribution_empty_entropy_and_json_are_bounded(self):
        report = source.inspect_bytes(bytes(range(256)))
        self.assertEqual(report['observations']['byte_counts'], {'nul': 1, 'distinct': 256, 'ascii_control': 33})
        self.assertEqual(report['observations']['entropy_bits_per_byte'], 8.0)
        self.assertIsNone(source.inspect_bytes(b'')['observations']['entropy_bits_per_byte'])
        self.assertLess(len(json.dumps(report, allow_nan=False)), 8192)

    def test_limit_types_and_corrupted_capture_refuse(self):
        for field in ['input_bytes', 'text_observation_bytes', 'preview_bytes']:
            for bad in [True, 0, -1, 1.5, '1', None, 2**100]:
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError): source.SourceLimits(**{field: bad})
        with self.assertRaisesRegex(source.SourceError, 'source_capture_digest_changed'):
            source.inspect_capture(source.SourceCapture(b'owned', 'name', '0'*64))


if __name__ == '__main__': unittest.main()
