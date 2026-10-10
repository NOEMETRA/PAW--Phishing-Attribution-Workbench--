"""Lossless standalone input contracts; constructed text is not phishing ground truth."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from paw.deobfuscate.input import analyze_input, MAX_INPUT_BYTES
from paw.core.network_policy import violations, network_allowed


class DeobfuscateInputContracts(unittest.TestCase):
    def test_regular_file_preserves_bom_crlf_unicode_and_hash(self):
        raw = '\ufeffCaffè già pagato\r\nUnicode: Straße, Ελληνικά\r\n'.encode('utf-8')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'input.txt'; path.write_bytes(raw)
            result = analyze_input(file=path)
            self.assertEqual(result['deobfuscated_artifacts']['text']['original_text'].encode('utf-8'), raw)
            self.assertEqual(result['deobfuscated_artifacts']['text']['final_text'].encode('utf-8'), raw)
            self.assertEqual(path.read_bytes(), raw)
            observation = result['input_observation']
            self.assertEqual(observation['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(observation['byte_count'], len(raw))
            self.assertEqual(observation['source_kind'], 'file')
            self.assertEqual(observation['case_storage'], 'not_created')
            self.assertTrue(observation['no_egress'])

    def test_invalid_bytes_are_rejected_without_lossy_analysis_or_rewrite(self):
        for raw in (b'pa\xffypal', b'\xff\xfea\x00', b'truncated\xc3'):
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)/'invalid.txt'; path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'not valid UTF-8'): analyze_input(file=path)
                self.assertEqual(path.read_bytes(), raw)

    def test_empty_text_and_file_are_explicit_valid_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'empty.txt'; path.write_bytes(b'')
            for options in ({'text':''}, {'file':path}):
                result = analyze_input(**options)
                self.assertEqual(result['deobfuscated_artifacts']['text']['original_text'], '')
                self.assertIsNone(result['suspicion_score'])
                self.assertEqual(result['input_observation']['byte_count'], 0)
                self.assertEqual(result['input_observation']['sha256'], hashlib.sha256(b'').hexdigest())

    def test_ambiguous_sources_rejected_before_file_access(self):
        for options in ({}, {'text':'', 'file':'missing'}, {'text':'hello','url':'https://example.invalid'},
                        {'file':'missing','url':''}, {'text':'','file':'missing','url':''}):
            with self.assertRaisesRegex(ValueError, 'exactly one'): analyze_input(**options)

    def test_url_is_only_literal_candidate_and_text_is_not_an_implicit_url(self):
        value = 'hxxps://example[.]invalid/a%2Fb?x=a%26b'
        before = len(violations())
        url = analyze_input(url=value)
        text = analyze_input(text=value)
        self.assertEqual(url['deobfuscated_artifacts']['urls'][0]['original_url'], value)
        self.assertEqual(url['deobfuscated_artifacts']['urls'][0]['network_url'], 'https://example.invalid/a%2Fb?x=a%26b')
        self.assertEqual(text['deobfuscated_artifacts']['urls'], [])
        self.assertEqual(len(violations()), before)

    def test_one_mib_file_boundary_and_large_file_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'boundary.txt'; raw = b'a'*MAX_INPUT_BYTES; path.write_bytes(raw)
            result = analyze_input(file=path)
            self.assertEqual(result['input_observation']['byte_count'], MAX_INPUT_BYTES)
            self.assertEqual(result['deobfuscated_artifacts']['text']['original_text'].encode(), raw)
            with path.open('ab') as stream: stream.write(b'a')
            with self.assertRaisesRegex(ValueError,'1 MiB'): analyze_input(file=path)
            self.assertEqual(path.stat().st_size, MAX_INPUT_BYTES+1)

    def test_literal_limits_are_utf8_bytes_and_invalid_surrogates_rejected(self):
        with self.assertRaisesRegex(ValueError, '1 MiB'): analyze_input(text='a'*(MAX_INPUT_BYTES+1))
        with self.assertRaisesRegex(ValueError, '1 MiB'): analyze_input(text='é'*(MAX_INPUT_BYTES//2+1))
        with self.assertRaisesRegex(ValueError, 'valid UTF-8'): analyze_input(text='\ud800')
        with self.assertRaisesRegex(ValueError, 'must be text'): analyze_input(text=b'bytes')

    def test_nonregular_missing_and_unc_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises((ValueError, OSError)): analyze_input(file=temporary)
            with self.assertRaises(FileNotFoundError): analyze_input(file=Path(temporary)/'missing')
        with self.assertRaisesRegex(ValueError, 'UNC'): analyze_input(file=r'\\invalid-host\share\input.txt')

    @unittest.skipUnless(os.name=='posix', 'POSIX FIFO contract')
    def test_fifo_is_rejected_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'pipe'; os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, 'regular file'): analyze_input(file=path)

    def test_policy_restored_after_success_and_input_failure(self):
        allowed = network_allowed()
        analyze_input(text='Original input')
        self.assertEqual(network_allowed(), allowed)
        with self.assertRaises(ValueError): analyze_input(url='é'*MAX_INPUT_BYTES)
        self.assertEqual(network_allowed(), allowed)


if __name__ == '__main__': unittest.main()
