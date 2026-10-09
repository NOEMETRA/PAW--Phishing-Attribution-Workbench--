"""Static JavaScript evidence contracts, not phishing accuracy labels."""
import base64
import unittest

from paw.core.network_policy import offline_policy, violations
from paw.deobfuscate.core import DeobfuscationEngine
from paw.deobfuscate.javascript import JavaScriptDeobfuscator


class JavaScriptContracts(unittest.TestCase):
    def test_original_source_is_never_rewritten_or_recursively_decoded(self):
        source = 'eval("hello"); atob("YXRvYignWVE9PScp"); String.fromCharCode(65,65);'
        for engine in (JavaScriptDeobfuscator(), DeobfuscationEngine()):
            result = engine.deobfuscate_javascript(source)
            self.assertEqual(result['original_code'], source)
            self.assertEqual(result['final_code'], source)
            self.assertEqual(result['transformations'], [])
            self.assertEqual(result['suspicion_score'], 0)
            self.assertEqual(len(result['literal_candidates']['candidates']), 3)
            self.assertNotIn('EVAL RESULT', str(result))
            self.assertNotIn('EVAL BLOCKED', str(result))

    def test_eval_literal_is_only_a_candidate_even_with_legacy_flag(self):
        engine = JavaScriptDeobfuscator()
        engine.safe_execution_enabled = True
        with offline_policy(True):
            before = violations()
            result = engine.deobfuscate_javascript('eval("fetch(\\\"https://example.invalid\\\")")')
            self.assertEqual(violations(), before)
        candidate, = result['literal_candidates']['candidates']
        self.assertEqual(candidate['status'], 'not_executed')
        self.assertEqual(candidate['decoded_text'], 'fetch("https://example.invalid")')
        self.assertFalse(candidate['network_target'])
        self.assertFalse(candidate['syntax_verified'])
        self.assertEqual(result['execution']['status'], 'not_evaluated')

    def test_atob_preserves_every_byte_and_rejects_invalid_alphabet(self):
        for raw in (b'\xff\xfe\x00', 'caffè'.encode()):
            token = base64.b64encode(raw).decode()
            result = JavaScriptDeobfuscator().deobfuscate_javascript('atob("'+token+'")')
            candidate, = result['literal_candidates']['candidates']
            self.assertEqual(candidate['decoded_text'].encode('latin-1'), raw)
            self.assertEqual(candidate['decoded_size'], len(raw))
        result = JavaScriptDeobfuscator().deobfuscate_javascript('atob("Y!Q==")')
        candidate, = result['literal_candidates']['candidates']
        self.assertEqual(candidate['status'], 'invalid_encoding')
        self.assertIsNone(candidate['decoded_text'])

    def test_fromcharcode_uses_utf16_units_and_never_extracts_digits_from_expressions(self):
        result = JavaScriptDeobfuscator().deobfuscate_javascript(
            'String.fromCharCode(65536,-1,65); String.fromCharCode(65+1,variable2);')
        first, second = result['literal_candidates']['candidates']
        self.assertEqual(first['code_units'], [0,65535,65])
        self.assertEqual(second['status'], 'unsupported_literal')
        self.assertIsNone(second['decoded_text'])

    def test_uri_decode_requires_valid_percent_and_utf8_and_preserves_plus(self):
        source = 'decodeURIComponent("a+b%2Fc"); decodeURIComponent("%FF"); decodeURIComponent("%ZZ");'
        candidates = JavaScriptDeobfuscator().deobfuscate_javascript(source)['literal_candidates']['candidates']
        self.assertEqual(candidates[0]['decoded_text'], 'a+b/c')
        for candidate in candidates[1:]:
            self.assertEqual(candidate['status'], 'invalid_encoding')
            self.assertIsNone(candidate['decoded_text'])

    def test_repeated_candidates_have_exact_original_spans_without_multiplication(self):
        source = 'atob("YQ=="); atob("YQ==");'
        candidates = JavaScriptDeobfuscator().deobfuscate_javascript(source)['literal_candidates']['candidates']
        self.assertEqual(len(candidates),2)
        self.assertEqual(len({tuple(c['source_span']) for c in candidates}),2)
        for candidate in candidates:
            start,end = candidate['source_span']
            self.assertEqual(source[start:end], candidate['original'])
            self.assertTrue(candidate['candidate_only'])

    def test_api_parity_and_javascript_only_risk_remains_unassessed(self):
        source = 'String.fromCharCode(65); eval("hello");'
        engine = DeobfuscationEngine()
        direct = JavaScriptDeobfuscator().deobfuscate_javascript(source)
        self.assertEqual(direct,engine.deobfuscate_javascript(source))
        result = engine.analyze_artifacts({'javascript':source})
        self.assertEqual(result['assessment_status'], 'descriptive_only')
        self.assertIsNone(result['suspicion_score'])
        self.assertEqual(result['coverage']['javascript']['risk_detection'], 'not_evaluated')

    def test_forgiving_base64_whitespace_padding_and_empty_literals(self):
        for token in ('YQ', 'YR', ' YQ== ', 'YQ= =', ''):
            with self.subTest(token=token):
                candidate, = JavaScriptDeobfuscator().deobfuscate_javascript(
                    'atob("'+token+'")')['literal_candidates']['candidates']
                self.assertEqual(candidate['decoded_text'], 'a' if token else '')
        for token in ('Y', 'YQ=', 'YQ===', 'YQ-_', 'YQ\u00a0'):
            candidate, = JavaScriptDeobfuscator().deobfuscate_javascript(
                'atob("'+token+'")')['literal_candidates']['candidates']
            self.assertEqual(candidate['status'], 'invalid_encoding')

    def test_utf16_pairs_unpaired_units_and_unsafe_large_numbers(self):
        result = JavaScriptDeobfuscator().deobfuscate_javascript(
            'String.fromCharCode(55357,56832); String.fromCharCode(55296); '
            'String.fromCharCode(9007199254740993);')
        pair, lone, large = result['literal_candidates']['candidates']
        self.assertEqual(pair['decoded_text'], '\U0001f600')
        self.assertEqual(lone['code_units'], [55296])
        self.assertEqual(lone['status'], 'utf16_code_units')
        self.assertIsNone(lone['decoded_text'])
        self.assertEqual(large['status'], 'unsupported_literal')

    def test_lexical_context_is_unverified_and_escapes_never_rewrite_source(self):
        source = '// atob("YQ==")\nconst help = "eval(1)"; const x="\\x41\\u0042"; ATOB("YQ==");'
        result = JavaScriptDeobfuscator().deobfuscate_javascript(source)
        self.assertEqual(result['final_code'], source)
        self.assertEqual(result['lexical_observations']['hex_escape_count'],1)
        self.assertEqual(result['lexical_observations']['unicode_escape_count'],1)
        self.assertEqual(len(result['literal_candidates']['candidates']),2)
        for candidate in result['literal_candidates']['candidates']:
            self.assertFalse(candidate['syntax_verified'])
            self.assertFalse(candidate['network_target'])

    def test_limits_are_bounded_and_propagate_partial_coverage(self):
        decoder = JavaScriptDeobfuscator()
        sources = ('atob("YQ==");'*33,
                   'atob("'+'a'*decoder.MAX_ARGUMENT_CHARS+'")',
                   'atob('+'a'*decoder.MAX_ARGUMENT_CHARS,
                   ' '*decoder.MAX_SCAN_CHARS+'atob("YQ==")')
        for source in sources:
            with self.subTest(length=len(source)):
                result = DeobfuscationEngine().analyze_artifacts({'javascript':source})
                js = result['deobfuscated_artifacts']['javascript']
                self.assertEqual(js['final_code'],source)
                self.assertEqual(result['assessment_status'], 'partial')
                self.assertIsNone(result['suspicion_score'])
                self.assertLessEqual(len(js['literal_candidates']['candidates']),32)
                self.assertLessEqual(js['literal_candidates']['scanned_characters'],decoder.MAX_SCAN_CHARS)

    def test_mixed_url_heuristic_does_not_include_javascript_candidates(self):
        engine = DeobfuscationEngine()
        url_only = engine.analyze_artifacts({'urls':['hxxps://example[.]invalid']})
        mixed = engine.analyze_artifacts({'urls':['hxxps://example[.]invalid'],
                                        'javascript':'eval("hello"); atob("YQ==");'})
        self.assertEqual(mixed['suspicion_score'],url_only['suspicion_score'])
        self.assertEqual(mixed['transformations'],url_only['transformations'])
        self.assertEqual(mixed['assessment_status'],'partial')

    def test_candidate_limit_reports_processed_prefix_and_unprocessed_range(self):
        prefix = 'atob("YQ==");'*32
        source = prefix+'eval("later");'+' '*100000
        result = JavaScriptDeobfuscator().deobfuscate_javascript(source)
        scan = result['literal_candidates']
        self.assertEqual(scan['scanned_characters'],len(prefix))
        self.assertEqual(scan['available_window_characters'],len(source))
        self.assertEqual(scan['unprocessed_source_span'],[len(prefix),len(source)])
        self.assertEqual(scan['coverage_scope'],'literal_candidate_search')
        self.assertEqual(len(scan['candidates']),32)

    def test_nested_parentheses_preserve_whole_unsupported_candidate_spans(self):
        for source in ('eval(("hello"))', 'String.fromCharCode(foo(65),66)',
                       'eval((("quoted ) (")))'):
            with self.subTest(source=source):
                result = JavaScriptDeobfuscator().deobfuscate_javascript(source)
                candidate, = result['literal_candidates']['candidates']
                self.assertEqual(candidate['original'],source)
                self.assertEqual(candidate['source_span'],[0,len(source)])
                self.assertEqual(candidate['status'],'unsupported_literal')
                self.assertIsNone(candidate['decoded_text'])

    def test_window_and_argument_limits_keep_bounded_nested_spans(self):
        decoder = JavaScriptDeobfuscator()
        source = 'eval('+'('*decoder.MAX_ARGUMENT_CHARS+')'*decoder.MAX_ARGUMENT_CHARS
        result = decoder.deobfuscate_javascript(source)['literal_candidates']
        candidate, = result['candidates']
        self.assertEqual(candidate['status'],'limited')
        self.assertEqual(candidate['source_span'],[0,len('eval(')+decoder.MAX_ARGUMENT_CHARS])
        capped = decoder.deobfuscate_javascript(' '*decoder.MAX_SCAN_CHARS+'eval("later")')['literal_candidates']
        self.assertEqual(capped['scanned_characters'],decoder.MAX_SCAN_CHARS)
        self.assertEqual(capped['unprocessed_source_span'],[decoder.MAX_SCAN_CHARS,decoder.MAX_SCAN_CHARS+len('eval("later")')])


if __name__ == '__main__':
    unittest.main()
