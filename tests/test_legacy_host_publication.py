"""Legacy host/IP/ASN writers reject before source/output access."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import runpy
import tempfile
import unittest

from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.network_policy import offline_policy, violations

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = (REPO/'util/derive_host_ip_asn.py', REPO/'advanced/derive_host_ip_asn_advanced.py')
REASON = 'Legacy host/IP/ASN publication unavailable'


class LegacyHostPublication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.policy = offline_policy(); self.policy.__enter__(); self.before = len(violations())

    def tearDown(self):
        blocked = violations()[self.before:]; self.policy.__exit__(None, None, None)
        self.temporary.cleanup(); self.assertEqual(blocked, [])

    def source(self, name):
        case = self.root/name; (case/'derived').mkdir(parents=True)
        (case/'detonation_endpoints.json').write_text('[{"host":"stored.invalid","ips":["192.0.2.1"]}]', encoding='utf-8')
        (case/'hunt_enrichments.json').write_text('[{"ip":"192.0.2.1"}]', encoding='utf-8')
        (case/'derived/host_ip_asn.csv').write_text('host,ip\nstored.invalid,192.0.2.1\n', encoding='utf-8')
        for name in ('threat_intel_enriched.csv', 'threat_assessment_report.json'):
            (case/'derived'/name).write_bytes(b'Original analyst note\n')
        seal_case(case); return case

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None
                for p in self.root.rglob('*')}

    def rejected(self, main, arguments):
        output = io.StringIO(); error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            main(arguments)
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(output.getvalue(), ''); self.assertIn(REASON, error.getvalue())

    def test_main_preserves_existing_sealed_and_missing_cases(self):
        for index, script in enumerate(SCRIPTS):
            namespace = runpy.run_path(str(script), run_name='legacy_import')
            for mode in ('saved', 'missing'):
                with self.subTest(script=script, mode=mode):
                    case = self.source(str(index)+mode) if mode == 'saved' else self.root/(str(index)+mode)
                    before = self.snapshot(); self.rejected(namespace['main'], [str(case)])
                    self.assertEqual(self.snapshot(), before)
                    if mode == 'saved': self.assertTrue(verify_case(str(case)))

    def test_explicit_output_cannot_overwrite_a_source_or_an_outside_file(self):
        main = runpy.run_path(str(SCRIPTS[0]), run_name='legacy_import')['main']
        case = self.source('saved'); outside = self.root/'outside.txt'; outside.write_bytes(b'Keep outside source')
        for target in (case/'hunt_enrichments.json', outside, self.root/'missing-parent/new.csv'):
            with self.subTest(target=target):
                before = self.snapshot(); self.rejected(main, [str(case), '--out', str(target)])
                self.assertEqual(self.snapshot(), before)
                self.assertTrue(verify_case(str(case)))

    def test_advanced_writer_rejects_before_inspecting_path_or_reading_case(self):
        class Opaque:
            def __str__(self): raise AssertionError('Argument inspected')
            def __fspath__(self): raise AssertionError('Argument inspected')
            def __truediv__(self, other): raise AssertionError('Argument inspected')
        writer = runpy.run_path(str(SCRIPTS[1]), run_name='legacy_import')['enrich']
        case = self.source('saved'); before = self.snapshot()
        for target in (case, Opaque()):
            with self.subTest(opaque=isinstance(target, Opaque)):
                with self.assertRaisesRegex(RuntimeError, REASON): writer(target)
        self.assertEqual(self.snapshot(), before); self.assertTrue(verify_case(str(case)))

    def test_exact_help_errors_and_long_option_prefixes(self):
        for script in SCRIPTS:
            main = runpy.run_path(str(script), run_name='legacy_import')['main']
            arguments = [(['--help'], 0), (['-h'], 0), ([], 2), (['case', '--unsupported'], 2)]
            arguments += [(['case', flag], 2) for flag in ('--h', '--he', '--hel')]
            if script == SCRIPTS[0]: arguments += [(['case', flag, 'out.csv'], 2) for flag in ('--o', '--ou')]
            for args, expected in arguments:
                with self.subTest(script=script, args=args):
                    output = io.StringIO(); error = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised: main(args)
                    self.assertEqual(raised.exception.code, expected)
                    if expected == 0:
                        self.assertIn('unavailable', output.getvalue()); self.assertIn('preserved', output.getvalue())

    def test_import_is_inert_for_sources_and_output_paths(self):
        self.source('saved'); before = self.snapshot()
        for script in SCRIPTS:
            output = io.StringIO()
            with redirect_stdout(output): runpy.run_path(str(script), run_name='legacy_import')
            self.assertEqual(output.getvalue(), ''); self.assertEqual(self.snapshot(), before)


if __name__ == '__main__': unittest.main()
