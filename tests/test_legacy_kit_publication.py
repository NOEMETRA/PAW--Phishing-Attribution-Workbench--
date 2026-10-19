"""Legacy kit writers reject before source/argument access; package observations stay separate."""
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
SCRIPTS = (REPO/'util/kit_static_mapper.py', REPO/'advanced/kit_static_mapper_advanced.py')
REASON = 'Legacy kit publication unavailable'


class LegacyKitPublication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = offline_policy(); self.policy.__enter__()
        self.before = len(violations())

    def tearDown(self):
        blocked = violations()[self.before:]
        self.policy.__exit__(None, None, None)
        self.temporary.cleanup()
        self.assertEqual(blocked, [])

    def source(self, name):
        case = self.root/name
        (case/'detonation/phishing_kit').mkdir(parents=True); (case/'derived').mkdir()
        (case/'detonation/phishing_kit/index.html').write_text('<a href="https://stored.invalid/path">supplied</a>', encoding='utf-8')
        (case/'input.eml').write_bytes(b'Subject: declared fixture\n\nhttps://stored.invalid/\n')
        for name in ('indicators_from_kit.csv','kit_graph.json','kit_graph.mmd','ttp_analysis.json',
                     'criminal_fingerprint.json','deobfuscation_cascade.json','threat_actor_profile.json'):
            (case/'derived'/name).write_bytes(b'Original analyst note\n')
        seal_case(case)
        return case

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None
                for p in self.root.rglob('*')}

    def test_writer_apis_refuse_existing_sealed_sources_without_changes(self):
        for index, script in enumerate(SCRIPTS):
            with self.subTest(script=script):
                case = self.source(str(index)); before = self.snapshot()
                namespace = runpy.run_path(str(script), run_name='legacy_import')
                args = (case, [], {}) if index == 0 else (case, {'ttp_analysis': [], 'criminal_infrastructure': {}, 'deobfuscation_chains': [], 'threat_actor_profile': {}})
                writer = namespace['write_outputs']
                with self.assertRaisesRegex(RuntimeError, REASON): writer(*args)
                self.assertEqual(self.snapshot(), before)
                self.assertTrue(verify_case(str(case)))

    def test_writer_arguments_are_not_inspected(self):
        class Opaque:
            def __str__(self): raise AssertionError('Argument inspected')
            def __fspath__(self): raise AssertionError('Argument inspected')
            def __truediv__(self, other): raise AssertionError('Argument inspected')
            def __iter__(self): raise AssertionError('Argument inspected')
        for index, script in enumerate(SCRIPTS):
            with self.subTest(script=script):
                namespace = runpy.run_path(str(script), run_name='legacy_import')
                args = (Opaque(), Opaque(), Opaque()) if index == 0 else (Opaque(), Opaque())
                with self.assertRaisesRegex(RuntimeError, REASON):
                    namespace['write_outputs'](*args)

    def test_main_refuses_existing_and_missing_cases_without_changes(self):
        for index, script in enumerate(SCRIPTS):
            namespace = runpy.run_path(str(script), run_name='legacy_import')
            for mode in ('existing', 'missing'):
                with self.subTest(script=script, mode=mode):
                    case = self.source(str(index)+mode) if mode == 'existing' else self.root/(str(index)+mode)
                    before = self.snapshot(); output = io.StringIO(); error = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                        namespace['main']([str(case)])
                    self.assertEqual(raised.exception.code, 1)
                    self.assertIn(REASON, error.getvalue())
                    self.assertEqual(output.getvalue(), '')
                    self.assertEqual(self.snapshot(), before)

    def test_exact_help_argument_errors_and_long_option_prefixes(self):
        for script in SCRIPTS:
            namespace = runpy.run_path(str(script), run_name='legacy_import')
            for args, expected in ((['--help'], 0), (['-h'], 0), ([], 2),
                    (['--h'], 2), (['--he'], 2), (['--hel'], 2), (['case', '--unsupported'], 2)):
                with self.subTest(script=script, args=args):
                    output = io.StringIO(); error = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                        namespace['main'](args)
                    self.assertEqual(raised.exception.code, expected)
                    if expected == 0:
                        self.assertIn('unavailable', output.getvalue())
                        self.assertIn('preserved', output.getvalue())

    def test_import_is_inert_for_saved_sources(self):
        self.source('saved'); before = self.snapshot()
        for script in SCRIPTS:
            with self.subTest(script=script):
                output = io.StringIO()
                with redirect_stdout(output): runpy.run_path(str(script), run_name='legacy_import')
                self.assertEqual(output.getvalue(), '')
                self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
