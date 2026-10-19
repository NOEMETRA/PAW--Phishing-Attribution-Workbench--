"""Unavailable prediction publishers/APIs preserve sources without NumPy import."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.network_policy import offline_policy, violations

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = (REPO/'util/operational_pattern_predictor.py', REPO/'advanced/operational_pattern_predictor.py')
REASON = 'Legacy operational prediction unavailable'
ADVANCED_APIS = ('build_evolution', 'build_actor_timeline', 'predict_targets', 'countermeasure_effectiveness', 'write_outputs')


class LegacyPredictionBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.policy = offline_policy(); self.policy.__enter__(); self.before = len(violations())

    def tearDown(self):
        blocked = violations()[self.before:]; self.policy.__exit__(None, None, None)
        self.temporary.cleanup(); self.assertEqual(blocked, [])

    def source(self, name):
        case = self.root/name; (case/'derived').mkdir(parents=True)
        (case/'derived/threat_intel_enriched.csv').write_text('host,ip,asn,risk_score\nstored.invalid,192.0.2.1,64500,0\n', encoding='utf-8')
        for name in ('operational_predictions.json','infrastructure_evolution.json','threat_actor_timeline.json','next_targets_prediction.json','countermeasure_effectiveness.json'):
            (case/'derived'/name).write_bytes(b'Original analyst note\n')
        seal_case(case); return case

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None for p in self.root.rglob('*')}

    def rejected(self, main, arguments):
        output = io.StringIO(); error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised: main(arguments)
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(output.getvalue(), ''); self.assertIn(REASON, error.getvalue())

    def test_main_preserves_saved_and_missing_cases(self):
        for index, script in enumerate(SCRIPTS):
            main = runpy.run_path(str(script), run_name='legacy_import')['main']
            for mode in ('saved', 'missing'):
                with self.subTest(script=script, mode=mode):
                    case = self.source(str(index)+mode) if mode == 'saved' else self.root/(str(index)+mode)
                    before = self.snapshot(); self.rejected(main, [str(case)])
                    self.assertEqual(self.snapshot(), before)
                    if mode == 'saved': self.assertTrue(verify_case(str(case)))

    def test_both_exact_output_options_preserve_source_outside_and_new_paths(self):
        main = runpy.run_path(str(SCRIPTS[0]), run_name='legacy_import')['main']
        case = self.source('saved'); outside = self.root/'outside'; outside.write_bytes(b'Keep outside file')
        for flag in ('--output', '-o'):
            for target in (case/'derived/threat_intel_enriched.csv', outside, self.root/'missing-parent/new.json'):
                with self.subTest(flag=flag, target=target):
                    before = self.snapshot(); self.rejected(main, [str(case), flag, str(target)])
                    self.assertEqual(self.snapshot(), before); self.assertTrue(verify_case(str(case)))

    def test_prediction_and_writer_apis_reject_before_inspecting_arguments(self):
        class Opaque:
            def __str__(self): raise AssertionError('Argument inspected')
            def __fspath__(self): raise AssertionError('Argument inspected')
            def __truediv__(self, other): raise AssertionError('Argument inspected')
            def __iter__(self): raise AssertionError('Argument inspected')
            def __getitem__(self, key): raise AssertionError('Argument inspected')
            def get(self, *args): raise AssertionError('Argument inspected')
        namespace = runpy.run_path(str(SCRIPTS[0]), run_name='legacy_import')
        with self.assertRaisesRegex(RuntimeError, REASON): namespace['ThreatActorBehaviorModel']().predict_infrastructure_evolution(Opaque())
        namespace = runpy.run_path(str(SCRIPTS[1]), run_name='legacy_import')
        for name in ADVANCED_APIS:
            with self.subTest(api=name), self.assertRaisesRegex(RuntimeError, REASON):
                namespace[name](*([Opaque()]*namespace[name].__code__.co_argcount))

    def test_exact_help_errors_and_long_option_prefixes(self):
        for script in SCRIPTS:
            main = runpy.run_path(str(script), run_name='legacy_import')['main']
            missing = str(self.root/'missing')
            arguments = [(['--help'],0), (['-h'],0), ([],2), ([missing,'--unsupported'],2)]
            arguments += [([missing,flag],2) for flag in ('--h','--he','--hel')]
            if script == SCRIPTS[0]: arguments += [([missing,flag,'output.json'],2) for flag in ('--o','--ou','--out','--outp','--outpu')]
            for args, expected in arguments:
                with self.subTest(script=script, args=args):
                    output = io.StringIO(); error = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised: main(args)
                    self.assertEqual(raised.exception.code, expected)
                    if expected == 0:
                        self.assertIn('unavailable', output.getvalue()); self.assertIn('preserved', output.getvalue())

    def test_import_is_inert_for_saved_sources(self):
        self.source('saved'); before = self.snapshot()
        for script in SCRIPTS:
            output = io.StringIO()
            with redirect_stdout(output): runpy.run_path(str(script), run_name='legacy_import')
            self.assertEqual(output.getvalue(), ''); self.assertEqual(self.snapshot(), before)

    def test_import_and_rejected_prediction_do_not_require_numpy(self):
        import builtins
        original = builtins.__import__
        def without_numpy(name, *args, **kwargs):
            if name == 'numpy' or name.startswith('numpy.'): raise AssertionError('NumPy imported by unavailable boundary')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', without_numpy):
            namespace = runpy.run_path(str(SCRIPTS[0]), run_name='legacy_import')
            self.rejected(namespace['main'], [str(self.root/'missing')])
            with self.assertRaisesRegex(RuntimeError, REASON):
                namespace['ThreatActorBehaviorModel']().predict_infrastructure_evolution(object())


if __name__ == '__main__': unittest.main()
