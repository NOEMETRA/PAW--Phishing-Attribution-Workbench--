"""Legacy conclusions cannot overwrite evidence or assert unvalidated capabilities."""
from contextlib import redirect_stderr, redirect_stdout
import inspect
import io
from pathlib import Path
import runpy
import tempfile
import unittest

from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.network_policy import offline_policy, violations

REPO = Path(__file__).resolve().parents[1]
SPECS = {
    'util/attribution_confirmation_engine.py': ('RealScientificAttributionEngine',
        ('analyze_real_attribution_evidence', 'generate_real_confidence_matrix')),
    'advanced/attribution_confirmation_engine.py': (None, ('confidence_matrix',)),
    'util/deception_countermeasure_engine.py': ('RealDeceptionEngine',
        ('create_real_honeytokens', 'design_real_deception_network', 'setup_real_monitoring',
         'create_real_fake_services', 'create_real_traffic_redirectors', 'deploy_real_honeypots')),
    'advanced/deception_countermeasure_engine.py': (None,
        ('create_honeytokens', 'design_deception_network', 'counter_intel_ops', 'adversary_manipulation', 'write_outputs')),
    'advanced/strategic_correlator.py': (None, ('build_dossier', 'write_markdown')),
}
REASON = 'Legacy conclusion publication unavailable'
OUTPUTS = ('real_attribution_confirmation.json', 'scientific_attribution.json',
    'attribution_confidence_matrix.json', 'evidence_chain.json', 'real_deception_plan.json',
    'deception_plan.json', 'counter_intelligence_ops.json', 'adversary_manipulation.json',
    'dossier.json', 'dossier.md')


def arguments(relative, case, profile):
    return [str(case)] + (['--profile', str(profile)] if relative == 'util/deception_countermeasure_engine.py' else [])


def call_api(namespace, relative, name, value):
    owner, _ = SPECS[relative]
    function = getattr(namespace[owner](), name) if owner else namespace[name]
    return function(*[value for p in inspect.signature(function).parameters.values()
                       if p.default is inspect.Parameter.empty])


class LegacyConclusionBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.case = self.root/'case'; (self.case/'derived').mkdir(parents=True)
        (self.case/'derived/threat_intel_enriched.csv').write_text('host,ip,asn,org,asn_country,risk_score\nstored.invalid,192.0.2.1,64500,supplied,ZZ,0\n', encoding='utf-8')
        for name in OUTPUTS: (self.case/'derived'/name).write_bytes(b'Original analyst note\n')
        self.profile = self.root/'profile.json'; self.profile.write_text('{}', encoding='utf-8')
        seal_case(self.case)
        self.policy = offline_policy(); self.policy.__enter__(); self.before = len(violations())

    def tearDown(self):
        blocked = violations()[self.before:]; self.policy.__exit__(None, None, None)
        self.temporary.cleanup(); self.assertEqual(blocked, [])

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None for p in self.root.rglob('*')}

    def invoke(self, main, args, expected):
        output = io.StringIO(); error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as raised: main(args)
        self.assertEqual(raised.exception.code, expected)
        if expected == 1:
            self.assertEqual(output.getvalue(), ''); self.assertIn(REASON, error.getvalue())
        if expected == 0:
            self.assertIn('unavailable', output.getvalue()); self.assertIn('preserved', output.getvalue())

    def test_saved_missing_malformed_sources_are_preserved(self):
        bad = self.root/'malformed'; (bad/'derived').mkdir(parents=True)
        (bad/'derived/threat_actor_profile.json').write_text('{invalid', encoding='utf-8')
        for relative in SPECS:
            main = runpy.run_path(str(REPO/relative), run_name='legacy_import')['main']
            for case in (self.case, self.root/'missing', bad):
                with self.subTest(script=relative, case=case):
                    before = self.snapshot(); self.invoke(main, arguments(relative, case, self.profile), 1)
                    self.assertEqual(self.snapshot(), before); self.assertTrue(verify_case(str(self.case)))

    def test_output_aliases_cannot_overwrite_sources_or_create_paths(self):
        for relative in ('util/attribution_confirmation_engine.py','util/deception_countermeasure_engine.py'):
            main = runpy.run_path(str(REPO/relative), run_name='legacy_import')['main']
            for flag in ('--output','-o'):
                for target in (self.case/'derived/threat_intel_enriched.csv', self.profile, self.root/'new/output.json'):
                    with self.subTest(script=relative, flag=flag, target=target):
                        before = self.snapshot(); self.invoke(main, arguments(relative,self.case,self.profile)+[flag,str(target)],1)
                        self.assertEqual(self.snapshot(),before); self.assertTrue(verify_case(str(self.case)))

    def test_profile_and_token_paths_are_not_read(self):
        for profile in (self.profile, self.root/'missing-profile', self.case):
            relative = 'util/deception_countermeasure_engine.py'
            main = runpy.run_path(str(REPO/relative), run_name='legacy_import')['main']
            before = self.snapshot(); self.invoke(main, arguments(relative,self.case,profile),1)
            self.assertEqual(self.snapshot(), before)
        main = runpy.run_path(str(REPO/'advanced/strategic_correlator.py'), run_name='legacy_import')['main']
        for flags in (['--place-tokens-file',str(self.profile)],['--place-tokens-file',str(self.root/'missing-tokens')],['--disable-country-detection']):
            before = self.snapshot(); self.invoke(main,[str(self.case),*flags],1); self.assertEqual(self.snapshot(),before)

    def test_high_level_apis_reject_opaque_arguments(self):
        class Opaque:
            def __fspath__(self): raise AssertionError('Argument inspected')
            def __str__(self): raise AssertionError('Argument inspected')
            def __truediv__(self, other): raise AssertionError('Argument inspected')
            def __iter__(self): raise AssertionError('Argument inspected')
            def __getitem__(self, key): raise AssertionError('Argument inspected')
            def get(self, *args): raise AssertionError('Argument inspected')
        for relative, (_, names) in SPECS.items():
            namespace = runpy.run_path(str(REPO/relative),run_name='legacy_import')
            for name in names:
                with self.subTest(script=relative,api=name), self.assertRaisesRegex(RuntimeError, REASON):
                    call_api(namespace,relative,name,Opaque())

    def test_apis_do_not_touch_saved_sources(self):
        for relative, (_, names) in SPECS.items():
            namespace = runpy.run_path(str(REPO/relative),run_name='legacy_import')
            for name in names:
                with self.subTest(script=relative,api=name):
                    before = self.snapshot()
                    with self.assertRaisesRegex(RuntimeError,REASON): call_api(namespace,relative,name,self.case)
                    self.assertEqual(self.snapshot(),before); self.assertTrue(verify_case(str(self.case)))

    def test_exact_help_errors_and_option_prefixes(self):
        for relative in SPECS:
            main = runpy.run_path(str(REPO/relative),run_name='legacy_import')['main']
            accepted = arguments(relative,self.case,self.profile)
            entries = [(['--help'],0),(['-h'],0),([],2),(accepted+['--unsupported'],2)]
            entries += [(accepted+[flag],2) for flag in ('--h','--he','--hel')]
            if relative.startswith('util/'):
                entries += [(accepted+[flag,str(self.profile)],2) for flag in ('--o','--ou','--out','--outp','--outpu')]
            if relative == 'util/deception_countermeasure_engine.py':
                entries += [([str(self.case)],2)]
                entries += [([str(self.case),flag,str(self.profile)],2) for flag in ('--p','--pr','--pro','--prof','--profi','--profil')]
            if relative == 'advanced/strategic_correlator.py':
                for option in ('--place-tokens-file','--disable-country-detection'):
                    entries += [(accepted+[option[:n]],2) for n in range(3,len(option))]
            for args, expected in entries:
                with self.subTest(script=relative,args=args): self.invoke(main,args,expected)

    def test_imports_are_inert(self):
        before = self.snapshot()
        for relative in (*SPECS,'util/validators.py'):
            output = io.StringIO(); error = io.StringIO()
            with redirect_stdout(output), redirect_stderr(error): runpy.run_path(str(REPO/relative),run_name='legacy_import')
            self.assertEqual(output.getvalue()+error.getvalue(),''); self.assertEqual(self.snapshot(),before)


if __name__ == '__main__': unittest.main()
