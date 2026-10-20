"""Actual original EML survives unavailable legacy forecasts, APIs and explicit output paths."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from integration_legacy_origin_update_real import REPO, seal_case, verify_case, snapshot

SCRIPTS = (REPO/'util/operational_pattern_predictor.py', REPO/'advanced/operational_pattern_predictor.py')
REASON = 'Legacy operational prediction unavailable'


def invoke(script, root, outside, arguments, entry='execute', expected=1):
    code = """import os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
argv=list(sys.argv); path=list(sys.path); cwd=os.getcwd(); threads=set(threading.enumerate())
protected=[os.path.normcase(os.path.abspath(p)) for p in %r]; attempts=[]
def forbid_source_io(event,args):
    if event=='import' and (args[0]=='numpy' or args[0].startswith('numpy.')):
        attempts.append('numpy import'); raise AssertionError('Optional NumPy import attempted')
    if event in ('os.rename','os.link','os.symlink'): paths=args[:2]
    elif event in ('open','os.chdir','os.listdir','os.scandir','os.mkdir','os.remove','os.rmdir','os.chmod','os.utime','os.truncate'): paths=args[:1]
    else: return
    for value in paths:
        if not isinstance(value,(str,os.PathLike)): continue
        absolute=os.path.normcase(os.path.abspath(value))
        if any(absolute==p or absolute.startswith(p+os.sep) for p in protected):
            attempts.append(event); raise AssertionError('Prediction attempted source I/O: '+event)
sys.addaudithook(forbid_source_io)
try:
    with offline_policy():
        entry=%r
        namespace=runpy.run_path(%r,run_name='__main__' if entry=='execute' else 'legacy_import')
        if entry=='main': namespace['main'](%r)
        if entry.startswith('api:'):
            class Opaque:
                def __fspath__(self): raise AssertionError('Argument inspected')
                def __str__(self): raise AssertionError('Argument inspected')
                def __truediv__(self,other): raise AssertionError('Argument inspected')
                def __iter__(self): raise AssertionError('Argument inspected')
                def items(self): raise AssertionError('Argument inspected')
                def get(self,*args): raise AssertionError('Argument inspected')
            opaque=Opaque()
            try:
                name=entry.split(':',1)[1]
                if name=='predict_infrastructure_evolution': namespace['ThreatActorBehaviorModel']().predict_infrastructure_evolution(opaque)
                else: namespace[name](*([opaque]*namespace[name].__code__.co_argcount))
            except RuntimeError as error:
                assert %r in str(error),error
                print(str(error),file=sys.stderr); raise SystemExit(1)
            else: raise AssertionError('Writer returned a result')
finally:
    assert not attempts and not violations(),(attempts,violations())
    assert os.getcwd()==cwd and sys.argv==argv and sys.path==path,'Process state changed'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('numpy','requests','paw.__main__','paw.core.trace','paw.core.evidence','paw.core.verify'):
        assert name not in sys.modules,name
    print('PREDICTION_NO_SOURCE_OR_NETWORK_ACCESS',file=sys.stderr)
""" % (str(REPO), str(script), arguments, [str(root), str(outside)], entry, str(script), arguments, REASON)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1'); env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root, env=env,
                            capture_output=True, timeout=30)
    output = (result.stdout+result.stderr).decode('utf-8')
    assert 'PREDICTION_NO_SOURCE_OR_NETWORK_ACCESS' in output and result.returncode == expected, output
    if expected == 1: assert REASON in output and result.stdout == b'', output
    if arguments in (['--help'], ['-h']): assert 'unavailable' in output and 'preserved' in output, output
    if entry == 'import': assert result.stdout == b'', output


def main():
    with tempfile.TemporaryDirectory(prefix='paw-legacy-predictions-real-') as temporary:
        base = Path(os.environ.get('PAW_VERIFICATION_DIR', temporary)).resolve()
        root = base/'work'; root.mkdir(parents=True)
        raw = next((REPO/'inbox').glob('*.eml')).read_bytes(); (root/'input.eml').write_bytes(raw)
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'full', 'input.eml',
            '--no-egress', '--deadline', '90', '--stage-timeout', '45'], cwd=root, env=env,
            capture_output=True, timeout=120)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode == 0, result.stdout+result.stderr
        completed, = (p for p in (root/'cases').glob('case-*') if p.is_dir())
        control, = (p for p in (root/'jobs').glob('analysis_*') if p.is_dir())
        assert json.loads((control/'supervisor.json').read_text(encoding='utf-8'))['tree_stopped']
        execution = json.loads((completed/'execution.json').read_text(encoding='utf-8'))
        assert execution['no_egress'] and not execution['blocked_operations']
        assert (completed/'input.eml').read_bytes() == raw and verify_case(str(completed))
        sealed = root/'cases/legacy-sealed'; (sealed/'derived').mkdir(parents=True)
        csv = 'host,ip,asn,risk_score\nstored.invalid,192.0.2.1,64500,0\n'
        (sealed/'derived/threat_intel_enriched.csv').write_text(csv, encoding='utf-8')
        for name in ('operational_predictions.json','infrastructure_evolution.json','threat_actor_timeline.json',
                     'next_targets_prediction.json','countermeasure_effectiveness.json'):
            (sealed/'derived'/name).write_bytes(b'Original analyst note\n')
        seal_case(sealed)
        extras = []
        for mode in ('unsealed', 'malformed-source', 'blocked-owner-metadata'):
            case = root/'cases'/mode; (case/'derived').mkdir(parents=True)
            (case/'derived/threat_intel_enriched.csv').write_text(csv, encoding='utf-8')
            (case/'attribution_matrix.json').write_text('{invalid' if mode == 'malformed-source' else '{}', encoding='utf-8')
            if mode == 'blocked-owner-metadata':
                identifier = 'analysis_'+'7'*32
                (case/'manifest.json').write_text(json.dumps({'analysis_job': identifier}), encoding='utf-8')
                (root/'jobs'/(identifier+'.json')).write_text('{"status":"running"}', encoding='utf-8')
            extras.append(case)
        outside = base/'outside'; outside.mkdir(); (outside/'retained.txt').write_bytes(b'Outside source')
        before = snapshot(root), snapshot(outside)
        targets = [completed, sealed, *extras, root/'cases/missing', outside]
        guarded = direct = 0
        for script in SCRIPTS:
            for target in targets:
                invoke(script, root, outside, [str(target)]); guarded += 1
                assert (snapshot(root), snapshot(outside)) == before
            entries = [([], 'import', 0), ([str(sealed)], 'main', 1),
                (['--help'], 'execute', 0), (['-h'], 'execute', 0), ([], 'execute', 2),
                ([str(sealed), '--unsupported'], 'execute', 2)]
            entries.extend(([str(sealed), flag], 'execute', 2) for flag in ('--h', '--he', '--hel'))
            if script.parent.name == 'advanced':
                entries.extend(([], 'api:'+name, 1) for name in ('build_evolution','build_actor_timeline',
                    'predict_targets','countermeasure_effectiveness','write_outputs'))
            else:
                entries.append(([], 'api:predict_infrastructure_evolution', 1))
                for output in (sealed/'derived/threat_intel_enriched.csv', outside/'retained.txt', outside/'missing-parent/new.json'):
                    for flag in ('--output','-o'):
                        for entry in ('execute', 'main'):
                            entries.append(([str(sealed), flag, str(output)], entry, 1))
                entries.extend(([str(sealed), flag, str(outside/'retained.txt')], 'execute', 2) for flag in ('--o','--ou','--out','--outp','--outpu'))
            for arguments, entry, expected in entries:
                invoke(script, root, outside, arguments, entry, expected); guarded += 1
                assert (snapshot(root), snapshot(outside)) == before
            direct_env = dict(env); direct_env.pop('PYTHONPATH', None)
            direct_entries = [([str(sealed)], 1), (['--help'], 0), (['-h'], 0),
                    ([str(sealed), '--h'], 2), ([str(sealed), '--he'], 2), ([str(sealed), '--hel'], 2)]
            if script.parent.name == 'util':
                direct_entries.extend(([str(sealed),flag,str(sealed/'derived/threat_intel_enriched.csv')],1) for flag in ('--output','-o'))
                direct_entries.extend(([str(sealed), flag, str(outside/'retained.txt')], 2) for flag in ('--o','--ou','--out','--outp','--outpu'))
            for arguments, expected in direct_entries:
                result = subprocess.run([sys.executable, '-X', 'utf8', str(script), *arguments],
                    cwd=root, env=direct_env, capture_output=True, timeout=30)
                assert result.returncode == expected, result.stdout+result.stderr
                if expected != 2: assert b'unavailable' in result.stdout+result.stderr
                assert (snapshot(root), snapshot(outside)) == before
                direct += 1
        for command in (['verify'], ['export']):
            arguments = [*command, '--case', str(completed)] + (['--format', 'zip'] if command == ['export'] else [])
            result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', *arguments],
                cwd=root, env=env, capture_output=True, timeout=30)
            assert result.returncode == 0, result.stdout+result.stderr
        with zipfile.ZipFile(str(completed)+'.zip') as archive:
            for relative, data in before[0].items():
                if data is not None and relative.startswith(completed.relative_to(root).as_posix()+'/'):
                    assert archive.read(completed.name+'/'+Path(relative).relative_to(completed.relative_to(root)).as_posix()) == data
        assert (completed/'input.eml').read_bytes() == raw
        assert verify_case(str(completed)) and verify_case(str(sealed))
    print(json.dumps({'status': 'passed', 'cold_guarded_legacy_processes': guarded,
        'direct_stdlib_processes': direct, 'actual_full_original_eml_analyses': 1, 'actual_cli_verify_and_zip': True,
        'scope': 'Both legacy prediction publishers and six top-level prediction/publication APIs reject before source/output/argument I/O, without NumPy imports. Exact --output/-o source/outside/new paths and prefixes checked. Original EML, CSV/JSON, notes, seals and exact ZIP bytes preserved. Fixtures are declared, not live workers or calibrated future events. Metadata syscalls are not exhaustively audited; no OS isolation, attribution, forecast confidence, intervention efficacy or accuracy claim.'}, indent=2))


if __name__ == '__main__':
    main()
