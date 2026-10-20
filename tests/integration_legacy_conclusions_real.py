"""Actual original EML survives the five unavailable legacy conclusion publishers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from integration_legacy_origin_update_real import REPO, seal_case, verify_case, snapshot
from test_legacy_conclusion_boundary import SPECS, OUTPUTS, REASON, arguments


def invoke(relative, root, outside, args, entry='execute', expected=1):
    script = REPO/relative
    owner, _ = SPECS[relative]
    code = '''import inspect,os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
argv=list(sys.argv); path=list(sys.path); cwd=os.getcwd(); threads=set(threading.enumerate())
protected=[os.path.normcase(os.path.abspath(p)) for p in %r]; attempts=[]
def forbid_source_io(event,args):
    if event in ('os.rename','os.link','os.symlink'): paths=args[:2]
    elif event in ('open','os.chdir','os.listdir','os.scandir','os.mkdir','os.remove','os.rmdir','os.chmod','os.utime','os.truncate'): paths=args[:1]
    else: return
    for value in paths:
        if not isinstance(value,(str,os.PathLike)): continue
        absolute=os.path.normcase(os.path.abspath(value))
        if any(absolute==p or absolute.startswith(p+os.sep) for p in protected):
            attempts.append(event); raise AssertionError('Conclusion attempted source I/O: '+event)
sys.addaudithook(forbid_source_io)
try:
    with offline_policy():
        entry=%r
        namespace=runpy.run_path(%r,run_name='__main__' if entry=='execute' else 'legacy_import')
        if entry=='main': namespace['main'](%r)
        if entry=='main-argv': namespace['main']()
        if entry.startswith('api:'):
            class Opaque:
                def __fspath__(self): raise AssertionError('Argument inspected')
                def __str__(self): raise AssertionError('Argument inspected')
                def __truediv__(self,other): raise AssertionError('Argument inspected')
                def __iter__(self): raise AssertionError('Argument inspected')
                def __getitem__(self,key): raise AssertionError('Argument inspected')
                def get(self,*args): raise AssertionError('Argument inspected')
            name=entry.split(':',1)[1]; owner=%r
            function=getattr(namespace[owner](),name) if owner else namespace[name]
            try:
                function(*[Opaque() for p in inspect.signature(function).parameters.values() if p.default is inspect.Parameter.empty])
            except RuntimeError as error:
                assert %r in str(error),error
                print(str(error),file=sys.stderr); raise SystemExit(1)
            else: raise AssertionError('Unvalidated API returned a result')
finally:
    assert not attempts and not violations(),(attempts,violations())
    assert os.getcwd()==cwd and sys.argv==argv and sys.path==path,'Process state changed'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('requests','paw.__main__','paw.core.trace','paw.core.evidence','paw.core.verify'):
        assert name not in sys.modules,name
    print('CONCLUSION_NO_SOURCE_OR_NETWORK_ACCESS',file=sys.stderr)
''' % (str(REPO),str(script),args,[str(root),str(outside)],entry,str(script),args,owner,REASON)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1'); env.pop('PYTHONPATH',None)
    result = subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,capture_output=True,timeout=30)
    output = (result.stdout+result.stderr).decode('utf-8')
    assert 'CONCLUSION_NO_SOURCE_OR_NETWORK_ACCESS' in output and result.returncode == expected, output
    if expected == 1: assert REASON in output and result.stdout == b'',output
    if args in (['--help'],['-h']): assert 'unavailable' in output and 'preserved' in output,output
    if entry == 'import': assert result.stdout == b'',output


def main():
    with tempfile.TemporaryDirectory(prefix='paw-legacy-conclusions-real-') as temporary:
        base = Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve()
        root = base/'work'; root.mkdir(parents=True)
        raw = next((REPO/'inbox').glob('*.eml')).read_bytes(); (root/'input.eml').write_bytes(raw)
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result = subprocess.run([sys.executable,'-X','utf8','-m','paw','full','input.eml',
            '--no-egress','--deadline','90','--stage-timeout','45'],cwd=root,env=env,capture_output=True,timeout=120)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode == 0,result.stdout+result.stderr
        completed, = (p for p in (root/'cases').glob('case-*') if p.is_dir())
        control, = (p for p in (root/'jobs').glob('analysis_*') if p.is_dir())
        assert json.loads((control/'supervisor.json').read_text(encoding='utf-8'))['tree_stopped']
        execution = json.loads((completed/'execution.json').read_text(encoding='utf-8'))
        assert execution['no_egress'] and not execution['blocked_operations']
        assert (completed/'input.eml').read_bytes() == raw and verify_case(str(completed))
        sealed = root/'cases/legacy-sealed'; (sealed/'derived').mkdir(parents=True)
        (sealed/'derived/threat_intel_enriched.csv').write_text('host,ip,asn,org,asn_country,risk_score\nstored.invalid,192.0.2.1,64500,supplied,ZZ,0\n',encoding='utf-8')
        for name in OUTPUTS: (sealed/'derived'/name).write_bytes(b'Original analyst note\n')
        seal_case(sealed)
        extras=[]
        for mode in ('unsealed','malformed-source','blocked-owner-metadata'):
            case=root/'cases'/mode; (case/'derived').mkdir(parents=True)
            (case/'derived/threat_actor_profile.json').write_text('{invalid' if mode=='malformed-source' else '{}',encoding='utf-8')
            if mode=='blocked-owner-metadata':
                identifier='analysis_'+'8'*32
                (case/'manifest.json').write_text(json.dumps({'analysis_job':identifier}),encoding='utf-8')
                (root/'jobs'/(identifier+'.json')).write_text('{"status":"running"}',encoding='utf-8')
            extras.append(case)
        outside=base/'outside'; outside.mkdir(); (outside/'retained.txt').write_bytes(b'Outside source')
        profile=root/'profile.json'; profile.write_text('{}',encoding='utf-8')
        before=snapshot(root),snapshot(outside)
        guarded=direct=0
        for relative,(_,names) in SPECS.items():
            for case in (completed,sealed,*extras,root/'cases/missing',outside):
                invoke(relative,root,outside,arguments(relative,case,profile)); guarded+=1
                assert (snapshot(root),snapshot(outside))==before
            accepted=arguments(relative,sealed,profile)
            entries=[([], 'import',0),(accepted,'main',1),(accepted,'main-argv',1),
                (['--help'],'execute',0),(['-h'],'execute',0),([],'execute',2),(accepted+['--unsupported'],'execute',2)]
            entries += [(accepted+[flag],'execute',2) for flag in ('--h','--he','--hel')]
            entries += [([], 'api:'+name,1) for name in names]
            if relative.startswith('util/'):
                for target in (sealed/'derived/threat_intel_enriched.csv',profile,outside/'retained.txt',outside/'missing-parent/new.json'):
                    for flag in ('--output','-o'):
                        entries += [(accepted+[flag,str(target)],entry,1) for entry in ('execute','main')]
                entries += [(accepted+[flag,str(profile)],'execute',2) for flag in ('--o','--ou','--out','--outp','--outpu')]
            if relative=='util/deception_countermeasure_engine.py':
                for target in (root/'missing-profile',sealed,profile):
                    entries += [([str(sealed),flag,str(target)],'execute',1) for flag in ('--profile','-p')]
                entries += [([str(sealed),flag,str(profile)],'execute',2) for flag in ('--p','--pr','--pro','--prof','--profi','--profil')]
                entries.append(([str(sealed)],'execute',2))
            if relative=='advanced/strategic_correlator.py':
                entries += [(accepted+['--place-tokens-file',str(target)],'execute',1) for target in (profile,root/'missing-tokens',outside/'retained.txt')]
                entries.append((accepted+['--disable-country-detection'],'execute',1))
                for option in ('--place-tokens-file','--disable-country-detection'):
                    entries += [(accepted+[option[:n]],'execute',2) for n in range(3,len(option))]
            for args,entry,expected in entries:
                invoke(relative,root,outside,args,entry,expected); guarded+=1
                assert (snapshot(root),snapshot(outside))==before
            direct_env=dict(env); direct_env.pop('PYTHONPATH',None)
            direct_entries=[(accepted,1),(['--help'],0),(['-h'],0),([],2),(accepted+['--h'],2)]
            if relative.startswith('util/'):
                direct_entries += [(accepted+[flag,str(profile)],1) for flag in ('--output','-o')]
            if relative=='advanced/strategic_correlator.py':
                direct_entries += [(accepted+['--place-tokens-file',str(profile)],1),(accepted+['--disable-country-detection'],1)]
            for args,expected in direct_entries:
                result=subprocess.run([sys.executable,'-X','utf8',str(REPO/relative),*args],cwd=root,env=direct_env,capture_output=True,timeout=30)
                assert result.returncode==expected,result.stdout+result.stderr
                if expected!=2: assert b'unavailable' in result.stdout+result.stderr
                assert (snapshot(root),snapshot(outside))==before
                direct+=1
        # The sixth external file is an unused library, not an analysis launcher.
        code="import runpy; runpy.run_path(%r,run_name='legacy_import')" % str(REPO/'util/validators.py')
        result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=direct_env,capture_output=True,timeout=30)
        assert result.returncode==0 and not result.stdout and not result.stderr
        assert (snapshot(root),snapshot(outside))==before
        for command in ('verify','export'):
            args=[command,'--case',str(completed)]+(['--format','zip'] if command=='export' else [])
            result=subprocess.run([sys.executable,'-X','utf8','-m','paw',*args],cwd=root,env=env,capture_output=True,timeout=30)
            assert result.returncode==0,result.stdout+result.stderr
        with zipfile.ZipFile(str(completed)+'.zip') as archive:
            for relative,data in before[0].items():
                if data is not None and relative.startswith(completed.relative_to(root).as_posix()+'/'):
                    assert archive.read(completed.name+'/'+Path(relative).relative_to(completed.relative_to(root)).as_posix())==data
        assert (completed/'input.eml').read_bytes()==raw
        assert verify_case(str(completed)) and verify_case(str(sealed))
    print(json.dumps({'status':'passed','cold_guarded_legacy_processes':guarded,'direct_stdlib_processes':direct,
        'inert_validator_library_imports':1,'high_level_apis':sum(len(names) for _,names in SPECS.values()),
        'actual_full_original_eml_analyses':1,'actual_cli_verify_and_zip':True,
        'scope':'Five legacy conclusion publishers and sixteen principal APIs unavailable before source/argument access. Source/profile/token/output preservation; no source I/O or blocked network attempts. Declared owner fixtures, not live workers. Remaining helpers unvalidated; no OS isolation, actor attribution, deployed monitoring or classifier accuracy claim.'},indent=2))


if __name__=='__main__': main()
