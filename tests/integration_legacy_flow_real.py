"""Actual offline case/graphs/export preserved; legacy request-flow writer rejects."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from integration_legacy_origin_update_real import snapshot

SCRIPT = REPO/'util/build_flow_mermaid.py'
REASON = 'Standalone request-flow publication unavailable'


def invoke(root,outside,arguments,entry='execute',expected=1):
    code = """import os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
argv=list(sys.argv); path=list(sys.path); cwd=os.getcwd()
threads=set(threading.enumerate())
protected=[os.path.normcase(os.path.abspath(p)) for p in %r]
attempts=[]
def forbid_source_io(event,args):
    if event in ('os.rename','os.link','os.symlink'): paths=args[:2]
    elif event in ('open','os.chdir','os.listdir','os.scandir','os.mkdir','os.remove',
                   'os.rmdir','os.chmod','os.utime','os.truncate'): paths=args[:1]
    else: return
    for value in paths:
        if not isinstance(value,(str,os.PathLike)): continue
        absolute=os.path.normcase(os.path.abspath(value))
        if any(absolute==p or absolute.startswith(p+os.sep) for p in protected):
            attempts.append(event)
            raise AssertionError('Legacy flow attempted source I/O: '+event)
sys.addaudithook(forbid_source_io)
try:
    with offline_policy():
        entry=%r
        namespace=runpy.run_path(%r,run_name='__main__' if entry=='execute' else 'legacy_import')
        if entry=='main': namespace['main'](%r)
        if entry in ('build','opaque-build'):
            class OpaquePath:
                def __fspath__(self): raise AssertionError('Path was inspected')
                def __str__(self): raise AssertionError('Path was inspected')
                def __truediv__(self,other): raise AssertionError('Path was inspected')
            target=OpaquePath() if entry=='opaque-build' else %r[0]
            try: namespace['build'](target)
            except RuntimeError as error:
                assert %r in str(error),error
                print(str(error),file=sys.stderr)
                raise SystemExit(1)
            else: raise AssertionError('build returned success')
finally:
    assert not attempts and not violations(),(attempts,violations())
    assert os.getcwd()==cwd and sys.argv==argv and sys.path==path,'Process state changed'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('requests','paw.__main__','paw.core.trace','paw.detonate.runner'):
        assert name not in sys.modules,name
    print('LEGACY_FLOW_NO_SOURCE_OR_NETWORK_ACCESS',file=sys.stderr)
""" % (str(REPO),str(SCRIPT),arguments,[str(root),str(outside)],entry,str(SCRIPT),arguments,arguments,REASON)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    text=result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
    assert 'LEGACY_FLOW_NO_SOURCE_OR_NETWORK_ACCESS' in text,text
    assert result.returncode==expected,text
    if expected==1: assert REASON in text and result.stdout==b'',text
    if arguments==['--help']: assert 'unavailable' in text and 'requests.jsonl' in text,text


def main():
    with tempfile.TemporaryDirectory(prefix='paw-legacy-flow-') as temporary:
        base=Path(os.environ.get('PAW_VERIFICATION_DIR',temporary)).resolve()
        root=base/'work'; root.mkdir(parents=True)
        raw=next((REPO/'inbox').glob('*.eml')).read_bytes()
        (root/'input.eml').write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result=subprocess.run([sys.executable,'-X','utf8','-m','paw','full','input.eml','--no-egress',
            '--deadline','90','--stage-timeout','45'],cwd=root,env=env,capture_output=True,timeout=120)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode==0,result.stdout+result.stderr
        completed,=(p for p in (root/'cases').glob('case-*') if p.is_dir())
        control,=(p for p in (root/'jobs').glob('analysis_*') if p.is_dir())
        assert json.loads((control/'supervisor.json').read_text(encoding='utf-8'))['tree_stopped']
        execution=json.loads((completed/'execution.json').read_text(encoding='utf-8'))
        assert execution['no_egress'] and not execution['blocked_operations']
        assert (completed/'input.eml').read_bytes()==raw and verify_case(str(completed))
        saved_graphs={name:(completed/'graphs'/name).read_bytes() for name in ('attribution.mmd','domain.mmd')}
        assert not (completed/'detonation').exists()
        sealed=root/'cases/legacy-sealed'
        (sealed/'detonation').mkdir(parents=True); (sealed/'derived').mkdir()
        requests='{"url":"https://a-b.invalid/p","headers":{"Referer":"https://origin.invalid/"}}\n'
        (sealed/'detonation/requests.jsonl').write_text(requests,encoding='utf-8')
        (sealed/'derived/flow.mmd').write_text('Preserve analyst notes\n',encoding='utf-8')
        seal_case(sealed)
        extras=[]
        for mode in ('unsealed','malformed-log','blocked-owner-metadata'):
            case=root/'cases'/mode; (case/'detonation').mkdir(parents=True)
            (case/'detonation/requests.jsonl').write_text('{invalid' if mode=='malformed-log' else requests,encoding='utf-8')
            if mode=='blocked-owner-metadata':
                identifier='analysis_'+'2'*32
                (case/'manifest.json').write_text(json.dumps({'analysis_job':identifier}),encoding='utf-8')
                (root/'jobs'/(identifier+'.json')).write_text('{"status":"running"}',encoding='utf-8')
            extras.append(case)
        outside=base/'outside'; (outside/'detonation').mkdir(parents=True)
        (outside/'detonation/requests.jsonl').write_text(requests,encoding='utf-8')
        before=snapshot(root),snapshot(outside)
        targets=[completed,sealed,*extras,root/'cases/missing',outside]
        for target in targets:
            invoke(root,outside,[str(target)])
            assert (snapshot(root),snapshot(outside))==before
        invoke(root,outside,[os.path.relpath(outside,root)])
        for arguments,entry,expected in (([],'import',0),([str(sealed)],'main',1),
                ([str(sealed)],'build',1),([str(sealed)],'opaque-build',1),(['--help'],'execute',0),
                ([],'execute',2),([str(sealed),'--unsupported'],'execute',2)):
            invoke(root,outside,arguments,entry,expected)
            assert (snapshot(root),snapshot(outside))==before
        env.pop('PYTHONPATH',None)
        for arguments,expected in (([str(sealed)],1),(['--help'],0)):
            direct=subprocess.run([sys.executable,'-X','utf8',str(SCRIPT),*arguments],cwd=root,
                env=env,capture_output=True,timeout=30)
            assert direct.returncode==expected and b'unavailable' in direct.stdout+direct.stderr
            assert (snapshot(root),snapshot(outside))==before
        exported=subprocess.run([sys.executable,'-X','utf8','-m','paw','export','--case',str(completed),
            '--format','zip'],cwd=root,env=dict(env,PYTHONPATH=str(REPO)),capture_output=True,timeout=30)
        assert exported.returncode==0,exported.stdout+exported.stderr
        with zipfile.ZipFile(str(completed)+'.zip') as archive:
            assert archive.read(completed.name+'/input.eml')==raw
            for name,content in saved_graphs.items():
                assert (completed/'graphs'/name).read_bytes()==content
                assert archive.read(completed.name+'/graphs/'+name)==content
        assert verify_case(str(completed)) and verify_case(str(sealed))
    print('PASS: actual full offline original-EML worker, saved attribution/domain graphs and CLI ZIP; '
          '15 cold guarded legacy paths plus two direct stdlib invocations, execute/main/build/import/arguments, '
          'source/notes/seals unchanged and no blocked operations. Synthetic log/owner fixtures are not real '
          'captures or live processes. Request-flow publication unavailable; no browser/collector/OS isolation claim.')


if __name__=='__main__':
    main()
