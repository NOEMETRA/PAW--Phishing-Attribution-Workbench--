"""Actual supervised review drafts remain available; unsafe legacy publisher rejects."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from integration_legacy_origin_update_real import snapshot

SCRIPT = REPO/'util'/'make_abuse_templates.py'


def invoke(root,outside,arguments,entry='execute',expected=1):
    code = """import os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
argv=list(sys.argv)
path=list(sys.path)
cwd=os.getcwd()
threads=set(threading.enumerate())
protected=[os.path.normcase(os.path.abspath(p)) for p in %r]
attempts=[]
def forbid_source_io(event,args):
    if event in ('os.rename','os.link','os.symlink'):
        paths=args[:2]
    elif event in ('open','os.chdir','os.listdir','os.scandir','os.mkdir',
                   'os.remove','os.rmdir','os.chmod','os.utime','os.truncate'):
        paths=args[:1]
    else: return
    for value in paths:
        if not isinstance(value,(str,os.PathLike)): continue
        absolute=os.path.normcase(os.path.abspath(value))
        if any(absolute==p or absolute.startswith(p+os.sep) for p in protected):
            attempts.append(event)
            raise AssertionError('Legacy generator attempted source I/O: '+event)
sys.addaudithook(forbid_source_io)
try:
    with offline_policy():
        entry=%r
        namespace=runpy.run_path(%r,run_name='__main__' if entry=='execute' else 'legacy_import')
        if entry=='main': namespace['main'](%r)
finally:
    assert not attempts and not violations(),(attempts,violations())
    assert os.getcwd()==cwd and sys.argv==argv and sys.path==path,'Process state changed'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('requests','ipwhois','paw.__main__','paw.core.abuse','paw.core.trace'):
        assert name not in sys.modules,name
    print('LEGACY_ABUSE_NO_SOURCE_OR_NETWORK_ACCESS',file=sys.stderr)
""" % (str(REPO),str(SCRIPT),arguments,[str(root),str(outside)],entry,str(SCRIPT),arguments)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    text=result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
    assert 'LEGACY_ABUSE_NO_SOURCE_OR_NETWORK_ACCESS' in text,text
    assert result.returncode==expected,text
    if expected==1:
        assert 'Legacy abuse-template generation unavailable' in text and result.stdout==b'',text
    if arguments==['--help']:
        assert 'unavailable' in text and '--no-egress' in text,text
    return {'entry':entry,'exit':result.returncode,'no_source_or_network_access':True}


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-abuse-boundary-') as temporary:
        base=Path(temporary)
        root=base/'work'
        root.mkdir()
        raw=next((REPO/'inbox').glob('*.eml')).read_bytes()
        (root/'input.eml').write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        completed=[]
        for language in ('en','it'):
            known=set((root/'cases').glob('case-*'))
            known_jobs=set((root/'jobs').glob('analysis_*'))
            analysis=subprocess.run([sys.executable,'-X','utf8','-m','paw','full','input.eml',
                '--no-egress','--lang',language,'--deadline','90','--stage-timeout','60'],cwd=root,env=env,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
            (root/('full-'+language+'.log')).write_bytes(analysis.stdout)
            assert analysis.returncode==0,analysis.stdout.decode('utf-8')
            case,=set((root/'cases').glob('case-*'))-known
            control,=(p for p in set((root/'jobs').glob('analysis_*'))-known_jobs if p.is_dir())
            supervisor=json.loads((control/'supervisor.json').read_text(encoding='utf-8'))
            execution=json.loads((case/'execution.json').read_text(encoding='utf-8'))
            assert supervisor['tree_stopped'] and supervisor['returncode']==0,supervisor
            assert execution['no_egress'] and not execution['blocked_operations'],execution
            assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
            draft=(case/'package'/('abuse_email_'+language+'.txt')).read_text(encoding='utf-8')
            markers={'en':('LOCAL REVIEW DRAFT - NOT SENT','This draft does not establish a compromised mailbox'),
                     'it':('BOZZA LOCALE PER REVISIONE - NON INVIATA','Questa bozza non accerta account compromessi')}
            assert all(marker in draft for marker in markers[language]),language
            assert 'line 1 shows the first HTTP GET to' not in draft and 'riga 1: primo GET a' not in draft
            local=json.loads((case/'package'/'xarf_report.json').read_text(encoding='utf-8'))
            assert local['status']=='draft' and local['recipient'] is None,local
            assert local['format_compliance']=={'arf':'not_validated','xarf':'not_validated'}
            completed.append(case)
        legacy=root/'cases'/'legacy-sealed'
        (legacy/'derived').mkdir(parents=True)
        (legacy/'transmitting_server.json').write_text('{"ip":"192.0.2.9"}',encoding='utf-8')
        for language in ('en','it'):
            (legacy/'derived'/('abuse_template_'+language+'.txt')).write_text(
                'Preserve analyst supplied '+language+' notes',encoding='utf-8')
        seal_case(legacy)
        extra=[]
        for mode in ('unsealed','malformed','blocked-owner-metadata'):
            case=root/'cases'/mode
            case.mkdir()
            (case/'transmitting_server.json').write_text('{invalid' if mode=='malformed' else '{}',encoding='utf-8')
            if mode=='blocked-owner-metadata':
                identifier='analysis_'+'1'*32
                (case/'manifest.json').write_text(json.dumps({'analysis_job':identifier}),encoding='utf-8')
                (root/'jobs'/(identifier+'.json')).write_text(json.dumps({'status':'running'}),encoding='utf-8')
                seal_case(case)
            extra.append(case)
        outside=base/'outside'
        outside.mkdir()
        (outside/'transmitting_server.json').write_text('{}',encoding='utf-8')
        before=snapshot(root),snapshot(outside)
        targets=[('completed',str(completed[0])),('legacy-sealed',str(legacy)),
                 *[(p.name,str(p)) for p in extra],('missing',str(root/'cases'/'missing')),
                 ('relative-outside',os.path.relpath(outside,root)),('absolute-outside',str(outside))]
        for name,target in targets:
            checks.append({'case':name,**invoke(root,outside,[target])})
            assert (snapshot(root),snapshot(outside))==before,name
        for name,arguments,entry,expected in (
                ('import',[],'import',0),('explicit-main',[str(legacy)],'main',1),
                ('help',['--help'],'execute',0),('missing-argument',[],'execute',2),
                ('invalid-argument',[str(legacy),'--unsupported'],'execute',2)):
            checks.append({'case':name,**invoke(root,outside,arguments,entry,expected)})
            assert (snapshot(root),snapshot(outside))==before,name
        env.pop('PYTHONPATH',None)
        for arguments,expected in (([str(legacy)],1),(['--help'],0)):
            direct=subprocess.run([sys.executable,'-X','utf8',str(SCRIPT),*arguments],cwd=root,
                env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            assert direct.returncode==expected,direct.stderr
            assert b'unavailable' in direct.stdout+direct.stderr
            assert (snapshot(root),snapshot(outside))==before
        for case in [*completed,legacy]:
            assert verify_case(str(case))
        assert all((case/'input.eml').read_bytes()==raw for case in completed)
    print(json.dumps({'status':'passed','original_eml_sha256':hashlib.sha256(raw).hexdigest(),
        'actual_supervised_full_analyses':2,'canonical_review_draft_languages':['en','it'],
        'guarded_legacy_processes':len(checks),'direct_legacy_processes':2,'checks':checks,
        'scope':'Actual completed original-EML analyses retain local unsent review drafts. Legacy publisher rejects without guarded source I/O or blocked operations; sources/notes/seals preserved. Ownership-state and sealed-filesystem fixtures are not live processes or analyzed messages. Direct stdlib invocations separate from guarded claims. No OS isolation, attribution, accuracy or external reporting/conformance claim.'},indent=2))


if __name__=='__main__':
    main()
