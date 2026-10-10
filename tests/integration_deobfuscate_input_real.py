"""Actual standalone CLI, exact UTF-8 bytes and pre-analysis input rejection."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='paw-deob-input-', dir=REPO.parent) as temporary:
        root = Path(temporary); inputs = root/'inputs'; inputs.mkdir()
        raw = '\ufeffCaffè già pagato\r\nStraße Ελληνικά\r\n'.encode('utf-8')
        source = inputs/'utf8.txt'; source.write_bytes(raw)
        invalid = inputs/'invalid.txt'; invalid.write_bytes(b'pa\xffypal\r\nOriginal')
        empty = inputs/'empty.txt'; empty.write_bytes(b'')
        large = inputs/'large.txt'; large.write_bytes(b'a'*(1024*1024+1))
        before = {path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs.iterdir()}
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        control_root = Path(tempfile.gettempdir())
        controls_before = set(control_root.glob('paw-standalone-*'))
        def run(args, expected=0, wrapper=None, cwd=None):
            command = [sys.executable,'-X','utf8'] + ([str(wrapper),'deobfuscate'] if wrapper else ['-m','paw','deobfuscate'])
            result = subprocess.run(command+args, cwd=cwd or root, env=env, capture_output=True, timeout=20)
            assert result.returncode == expected, (args,result.returncode,result.stderr.decode(errors='replace'))
            if expected: assert result.stdout == b'', (args,result.stdout)
            return result
        results = []
        for options, expected_raw in ((['--file',str(source)],raw),
                                     (['--text','Inline\r\nCaffè'], 'Inline\r\nCaffè'.encode()),
                                     (['--file',str(empty)],b''), (['--text',''],b'')):
            data = json.loads(run(options+['--json']).stdout)
            assert data['deobfuscated_artifacts']['text']['original_text'].encode('utf-8') == expected_raw
            assert data['deobfuscated_artifacts']['text']['final_text'].encode('utf-8') == expected_raw
            assert data['input_observation']['sha256'] == hashlib.sha256(expected_raw).hexdigest()
            assert data['input_observation']['byte_count'] == len(expected_raw)
            assert data['input_observation']['no_egress'] is True
            assert data['input_observation']['case_storage']=='not_created'
            assert data['standalone_execution']['status']=='completed'
            assert data['standalone_execution']['tree_stopped'] is True
            assert data['standalone_execution']['limits']['wall_seconds']==60
            assert data['suspicion_score'] is None and data['deobfuscated_artifacts']['urls']==[]
            results.append(data)
        literal = 'hxxps://example[.]invalid/a%2Fb?x=a%26b'
        url = json.loads(run(['--url',literal,'--json']).stdout)
        assert url['deobfuscated_artifacts']['urls'][0]['original_url']==literal
        assert url['deobfuscated_artifacts']['text']['original_text']==literal
        assert url['input_observation']['source_kind']=='url'
        for args in ([], ['--text','A','--url',literal], ['--text','','--file',str(source)],
                     ['--file',str(source),'--url',literal], ['--file',str(invalid)],
                     ['--file',str(large)], ['--file',str(inputs/'missing')], ['--file',str(inputs)]):
            run(args+['--json'], expected=2)
        human = run(['--file',str(source)]).stdout.decode('utf-8')
        assert hashlib.sha256(raw).hexdigest() in human and 'no sealed case created' in human
        assert 'not_evaluated' in human
        help_text = ' '.join(run(['--help']).stdout.decode('utf-8').split())
        assert 'never fetched' in help_text and 'invalid encoding rejected' in help_text
        assert '--deadline' in help_text and '--memory-mib' in help_text
        for options in (['--deadline','0'],['--deadline','nan'],['--memory-mib','63']):
            run(['--file',str(source),'--json']+options,expected=2)
        timed_out = run(['--file',str(source),'--json','--deadline','0.001'],expected=1)
        assert 'timed_out' in timed_out.stderr.decode('utf-8')
        assert 'no results returned' in timed_out.stderr.decode('utf-8')
        # Instrument the same real input helper used inside the CLI worker; no
        # substituted decoder/result. CLI workers run in a separate process, so
        # this audit observes the helper directly after normal module bootstrap.
        wrapper = root/'observe_dispatch.py'
        wrapper.write_text('''import json,sys
from paw.deobfuscate.input import analyze_input
from paw.core.network_policy import network_allowed
source=sys.argv[sys.argv.index('--file')+1]
opens=[]; attempts=[]
def observe(event,args):
    if event=='open' and args[0]==source: opens.append(not network_allowed())
    if (event.startswith('socket.') and event!='socket.gethostname') or event in {'subprocess.Popen','os.system','os.posix_spawn','os.spawn','os.fork','os.exec','os.startfile','os.startfile/2','_winapi.CreateProcess'}: attempts.append(event)
sys.addaudithook(observe)
print(json.dumps(analyze_input(file=source)))
assert opens==[True], opens
assert not attempts, attempts
''',encoding='utf-8')
        observed = json.loads(run(['--file',str(source),'--json'],wrapper=wrapper).stdout)
        assert observed=={key:value for key,value in results[0].items() if key!='standalone_execution'}
        # Actual CLI rejection, with a test-only audit stop BEFORE any attempted
        # filesystem open or network/process call can reach the OS. Never probe SMB.
        unc_wrapper = root/'observe_unc_rejection.py'
        unc_wrapper.write_text('''import sys
from paw.__main__ import main
source=sys.argv[sys.argv.index('--file')+1]
attempts=[]
def observe(event,args):
    if event=='open' and args[0]==source:
        attempts.append(event)
        raise AssertionError('Test blocked UNC filesystem access before OS open')
    if (event.startswith('socket.') and event!='socket.gethostname') or event in {'subprocess.Popen','os.system','os.posix_spawn','os.spawn','os.fork','os.exec','os.startfile','os.startfile/2','_winapi.CreateProcess'}:
        attempts.append(event)
        raise AssertionError('Test blocked network/process attempt')
sys.addaudithook(observe)
try:
    main()
except SystemExit as exc:
    assert exc.code==2, exc.code
    assert not attempts, attempts
    raise
raise AssertionError('CLI accepted UNC input')
''',encoding='utf-8')
        for path in (r'\\invalid-host\share\input.txt', '//invalid-host/share/input.txt',
                     r'/\invalid-host/share/input.txt', r'\/invalid-host\share\input.txt',
                     r'\\?\UNC\invalid-host\share\input.txt', '//?/UNC/invalid-host/share/input.txt'):
            rejected = run(['--file',path,'--json'],expected=2,wrapper=unc_wrapper)
            assert 'UNC paths are not accepted' in rejected.stderr.decode('utf-8')
        # Build long literals inside a real CLI wrapper to avoid the OS argument
        # size limit. An audit stop prevents any bootstrap socket/process or
        # temporary transport operation if admission regresses.
        literal_wrapper = root/'observe_literal_rejection.py'
        literal_wrapper.write_text('''import sys
from paw.__main__ import main
kind=sys.argv[2]; variant=sys.argv[3]
values={'two':'é'*524289, 'three':'€'*349526, 'four':'😀'*262145, 'surrogate':chr(0xd800)}
sys.argv=['paw','deobfuscate',kind,values[variant],'--json']
attempts=[]
def observe(event,args):
    if event=='tempfile.mkdtemp' or (event.startswith('socket.') and event!='socket.gethostname') or event in {'subprocess.Popen','os.system','os.posix_spawn','os.spawn','os.fork','os.exec','os.startfile','os.startfile/2','_winapi.CreateProcess'}:
        attempts.append(event)
        raise AssertionError('Test blocked bootstrap/transport operation')
sys.addaudithook(observe)
try:
    main()
except SystemExit as exc:
    assert exc.code==2, exc.code
    assert not attempts, attempts
    raise
raise AssertionError('CLI accepted invalid literal')
''',encoding='utf-8')
        for kind in ('--text','--url'):
            for variant in ('two','three','four','surrogate'):
                rejected = run([kind,variant],expected=2,wrapper=literal_wrapper)
                assert ('valid UTF-8' if variant=='surrogate' else '1 MiB') in rejected.stderr.decode('utf-8')
        # Trusted console-entry-point equivalent outside the analysis directory;
        # only its actual child worker could import these benign cwd shadows.
        entrypoint = root/'trusted_entrypoint.py'
        entrypoint.write_text('from paw.__main__ import main\nmain()\n',encoding='utf-8')
        for shadow in ('paw','psutil'):
            directory = root/('shadow-'+shadow); directory.mkdir()
            marker = directory/'imported.txt'
            if shadow=='paw':
                package = directory/'paw'; package.mkdir(); module = package/'__init__.py'
            else:
                module = directory/'psutil.py'
            module.write_text('from pathlib import Path\nPath('+repr(str(marker))+
                ").write_text('Unexpected cwd import')\nraise RuntimeError('Cwd shadow imported')\n",encoding='utf-8')
            result = json.loads(run(['--file',str(source),'--json'],wrapper=entrypoint,cwd=directory).stdout)
            assert not marker.exists()
            assert result['input_observation']['sha256']==hashlib.sha256(raw).hexdigest()
            assert result['deobfuscated_artifacts']['text']['original_text'].encode('utf-8')==raw
            assert result['standalone_execution']['tree_stopped'] is True
        after = {path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs.iterdir()}
        assert after==before
        assert set(control_root.glob('paw-standalone-*'))==controls_before
        assert not any((root/name).exists() for name in ('cases','jobs','reports','exports'))
        # The common parser still accepts actual supervised email analysis;
        # required standalone-source arguments must not leak into full.
        original = next((REPO/'inbox').glob('*.eml')).read_bytes()
        email = root/'original.eml'; email.write_bytes(original)
        full = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(email),
            '--no-egress','--deadline','60','--stage-timeout','45'],
            cwd=root,env=env,capture_output=True,timeout=90)
        assert full.returncode==0, (full.stdout+full.stderr).decode(errors='replace')[-4000:]
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        cases = list((root/'cases').glob('case-*'))
        assert len(cases)==1 and (cases[0]/'input.eml').read_bytes()==original and verify_case(str(cases[0]))
        assert json.loads((cases[0]/'execution.json').read_text())['no_egress'] is True
        assert email.read_bytes()==original
        print('PASS: 35 actual standalone CLI invocations plus one real input-helper audit; BOM/CRLF/Unicode/empty/literal-URL inputs preserved with byte count/SHA-256; invalid UTF-8, ambiguous, oversized, missing and nonregular inputs fail before output; human/help/JSON consistent. Actual deadline stops the worker with exit 1 and empty stdout; invalid deadline/memory reject with exit 2. Six UNC backslash/forward/mixed/extended spellings rejected with exit 2, empty stdout and zero attempted input opens/network/process calls after CLI bootstrap; audit safety stops prevent OS access on regression. Eight multibyte/surrogate literals reject before bootstrap/transport operations; two real CLI workers ignore cwd package/dependency shadows. Instrumented real input helper reads under the application guard with zero socket/process attempts after module bootstrap; source files unchanged, confirmed-stop temporary controls cleaned, no standalone cases/jobs created. One subsequent actual supervised full --no-egress on an original public EML preserves MIME/seal and verifies common-parser compatibility. Constructed text contracts, not phishing accuracy or OS isolation.')


if __name__ == '__main__': main()
