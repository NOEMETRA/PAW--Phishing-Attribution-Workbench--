"""Explicit harmless acceptance sources. No downloaded code or real target."""
SOURCES = {
    'positive': b"import os,json\nfrom pathlib import Path\ns=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)\nflags=set(Path('/proc/cpuinfo').read_text().split('flags',1)[1].splitlines()[0].split(':',1)[1].split())\nassert os.getuid()==os.getgid()==65534 and int(s['CapEff'],16)==0 and s['NoNewPrivs'].strip()=='1'\nassert sorted(p.name for p in Path('/sys/class/net').iterdir())==['lo']\nassert os.readlink('/proc/self/fd/0')=='/dev/null'\nassert not flags.intersection({'avx','avx2','xsave'})\nPath('previous-job-marker').write_text('owned grant reset marker')\nprint(json.dumps({'owned_marker':'ONE-USE-OFFLINE','cpu_avx_xsave_absent':True,'uid':os.getuid()}))\n",
    'failed': b"import sys\nprint('OWNED-EXPECTED-FAILURE')\nsys.exit(7)\n",
    'timeout': b"import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nif os.fork()==0:\n time.sleep(12);open('late-marker','w').write('owned-late-marker')\nelse: time.sleep(20)\n",
    'cancel': b"import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nif os.fork()==0: time.sleep(12)\nelse: time.sleep(20)\n",
    'overflow': b"import os\nos.write(1,b'OWNED-OUTPUT-'*400)\n",
}
CPU_DISABLED = ('avx', 'avx2', 'fma', 'f16c', 'xsave', 'xsaveopt', 'xsavec', 'xsaves', 'xgetbv1')
