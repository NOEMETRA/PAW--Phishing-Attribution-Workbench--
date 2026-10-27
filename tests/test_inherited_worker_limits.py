"""Actual harmless no-egress CLI workers below inherited POSIX ceilings."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
INSTALLED = os.environ.get('PAW_TEST_INHERITED_INSTALLED') == '1'


def environment():
    value = dict(os.environ)
    if INSTALLED:
        value.pop('PYTHONPATH', None); value.pop('PYTHONHOME', None)
        value['PYTHONNOUSERSITE'] = '1'
    else: value['PYTHONPATH'] = str(REPO)
    return value


@unittest.skipUnless(os.name == 'posix', 'POSIX inherited resource ceilings')
class InheritedWorkerLimits(unittest.TestCase):
    def exercise(self, kind, ceiling):
        import resource
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); source = folder/'owned.bin'
            original = b'Content-Type: text/plain\r\n\r\nOwned harmless bytes.\n'
            source.write_bytes(original); workspace = folder/'workspace'
            action = ['inspect-source'] if kind == 'bytes' else ['inspect-representations']
            arguments = [str(source), '--workdir', str(workspace)]
            if kind != 'bytes': arguments += ['--interpretation', 'mime']
            def inherited():
                if ceiling == 'file': resource.setrlimit(resource.RLIMIT_FSIZE, (8*1024**2, 8*1024**2))
                elif ceiling == 'cpu': resource.setrlimit(resource.RLIMIT_CPU, (5, 6))
                elif ceiling == 'memory': resource.setrlimit(resource.RLIMIT_AS, (192*1024**2, 192*1024**2))
                else: raise AssertionError('unknown test ceiling')
            result = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', *action, *arguments],
                cwd=folder, env=environment(), preexec_fn=inherited,
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            value = json.loads(result.stdout); worker = value['worker']
            self.assertEqual(worker['status'], 'completed'); self.assertTrue(value['supervisor']['tree_stopped'])
            case = workspace/'cases'/worker['case_id']
            self.assertEqual((case/'source.bin').read_bytes(), original); self.assertEqual(source.read_bytes(), original)
            from paw.core.verify import verify_case
            if INSTALLED: self.assertNotIn(REPO, Path(sys.modules[verify_case.__module__].__file__).resolve().parents)
            self.assertTrue(verify_case(case))
            execution = json.loads((case/'execution.json').read_bytes())
            self.assertEqual(execution['sample_execution'], 'not_performed')
            self.assertTrue(execution['no_egress'])
            if ceiling == 'memory': self.assertEqual(execution['limits']['address_space_bytes'], 192*1024**2)
            if ceiling == 'cpu': self.assertEqual(execution['limits']['cpu_seconds'], 5)
            if ceiling == 'file': self.assertEqual(execution['limits']['file_bytes'], 8*1024**2)

    def test_representation_worker_under_inherited_file_limit(self): self.exercise('representations', 'file')
    def test_byte_worker_under_inherited_file_limit(self): self.exercise('bytes', 'file')
    def test_representation_worker_under_inherited_cpu_limit(self): self.exercise('representations', 'cpu')
    def test_byte_worker_under_inherited_cpu_limit(self): self.exercise('bytes', 'cpu')
    def test_representation_worker_under_inherited_memory_limit(self): self.exercise('representations', 'memory')
    def test_byte_worker_under_inherited_memory_limit(self): self.exercise('bytes', 'memory')

    def test_kernel_retains_each_soft_and_hard_ceiling_and_blocks_file_overflow(self):
        code = '''import errno,json,resource,signal
from pathlib import Path
from paw.core.runtime import tighten_posix_limit
ceilings = {resource.RLIMIT_CPU:(5,6), resource.RLIMIT_AS:(192*1024**2,224*1024**2), resource.RLIMIT_FSIZE:(4096,8192)}
for kind,limits in ceilings.items(): resource.setrlimit(kind,limits)
tighten_posix_limit(resource.RLIMIT_CPU,10,11)
tighten_posix_limit(resource.RLIMIT_AS,256*1024**2)
tighten_posix_limit(resource.RLIMIT_FSIZE,80*1024**2)
assert {kind:resource.getrlimit(kind) for kind in ceilings} == ceilings
signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
blocked=False
try: Path('owned-overflow').write_bytes(b'x'*16384)
except OSError as error: blocked=error.errno==errno.EFBIG
assert blocked and Path('owned-overflow').stat().st_size <= 4096
print(json.dumps({'retained':True,'overflow_blocked':blocked}))
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-P', '-B', '-c', code], cwd=directory,
                env=environment(), stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout), {'retained': True, 'overflow_blocked': True})


if __name__ == '__main__': unittest.main()
