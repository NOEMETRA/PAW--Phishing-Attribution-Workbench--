"""Reuse shared process controls without creating an analysis job or sealed case."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from .core.runtime import RunLimits, atomic_json, read_progress, supervise

MAX_RESULT_BYTES = 32 * 1024 * 1024


def restrict_control_access(directory):
    """Protect transport contents before writing, independent of TEMP inheritance."""
    if os.name != 'nt':
        os.chmod(directory, 0o700)
        return
    # Python 3.11/3.12 Windows mkdir ignores mode 0700. Apply an explicit,
    # protected, inheritable DACL for the object owner and SYSTEM instead.
    import ctypes
    from ctypes import wintypes
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    security.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    security.SetFileSecurityW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            'D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)', 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not security.SetFileSecurityW(str(directory), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


class StandaloneFailure(RuntimeError):
    def __init__(self, message, outcome):
        super().__init__(message)
        self.outcome = outcome


def admit_request(*, text=None, file=None, url=None, deadline=60, memory_mib=256):
    from .deobfuscate.input import validate_input_source
    # Invalid source/UNC and limit admission must not launch a worker.
    kind, value = validate_input_source(text=text, file=file, url=url)
    if isinstance(memory_mib, bool) or not isinstance(memory_mib, int) or not 64 <= memory_mib <= 4096:
        raise ValueError('Worker memory must be between 64 and 4096 MiB')
    limits = RunLimits(wall_seconds=deadline, stage_seconds=deadline,
        memory_bytes=memory_mib*1024**2, log_bytes=1024**2)
    return kind, value, limits


async def run_deobfuscation(*, text=None, file=None, url=None, deadline=60, memory_mib=256):
    kind, value, limits = admit_request(text=text, file=file, url=url, deadline=deadline, memory_mib=memory_mib)
    temporary_root = Path(tempfile.gettempdir()).resolve()
    control = Path(tempfile.mkdtemp(prefix='paw-standalone-', dir=temporary_root)).resolve()
    try:
        restrict_control_access(control)
    except OSError:
        control.rmdir()  # Empty directory; no request or worker exists yet.
        raise
    try:
        request = control/'request.json'
        atomic_json(request, {kind:value})
        try:
            # Python >=3.11 -P excludes cwd from module/dependency lookup;
            # PYTHONPATH below contains only this trusted installation root.
            outcome = await supervise([sys.executable,'-P','-X','utf8','-m','paw.standalone_worker',str(request)],
                cwd=Path.cwd(), control=control, limits=limits,
                env={'PYTHONPATH':str(Path(__file__).resolve().parents[1])})
        except (OSError, RuntimeError) as exc:
            outcome = read_progress(control/'supervisor.json')
            retained = '; temporary control retained at '+str(control) if outcome.get('tree_stopped') is not True else ''
            raise StandaloneFailure('Worker launch/control failed; no results returned'+retained, outcome) from exc
        if outcome.get('tree_stopped') is not True:
            raise StandaloneFailure('Worker shutdown not confirmed; temporary control retained at '+str(control), outcome)
        if outcome.get('status') != 'exited' or outcome.get('returncode') != 0:
            raise StandaloneFailure(str(outcome.get('status'))+': '+
                (outcome.get('error') or 'Worker failed')+'; no results returned', outcome)
        try:
            with (control/'result.json').open('rb') as stream:
                raw = stream.read(MAX_RESULT_BYTES+1)
            if len(raw) > MAX_RESULT_BYTES:
                raise StandaloneFailure('Worker result exceeds 32 MiB; no results returned', outcome)
            response = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise StandaloneFailure('Worker result unavailable or invalid; no results returned', outcome) from exc
        if not isinstance(response, dict):
            raise StandaloneFailure('Worker result is incomplete; no results returned', outcome)
        if response.get('status') == 'input_error': raise ValueError(response['error'])
        if response.get('status') != 'completed' or not isinstance(response.get('result'), dict):
            raise StandaloneFailure('Worker result is incomplete; no results returned', outcome)
        result = response['result']
        result['standalone_execution'] = {
            'schema_version':1, 'status':'completed', 'tree_stopped':True,
            'elapsed_seconds':outcome['elapsed_seconds'], 'limits':outcome['limits'],
            'containment':outcome['containment'], 'network_isolation':'application_policy_only',
            'scope':'worker startup, input read, analysis and result writing',
            'case_storage':'not_created',
        }
        return result
    finally:
        # Never remove controls while a writer may still be active. A unique
        # directory plus confirmed shutdown prevents deleting another run's data.
        if read_progress(control/'supervisor.json').get('tree_stopped') is True:
            if control.parent != temporary_root or not control.name.startswith('paw-standalone-'):
                raise RuntimeError('Unexpected standalone temporary directory')
            shutil.rmtree(control)


def analyze_supervised(*, text=None, file=None, url=None, deadline=60, memory_mib=256):
    # Windows asyncio bootstrap creates a local socketpair. Reject invalid/UNC
    # inputs before even that supervisor bootstrap, as well as before worker launch.
    kind, value, _ = admit_request(text=text, file=file, url=url, deadline=deadline, memory_mib=memory_mib)
    return asyncio.run(run_deobfuscation(**{kind:value}, deadline=deadline, memory_mib=memory_mib))
