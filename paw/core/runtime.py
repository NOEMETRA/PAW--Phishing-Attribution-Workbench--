"""Supervised real processes. Resource controls are not a network sandbox."""
import asyncio
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import signal
import time
import uuid


@dataclass(frozen=True)
class RunLimits:
    wall_seconds: float = 900
    stage_seconds: float = 120
    memory_bytes: int = 2 * 1024 ** 3
    artifact_bytes: int = 512 * 1024 ** 2
    artifact_files: int = 10000
    log_bytes: int = 8 * 1024 ** 2

    def __post_init__(self):
        for value in asdict(self).values():
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError('Runtime limits must be positive')


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        temporary.write_text(json.dumps(value, indent=2, allow_nan=False), encoding='utf-8')
        end = time.monotonic() + .5
        while True:
            try:
                temporary.replace(path)
                break
            except PermissionError as exc:
                # Windows readers may briefly hold a handle without FILE_SHARE_DELETE.
                if os.name != 'nt' or getattr(exc, 'winerror', None) not in {5, 32, 33} or time.monotonic() >= end:
                    raise
                time.sleep(.01)
    finally:
        temporary.unlink(missing_ok=True)


def wait_for_gate():
    """Workers do not import analysis modules or spawn children until contained."""
    gate = os.environ.get('PAW_START_GATE')
    if not gate: return
    end = time.monotonic() + 30
    while not Path(gate).exists():
        if time.monotonic() > end: raise TimeoutError('Supervisor did not release worker')
        time.sleep(.02)
    if os.name != 'nt':
        import resource
        memory = int(os.environ['PAW_MEMORY_BYTES'])
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))


class WindowsJob:
    """Win32 Job Object: tree-wide memory cap and kill on supervisor close."""
    def __init__(self, pid, memory_bytes):
        size = ctypes.c_size_t
        class Basic(ctypes.Structure):
            _fields_ = [('ProcessTime', ctypes.c_longlong), ('JobTime', ctypes.c_longlong),
                ('Flags', wintypes.DWORD), ('MinWS', size), ('MaxWS', size),
                ('Active', wintypes.DWORD), ('Affinity', size),
                ('Priority', wintypes.DWORD), ('Scheduling', wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                ('ReadOps','WriteOps','OtherOps','ReadBytes','WriteBytes','OtherBytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('Basic', Basic), ('IO', IO), ('ProcessMemory', size),
                ('JobMemory', size), ('PeakProcessMemory', size), ('PeakJobMemory', size)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW': ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            'SetInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            'OpenProcess': ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            'AssignProcessToJobObject': ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            'QueryInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
            'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL)}
        for name, (arguments, result) in signatures.items():
            function = getattr(kernel, name)
            function.argtypes, function.restype = arguments, result
        self.kernel, self.handle = kernel, kernel.CreateJobObjectW(None, None)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = Extended()
            info.Basic.Flags = 0x2000 | 0x200 | 0x8  # kill on close, job memory, active count
            info.Basic.Active = 32
            info.JobMemory = memory_bytes
            if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            process = kernel.OpenProcess(0x100 | 0x1, False, pid)
            if not process: raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not kernel.AssignProcessToJobObject(self.handle, process):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally: kernel.CloseHandle(process)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    async def stop(self):
        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_longlong) for name in ('User','Kernel','PeriodUser','PeriodKernel')] + [
                (name, wintypes.DWORD) for name in ('Faults','Total','Active','Terminated')]
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        end = time.monotonic() + 5
        while True:
            info = Accounting()
            if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if not info.Active: return True
            if time.monotonic() > end: return False
            await asyncio.sleep(.02)


def read_progress(path):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError): return {}


def mark_stage(stage, case_id=None):
    path = os.environ.get('PAW_PROGRESS_PATH')
    if not path: return
    value = read_progress(path)
    now = time.time()
    monotonic_now = time.monotonic()
    if 'stage_started_monotonic' in value:
        value.setdefault('stage_timings', []).append({'stage':value['stage'],
            'elapsed_seconds':max(0, monotonic_now-value['stage_started_monotonic'])})
    if case_id and case_id not in value.setdefault('case_ids', []): value['case_ids'].append(case_id)
    value.update(stage=stage, stage_started_epoch=now, stage_started_monotonic=monotonic_now)
    atomic_json(path, value)


def artifact_usage(cwd, progress, limits):
    """Count only cases associated with this worker, never other jobs."""
    count = total = 0
    for case_id in progress.get('case_ids', []):
        root = Path(cwd)/'cases'/case_id
        if Path(case_id).name != case_id or not root.resolve().is_relative_to((Path(cwd)/'cases').resolve()):
            raise ValueError('Invalid case path in worker progress')
        for path in root.rglob('*'):
            if path.is_symlink(): raise ValueError('Symlink in worker evidence')
            if path.is_file():
                count += 1
                try: total += path.stat().st_size
                except FileNotFoundError: continue
                if count > limits.artifact_files or total > limits.artifact_bytes:
                    return True
    return False


async def supervise(command, *, cwd, control, limits=RunLimits(), cancel=None, env=None):
    control = Path(control).resolve()
    control.mkdir(parents=True, exist_ok=True)
    gate, progress_path, log_path = control/'start.gate', control/'progress.json', control/'worker.log'
    gate.unlink(missing_ok=True)
    progress_path.unlink(missing_ok=True)
    environment = dict(os.environ)
    environment.update(env or {})
    environment.update(PAW_START_GATE=str(gate),
        PAW_PROGRESS_PATH=str(progress_path), PAW_MEMORY_BYTES=str(limits.memory_bytes),
        PAW_RUNTIME_LIMITS=json.dumps(asdict(limits)), PYTHONIOENCODING='utf-8')
    process = job = None
    started = time.monotonic()
    status, error = 'failed', None
    try:
        with log_path.open('wb') as log:
            process = await asyncio.create_subprocess_exec(*command, cwd=str(cwd), env=environment,
                stdout=log, stderr=asyncio.subprocess.STDOUT,
                **({'start_new_session':True} if os.name != 'nt' else {}))
            if os.name == 'nt': job = WindowsJob(process.pid, limits.memory_bytes)
            gate.touch()
            while True:
                progress = read_progress(progress_path)
                elapsed = time.monotonic() - started
                stage_elapsed = time.monotonic() - progress['stage_started_monotonic'] if 'stage_started_monotonic' in progress else 0
                if cancel is not None and cancel.is_set():
                    status, error = 'cancelled', 'Cancelled by operator'
                    break
                if elapsed >= limits.wall_seconds or stage_elapsed >= limits.stage_seconds:
                    status, error = 'timed_out', 'Overall deadline exceeded' if elapsed >= limits.wall_seconds else 'Stage deadline exceeded: ' + progress.get('stage', 'unknown')
                    break
                if log_path.stat().st_size > limits.log_bytes or await asyncio.to_thread(artifact_usage, cwd, progress, limits):
                    status, error = 'resource_limited', 'Log or case artifact budget exceeded'
                    break
                if time.monotonic() - started >= limits.wall_seconds:
                    continue
                if process.returncode is not None:
                    status = 'exited'
                    break
                await asyncio.sleep(.1)
    except asyncio.CancelledError:
        status, error = 'interrupted', 'Supervisor stopped'
        raise
    finally:
        tree_stopped = True
        if job is not None:
            try: tree_stopped = await job.stop()
            except OSError: tree_stopped = False
            finally: job.close()
        elif process is not None:
            if os.name != 'nt':
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            elif process.returncode is None: process.kill()
        if process is not None: await process.wait()
        if not tree_stopped and status == 'exited':
            status, error = 'failed', 'Process tree shutdown not confirmed'
        atomic_json(control/'supervisor.json', {'status':status, 'error':error,
            'returncode':process.returncode if process else None,
            'elapsed_seconds':time.monotonic()-started, 'limits':asdict(limits),
            'containment':'windows_job' if os.name == 'nt' else 'posix_process_group',
            'tree_stopped':tree_stopped,
            'network_isolation':'application_policy_only'})
    return read_progress(control/'supervisor.json')


def preserve_interrupted(cwd, control, status, error):
    """Called only after the entire worker tree has stopped. Never delete evidence."""
    from .evidence import seal_case
    if read_progress(Path(control)/'supervisor.json').get('tree_stopped') is False:
        return []  # Keep raw evidence; do not race a still-running writer with sealing.
    cases = []
    for case_id in read_progress(Path(control)/'progress.json').get('case_ids', []):
        if Path(case_id).name != case_id: continue
        case = Path(cwd)/'cases'/case_id
        if not case.is_dir() or not case.resolve().is_relative_to((Path(cwd)/'cases').resolve()): continue
        # A previously sealed completed case in a folder run stays intact.
        if (case/'execution.json').exists() and read_progress(case/'execution.json').get('status') == 'completed':
            from .verify import verify_case
            try: valid = verify_case(case)
            except (OSError, ValueError, KeyError, TypeError): valid = False
            if valid:
                cases.append({'case_id':case_id, 'status':'completed', 'integrity':'verified'})
                continue
        atomic_json(case/'execution.json', {'status':status,'error':error,'assessment_status':'partial'})
        integrity = 'unsealed'
        try:
            seal_case(case)
            integrity = 'sealed_partial'
        except (OSError, ValueError): pass
        cases.append({'case_id':case_id, 'status':status,'integrity':integrity})
    return cases
