"""Persist process identity before release and confirm shutdown after a crash.

Control files are trusted local supervisor metadata, not email evidence. Unknown
identity fails closed: never kill a reused PID or seal/export a possible writer.
"""
import asyncio
import os
from pathlib import Path
import signal
import time
import math

import psutil

from .runtime import atomic_json, read_progress


def process_identity(pid, *, dedicated_group=True):
    process = psutil.Process(pid)
    value = {'pid': pid, 'created_at': process.create_time(),
             'boot_time': psutil.boot_time(), 'platform': os.name}
    if os.name != 'nt':
        value.update(pgid=os.getpgid(pid), sid=os.getsid(pid))
        if dedicated_group and (value['pgid'] != pid or value['sid'] != pid):
            raise ValueError('Worker must lead its dedicated process group and session')
    return value


def identity_alive(record):
    """True for the same live process, False for an exited/reused PID, None if unknown."""
    try:
        pid = record.get('pid')
        if (type(pid) is not int or pid <= 1 or record.get('platform') != os.name
                or not same_boot(record)):
            return None
        process = psutil.Process(pid)
        return (process.create_time() == record.get('created_at') and
                process.status() not in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD})
    except psutil.NoSuchProcess:
        return False
    except (OSError, psutil.Error, TypeError):
        return None


def same_boot(record):
    # Windows boot_time is estimated separately in each interpreter and differs
    # by small fractions of a second. PID creation time is still compared exactly.
    boot = record.get('boot_time')
    if not isinstance(boot,(int,float)) or isinstance(boot,bool) or not math.isfinite(boot):
        return False
    return abs(boot-psutil.boot_time()) <= (2 if os.name=='nt' else 0)


def group_writers(pgid):
    """Zombies have exited and cannot modify evidence; permissions fail closed."""
    writers = []
    for process in psutil.process_iter():
        try:
            if os.getpgid(process.pid) == pgid and process.status() not in {
                    psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}:
                writers.append(process.pid)
        except (ProcessLookupError, psutil.NoSuchProcess):
            continue
    return writers


async def recover_worker(control):
    """Stop only the recorded tree; return proof or an explicit blocked recovery."""
    control = Path(control)
    record = read_progress(control/'process.json')
    previous = read_progress(control/'supervisor.json')
    if previous.get('tree_stopped') is True:
        return previous
    outcome = {'status': 'interrupted', 'tree_stopped': False,
               'error': 'Worker identity or shutdown could not be established',
               'network_isolation': 'application_policy_only'}
    try:
        pid = record.get('pid')
        if (type(pid) is not int or pid <= 1 or record.get('platform') != os.name
                or not same_boot(record)):
            raise ValueError('Missing or incompatible worker identity')
        try:
            process = psutil.Process(pid)
            same = process.create_time() == record.get('created_at')
        except psutil.NoSuchProcess:
            process, same = None, False
        if os.name == 'nt':
            # The original Windows Job Object closes on API death and kills its
            # tree. Do not terminate a process just because its PID was reused.
            end = time.monotonic() + 5
            while same and process.is_running() and time.monotonic() < end:
                await asyncio.sleep(.02)
            if same and process.is_running():
                raise ValueError('Windows Job Object shutdown not confirmed')
        else:
            pgid = record.get('pgid')
            if pgid != pid or record.get('sid') != pid:
                raise ValueError('Invalid worker group identity')
            members = group_writers(pgid)
            if members:
                if not same or os.getpgid(pid) != pgid or os.getsid(pid) != pid:
                    raise ValueError('Live group ownership cannot be confirmed')
                os.killpg(pgid, signal.SIGKILL)
                end = time.monotonic() + 5
                while group_writers(pgid):
                    if time.monotonic() >= end:
                        raise ValueError('Worker group shutdown not confirmed')
                    await asyncio.sleep(.02)
        outcome.update(tree_stopped=True, error='API restarted; recorded worker tree stopped')
    except (OSError, ValueError, psutil.Error) as exc:
        outcome['error'] = str(exc)
    # Persist confirmation before API publishes a terminal state or seals files.
    control.mkdir(parents=True, exist_ok=True)
    atomic_json(control/'supervisor.json', outcome)
    return outcome
