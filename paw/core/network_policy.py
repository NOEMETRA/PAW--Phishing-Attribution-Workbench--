"""Application-level offline policy. Not an OS sandbox for native code."""
from contextlib import contextmanager
from functools import wraps
import inspect
import sys
import threading

_lock = threading.RLock()
_offline_depth = 0
_installed = False
_violations = []

class EgressDenied(PermissionError):
    pass

def network_allowed():
    return _offline_depth == 0

def violations():
    with _lock:
        return list(_violations)

def _audit(event, args):
    if not network_allowed() and (
        (event.startswith('socket.') and event != 'socket.gethostname')
        or event in {'subprocess.Popen', 'os.system', 'os.posix_spawn',
                     'os.spawn', 'os.fork', 'os.forkpty', 'os.exec',
                     'os.startfile', 'os.startfile/2', '_winapi.CreateProcess'}
    ):
        with _lock:
            _violations.append(event)
        raise EgressDenied(f'no-egress blocked {event}')

@contextmanager
def offline_policy(enabled=True):
    # Process-wide while active: worker threads cannot bypass the policy.
    global _installed, _offline_depth
    if not enabled:
        yield
        return
    with _lock:
        if not _installed:
            sys.addaudithook(_audit)
            _installed = True
        _offline_depth += 1
    try:
        yield
    finally:
        with _lock:
            _offline_depth -= 1

def enforce_trace_policy(function):
    signature = inspect.signature(function)
    @wraps(function)
    def wrapped(*args, **kwargs):
        arguments = signature.bind(*args, **kwargs)
        with offline_policy(bool(arguments.arguments.get('no_egress', False))):
            return function(*args, **kwargs)
    return wrapped
