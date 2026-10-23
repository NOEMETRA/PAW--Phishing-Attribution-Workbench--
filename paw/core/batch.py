"""Local input admission, explicit selection and per-email batch failures."""
import os
import stat
from pathlib import Path


class BatchAnalysisError(RuntimeError):
    def __init__(self, paths, failures, inputs):
        self.case_paths = paths
        self.failures = failures
        self.inputs = inputs
        super().__init__(f'Batch incomplete: {len(paths)} completed, {len(failures)} failed; see worker result for individual inputs')


def local_source_path(source):
    """Reject network path syntax before Path resolution, stat or source I/O."""
    try: value = os.fspath(source)
    except TypeError: raise ValueError('Input requires a local filesystem path') from None
    if (not isinstance(value, str) or not value.strip() or '\x00' in value or
            value.replace('/', '\\').startswith('\\\\')):
        raise ValueError('Input requires a nonblank local path; UNC paths are unavailable')
    return Path(value)


def read_source_bytes(source, max_bytes, *, limit_error=ValueError,
                      limit_message='Input file byte limit exceeded'):
    path = local_source_path(source)
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError('Input byte limit must be a positive integer')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode): raise ValueError('Input must be a regular file')
            if before.st_size > max_bytes: raise limit_error(limit_message)
            raw = stream.read(max_bytes + 1)
            if len(raw) > max_bytes: raise limit_error(limit_message)
            after = os.fstat(descriptor)
            if (len(raw) != before.st_size or before.st_size != after.st_size or
                    before.st_mtime_ns != after.st_mtime_ns):
                raise ValueError('Input file changed during reading')
    finally:
        os.close(descriptor)
    return raw


def select_inputs(source):
    source = local_source_path(source)
    if source.is_file():
        if source.suffix.lower() not in {'.eml', '.msg'}:
            raise ValueError('Unsupported input extension; provide original EML')
        return [source]
    if not source.is_dir():
        raise FileNotFoundError(str(source))
    paths = sorted((path for path in source.iterdir()
                    if path.is_file() and path.suffix.lower() in {'.eml', '.msg'}),
                   key=lambda path: (path.name.casefold(), path.name))
    if not paths:
        raise ValueError('No EML/MSG inputs found in directory')
    return paths
