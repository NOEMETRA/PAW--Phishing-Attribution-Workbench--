"""Shared offline Sentinel admission/budget helpers; no configuration or storage is opened on import."""
import json
import math
import os
import stat
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from functools import wraps


_DEFAULT_LIMITS = {'max_rows': 10_000, 'max_row_bytes': 8*1024**2,
    'max_result_bytes': 32*1024**2, 'max_sql_steps': 10_000_000,
    'max_output_bytes': 64*1024**2, 'max_json_depth': 64, 'max_json_nodes': 100_000,
    'max_json_bytes': 1024**2}


def _resource_limits(value=None):
    if value is not None and (type(value) is not dict or
            any(key not in _DEFAULT_LIMITS or type(limit) is not int or not 0 < limit < 2**31
                for key, limit in value.items())):
        raise ValueError('Sentinel limits require known positive integer values')
    return MappingProxyType({**_DEFAULT_LIMITS, **(value or {})})


def _json_tree(value, *, depth=64, nodes=100_000, budget=None):
    """Copy admitted native JSON; do not encode from mutable caller containers."""
    active = set()
    if budget is None: budget = [nodes]
    def visit(item, level):
        budget[0] -= 1
        if budget[0] < 0 or level > depth: raise ValueError('Sentinel JSON depth/node limit exceeded')
        kind = type(item)
        if kind is str:
            if len(item) > 1024**2: raise ValueError('Sentinel JSON string limit exceeded')
        elif item is None or kind in (bool, int): pass
        elif kind is float:
            if not math.isfinite(item): raise ValueError('Sentinel JSON requires finite numbers')
        elif kind in (dict, list):
            if id(item) in active: raise ValueError('Sentinel JSON cycle')
            active.add(id(item))
            try:
                if kind is dict:
                    result = {}
                    for key, child in item.items():
                        if type(key) is not str: raise ValueError('Sentinel JSON requires string keys')
                        visit(key, level+1); result[key] = visit(child, level+1)
                else: result = [visit(child, level+1) for child in item]
            finally: active.remove(id(item))
            return result
        else: raise ValueError('Sentinel JSON requires native values')
        return item
    return visit(value, 0)


def _json_chunks(value, limit, *, indent=None):
    size = 0
    for part in json.JSONEncoder(ensure_ascii=True, allow_nan=False, indent=indent).iterencode(value):
        size += len(part)
        if size > limit: raise ValueError('Sentinel JSON output byte limit exceeded')
        yield part


def _bounded_report(method):
    @wraps(method)
    def bounded(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        database = getattr(self, 'db', self)
        return database.check_report(result)
    return bounded


def _require_active():
    from ..core.network_policy import network_allowed
    if not network_allowed():
        raise RuntimeError('Active Sentinel collection and interpretation are unavailable under no-egress')


def _encode_writer_json(value, field, expected=dict):
    if type(value) is not expected: raise ValueError(f'{field} must be a JSON {expected.__name__}')
    value = _json_tree(value)
    if expected is list and any(type(item) is not str for item in value):
        raise ValueError(f'{field} must contain only strings')
    return ''.join(_json_chunks(value, 1024**2))


def _storage_directory(path):
    """Admit every known ancestor, without resolving a link away."""
    path = _storage_path(path)
    for candidate in (*reversed(path.parents), path):
        try: metadata = candidate.lstat()
        except FileNotFoundError: continue
        if (stat.S_ISLNK(metadata.st_mode) or
                getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise ValueError(f'Unsupported Sentinel directory: {candidate}')
        if not stat.S_ISDIR(metadata.st_mode): raise NotADirectoryError(str(candidate))
    return path


def _storage_path(value, *, base=None):
    """Bind literal local paths without following away symbolic components."""
    try: value = os.fspath(value)
    except TypeError: raise ValueError('Sentinel requires a filesystem path') from None
    if (not isinstance(value, str) or not value.strip() or '\x00' in value or
            value == ':memory:' or value.lower().startswith('file:') or
            value.startswith(('\\\\', '//'))):
        raise ValueError('Sentinel requires a nonblank local filesystem path')
    path = Path(value)
    if os.name == 'nt':
        windows = PureWindowsPath(value)
        reserved = getattr(os.path, 'isreserved', lambda part: PureWindowsPath(part).is_reserved())
        components = [part for part in windows.parts if part not in (windows.anchor, '.', '..')]
        if (windows.drive and not path.is_absolute() or
                any(':' in part or part.endswith((' ', '.')) or reserved(part) for part in components)):
            raise ValueError('Device, stream/normalization aliases and drive-relative storage paths are unavailable')
    bound = (Path(base) / path if base is not None and not path.is_absolute() else path).absolute()
    if str(bound).startswith(('\\\\', '//')):
        raise ValueError('Network storage paths are unavailable')
    return bound


def _admit_storage_path(path, *, must_exist=False, directory_as_missing=False):
    """Reject non-directory ancestors and symbolic/reparse/special targets."""
    for parent in reversed(path.parents):
        try: metadata = parent.lstat()
        except FileNotFoundError: continue
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or
                getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise ValueError(f'Unsupported Sentinel storage ancestor: {parent}')
    try: metadata = path.lstat()
    except FileNotFoundError:
        if must_exist: raise
        return None
    if (directory_as_missing and stat.S_ISDIR(metadata.st_mode) and
            not getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise FileNotFoundError(f'Sentinel database is not an existing file: {path}')
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or
            getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise ValueError(f'Sentinel storage must be a regular non-reparse file: {path}')
    if metadata.st_nlink != 1:
        raise ValueError(f'Multiple-link Sentinel storage is unavailable: {path}')
    return metadata


def _storage_identity(metadata):
    return metadata.st_dev, metadata.st_ino


def _storage_stamp(metadata):
    # Rename may change POSIX ctime. Preserve the same fingerprint across the
    # publication commit, without requiring a fallible target read afterward.
    return _storage_identity(metadata), metadata.st_mode, metadata.st_size, metadata.st_mtime_ns


def _storage_opener(path, flags):
    return os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
