"""Bounded opaque source acquisition and byte observations; never execution.

The unchanged acquired bytes are the
source. Prefix hints, byte counts and strict UTF-8 observations neither establish
format validity/authenticity nor authorize a parser, interpreter or VM profile.
Process wall/CPU/memory bounds belong to the supervised worker, not this reader.
"""
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import math
import os
import re
import stat

from .batch import local_source_path

MAX_INPUT = 64 * 1024**2
MAX_TEXT = 1024**2


class SourceError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SourceLimits:
    input_bytes: int = 16 * 1024**2
    text_observation_bytes: int = MAX_TEXT
    preview_bytes: int = 64

    def __post_init__(self):
        for name, maximum in [('input_bytes', MAX_INPUT), ('text_observation_bytes', MAX_TEXT), ('preview_bytes', 4096)]:
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= maximum:
                raise ValueError('source_limit_'+name)


@dataclass(frozen=True)
class SourceCapture:
    raw: bytes
    display_name: str
    sha256: str


def admit_path(source):
    # Scheme/UNC/blank/NUL refusal must precede any filesystem access. Paths
    # containing a colon without URI syntax remain ordinary local filenames.
    try: value = os.fspath(source)
    except TypeError: raise SourceError('source_local_path_required') from None
    if isinstance(value, str) and re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', value):
        raise SourceError('source_uri_unavailable')
    try: return local_source_path(value)
    except ValueError: raise SourceError('source_local_path_required') from None


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def acquire_source(source, limits=SourceLimits()):
    if not isinstance(limits, SourceLimits): raise ValueError('source_limits_required')
    path = admit_path(source)
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    try: fd = os.open(path, flags | getattr(os, 'O_BINARY', 0))
    except OSError: raise SourceError('source_open_failed') from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): raise SourceError('source_not_regular')
        if before.st_size > limits.input_bytes: raise SourceError('source_input_budget')
        chunks = []; length = 0; digest = hashlib.sha256()
        while True:
            piece = os.read(fd, min(65536, limits.input_bytes-length+1))
            if not piece: break
            length += len(piece)
            if length > limits.input_bytes: raise SourceError('source_input_budget')
            chunks.append(piece); digest.update(piece)
        after = os.fstat(fd)
        if length != before.st_size or fingerprint(before) != fingerprint(after):
            raise SourceError('source_changed_during_read')
        try: named = os.stat(path, follow_symlinks=False)
        except OSError: raise SourceError('source_path_changed_during_read') from None
        if not stat.S_ISREG(named.st_mode) or fingerprint(named) != fingerprint(after):
            raise SourceError('source_path_changed_during_read')
        return SourceCapture(b''.join(chunks), path.name, digest.hexdigest())
    except OSError: raise SourceError('source_read_failed') from None
    finally: os.close(fd)


def prefix_hints(raw):
    # Hints report only byte signatures. No archive/image/native file parser,
    # decompressor, external command, MIME decoder or dynamic loader is called.
    signatures = [(b'\x7fELF', 'elf_prefix'), (b'MZ', 'dos_mz_prefix'),
                  (b'PK\x03\x04', 'zip_local_header_prefix'), (b'PK\x05\x06', 'zip_end_record_prefix'),
                  (b'%PDF-', 'pdf_prefix'), (b'\x1f\x8b', 'gzip_prefix'),
                  (b'\x89PNG\r\n\x1a\n', 'png_prefix'), (b'\xff\xd8\xff', 'jpeg_prefix')]
    hints = [{'kind': kind, 'offset': 0, 'scope': 'prefix_only_not_format_validation'}
             for marker, kind in signatures if raw.startswith(marker)]
    if raw.startswith(b'#!'):
        hints.append({'kind': 'shebang_prefix', 'offset': 0, 'scope': 'prefix_only_no_interpreter_selected'})
    return hints


def inspect_bytes(raw, *, display_name='', limits=SourceLimits()):
    if not isinstance(limits, SourceLimits): raise ValueError('source_limits_required')
    if type(raw) is not bytes or len(raw) > limits.input_bytes: raise SourceError('source_input_budget')
    if type(display_name) is not str: raise ValueError('source_display_name_required')
    digest = hashlib.sha256(raw).hexdigest(); counts = Counter(raw); size = len(raw)
    entropy = -sum((count/size)*math.log2(count/size) for count in counts.values()) if size else None
    utf8 = {'status': 'omitted_budget', 'byte_budget': limits.text_observation_bytes, 'encoding': 'utf-8',
            'policy': 'strict_no_replacement_no_newline_or_BOM_translation'}
    if size <= limits.text_observation_bytes:
        try: text = raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError as error:
            utf8.update(status='invalid', error_offset=error.start, error_end=error.end, reason=error.reason)
        else:
            # Decodability does not establish text format or semantic coverage.
            encoded = text.encode('utf-8', errors='strict')
            if encoded != raw: raise SourceError('source_utf8_roundtrip_changed')
            utf8.update(status='strictly_decodable', character_count=len(text),
                        roundtrip_sha256=hashlib.sha256(encoded).hexdigest())
    return {'schema': 'paw-source-inspection-v1', 'observer_version': 'bounded-byte-observers-v1',
            'source': {'artifact': 'source.bin', 'display_name': display_name, 'bytes': size, 'sha256': digest,
                       'empty': size == 0, 'origin_verified': False},
            'observations': {'prefix': {'encoding': 'hex', 'bytes': min(size, limits.preview_bytes),
                                         'data': raw[:limits.preview_bytes].hex()},
                             'byte_counts': {'nul': counts[0], 'distinct': len(counts),
                                             'ascii_control': sum(counts[n] for n in [*range(32), 127])},
                             'entropy_bits_per_byte': entropy, 'prefix_hints': prefix_hints(raw), 'utf8': utf8},
            'coverage': {'bytes': 'completed', 'format_interpretation': 'not_performed',
                         'semantic_analysis': 'not_performed', 'classification': 'not_evaluated',
                         'execution': 'not_requested', 'execution_authority': 'none',
                         'limitation': 'Byte observations only. Prefixes and decodability do not prove format validity, safety or authenticity.'},
            'limits': asdict(limits)}


def inspect_capture(capture, *, limits=SourceLimits()):
    if not isinstance(capture, SourceCapture): raise ValueError('source_capture_required')
    value = inspect_bytes(capture.raw, display_name=capture.display_name, limits=limits)
    if capture.sha256 != value['source']['sha256']: raise SourceError('source_capture_digest_changed')
    value['source']['acquisition'] = 'stable_descriptor_and_final_named_inode'
    value['source']['io_scope'] = 'local filesystem APIs; no URL fetch; kernel-backed mounts are outside the Python egress guard'
    return value
