"""Bounded, lossless UTF-8 input for standalone offline observations."""
import hashlib
import os
import stat

from ..core.network_policy import offline_policy

MAX_INPUT_BYTES = 1024 * 1024


def validate_input_source(*, text=None, file=None, url=None):
    """Admit a source without opening it or starting analysis."""
    provided = [(kind, value) for kind, value in
                (('text', text), ('file', file), ('url', url)) if value is not None]
    if len(provided) != 1:
        raise ValueError('Provide exactly one of --text, --file or --url')
    kind, value = provided[0]
    if kind == 'file':
        value = os.fspath(value)
        # Windows accepts slash and mixed-separator UNC spellings too.
        # Normalize only for admission; open the original local path.
        if not isinstance(value, str) or value.replace('/', '\\').startswith('\\\\'):
            raise ValueError('Input must be a local regular file; UNC paths are not accepted')
    elif not isinstance(value, str):
        raise ValueError('Input must be text')
    elif len(value) > MAX_INPUT_BYTES:
        raise ValueError('Input exceeds the 1 MiB UTF-8 byte limit')
    else:
        # The character precheck bounds encoding allocation, but admission must
        # also reject invalid UTF-8 and multibyte overflow before worker startup.
        try:
            raw = value.encode('utf-8')
        except UnicodeError as exc:
            raise ValueError('Input cannot be encoded as valid UTF-8') from exc
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError('Input exceeds the 1 MiB UTF-8 byte limit')
    return kind, value


def analyze_input(*, text=None, file=None, url=None):
    """Exactly one literal input; no URL fetch or implicit encoding repair."""
    kind, value = validate_input_source(text=text, file=file, url=url)
    with offline_policy(True):
        if kind == 'file':
            fd = os.open(value, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0))
            try:
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError('Input must be a regular file')
                    if info.st_size > MAX_INPUT_BYTES:
                        raise ValueError('Input exceeds the 1 MiB UTF-8 byte limit')
                    raw = stream.read(MAX_INPUT_BYTES + 1)
            finally:
                os.close(fd)
        else:
            try:
                raw = value.encode('utf-8')
            except UnicodeError as exc:
                raise ValueError('Input cannot be encoded as valid UTF-8') from exc
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError('Input exceeds the 1 MiB UTF-8 byte limit')
        try:
            content = raw.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError(f'Input is not valid UTF-8 at byte {exc.start}; content was not analyzed') from exc
        # Imports and analysis are inside the dispatch guard. CLI bootstrap is
        # outside this function; this is not an OS or import-time sandbox.
        from .core import DeobfuscationEngine
        results = DeobfuscationEngine().analyze_artifacts({
            'text': content, 'urls': [content] if kind == 'url' else [],
            'html': '', 'javascript': '', 'attachments': []})
        results['input_observation'] = {
            'schema_version': 1, 'source_kind': kind, 'encoding': 'utf-8',
            'byte_count': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'decoding': 'strict_no_newline_translation',
            'case_storage': 'not_created', 'no_egress': True,
            'policy_scope': 'Python application guard during input reading and analysis; not OS isolation',
        }
        return results
