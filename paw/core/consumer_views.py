"""Bounded saved-evidence reads and descriptive assessment projections.

These checks establish JSON shape and internal score consistency, never source
authenticity. Operational job journals keep their separate runtime contract.
"""
import json
import math
import os
from pathlib import Path
import stat

from .scoring import finalize_score

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 128


class ReadBudget:
    """Aggregate accepted source bytes/nodes for one consumer invocation."""
    def __init__(self, bytes=128 * 1024 * 1024, nodes=MAX_JSON_NODES):
        self.bytes, self.nodes = bytes, nodes


def read_artifact_text(path, budget=None, root=None):
    path = Path(path)
    if root is not None and not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('Artifact path outside source case')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Artifact must be a regular file, not a link')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('Artifact identity changed or is not regular')
        limit = min(MAX_ARTIFACT_BYTES, budget.bytes) if budget else MAX_ARTIFACT_BYTES
        if opened.st_size > limit:
            raise ValueError('Artifact byte limit exceeded')
        raw = stream.read(limit + 1)
    if budget: budget.bytes -= min(len(raw), limit)
    if len(raw) > limit:
        raise ValueError('Artifact byte limit exceeded')
    # Match the existing text-reader/API view on every platform. Original bytes
    # remain in the file/ZIP; JSON string escape sequences are not rewritten.
    return raw.decode('utf-8', errors='strict').replace('\r\n', '\n').replace('\r', '\n')


def _object(pairs):
    result = {}
    for key, value in pairs:
        try: key.encode('utf-8', errors='strict')
        except UnicodeError as exc: raise ValueError('Invalid Unicode scalar in JSON key') from exc
        if key in result: raise ValueError('Duplicate JSON object key')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('Nonfinite JSON number')


def read_artifact_json(path, expected=dict, budget=None, root=None):
    if budget and budget.nodes < 1: raise ValueError('Aggregate JSON node limit exceeded')
    try:
        value = json.loads(read_artifact_text(path, budget, root), object_pairs_hook=_object, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError('JSON nesting limit exceeded') from exc
    if type(value) is not expected:
        raise ValueError('Expected JSON ' + expected.__name__)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        if budget:
            budget.nodes -= 1
            if budget.nodes < 0: raise ValueError('Aggregate JSON node limit exceeded')
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError('JSON node or nesting limit exceeded')
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError('Nonfinite JSON number')
        if isinstance(item, str):
            try: item.encode('utf-8', errors='strict')
            except UnicodeError as exc: raise ValueError('Invalid Unicode scalar in JSON value') from exc
        if isinstance(item, dict): pending.extend((child, depth+1) for child in item.values())
        elif isinstance(item, list): pending.extend((child, depth+1) for child in item)
    return value


def native_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def assessment_view(score, *, source='report/score.json'):
    """No decision is inferred from a historical rounded display score."""
    view = {'schema_version':1, 'source':source, 'status':'not_evaluated',
            'display_score':None, 'decision_score':None, 'decision':None,
            'profile':None, 'thresholds':None, 'coverage':None,
            'calibrated':None, 'authenticity':'not_evaluated'}
    if not isinstance(score, dict) or not score:
        return dict(view, reason='Assessment object unavailable')
    display = score.get('score')
    if score.get('score_schema_version') != 2:
        if native_number(display) and 0 <= display <= 1:
            return dict(view, status='legacy_display_only', display_score=display,
                        reason='Recorded rounded score only; decision, profile, thresholds and coverage unavailable')
        return dict(view, status='invalid', reason='Finite native display score unavailable')
    try:
        if score.get('profile') not in ('default', 'strict', 'conservative'):
            raise ValueError()
        if not all(native_number(score.get(key)) for key in ('score','raw_score','decision_score')):
            raise ValueError()
        components = score.get('score_components')
        if not isinstance(components, dict) or not components or not all(native_number(v) for v in components.values()):
            raise ValueError()
        normalized = finalize_score(dict(score))
        keys = ('score_schema_version','score','raw_score','decision_score','score_components','component_sources',
                'decision','profile','thresholds','decision_basis','decision_scope','calibrated')
        if any(key not in score or score[key] != normalized[key] for key in keys):
            raise ValueError()
        if score['calibrated'] is not False or not isinstance(score.get('coverage'), dict):
            raise ValueError()
        return dict(view, status='consistent_current_metadata', display_score=display,
                    decision_score=score['decision_score'], decision=score['decision'], profile=score['profile'],
                    thresholds=score['thresholds'], coverage=score['coverage'], calibrated=False)
    except (ValueError, TypeError, KeyError, OverflowError):
        return dict(view, status='invalid', reason='Inconsistent current score metadata; consult recorded source')


def verdict_color(score):
    view = assessment_view(score)
    if view['status'] != 'consistent_current_metadata': return 'white'
    return {'Likely malicious infrastructure':'red', 'Suspicious or compromised account':'yellow',
            'Inconclusive':'white'}[view['decision']]
