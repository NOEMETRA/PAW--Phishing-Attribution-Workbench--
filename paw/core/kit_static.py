"""Bounded observations from supplied/captured HTML, JS and CSS; never execute them."""
from dataclasses import asdict, dataclass
import hashlib
from .html_contexts import HTMLTextContextParser
import os
from pathlib import Path
import re
import stat


@dataclass(frozen=True)
class KitLimits:
    sources: int = 128
    source_bytes: int = 1024 * 1024
    total_bytes: int = 4 * 1024 * 1024
    observations: int = 2048
    value_chars: int = 4096
    directory_entries: int = 1024
    directory_depth: int = 8

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError('Kit limits must be positive integers')


KINDS = ('html', 'javascript', 'css')
URL = re.compile(r'https?://[^\s\'"<>`]+', re.I)
CSS_URL = re.compile(r'url\(\s*(?:"([^"]*)"|\'([^\']*)\'|([^)]*))\s*\)', re.I)
MARKERS = re.compile(r'eval\s*\(|atob\s*\(|btoa\s*\(|unescape\s*\(|fromCharCode|\\[xu]', re.I)
KEYWORDS = re.compile(r'\b(?:emotet|epoch\d+|trickbot|trickload|ryuk|hermes|password|login|verify|account|dropper|loader|shellcode)\b', re.I)


def analyze_kit_patterns(_analysis):
    """Compatibility boundary: static strings do not identify an attacker/family."""
    return {'status': 'unavailable', 'verified': False, 'malware_family': 'unknown',
            'campaign_indicators': [], 'attacker_fingerprint': {}, 'similar_campaigns': [],
            'reason': 'No independently supported family, campaign or attacker attribution'}


def assess_kit_risk(_analysis):
    return 'unavailable'


class _Inventory:
    def __init__(self, limits):
        self.limits = limits
        self.result = {
            'schema_version': 2, 'status': 'completed', 'verified': False,
            'scope': 'static lexical observations; no network, execution or behavior verification',
            'limits': asdict(limits), 'sources': [], 'observations': [], 'coverage': {
                'processed_bytes': 0, 'omitted_source_count': 0,
                'total_observation_count': 0, 'omitted_observation_count': 0,
                'issues': []},
            # Old classifications stay empty; consumers must read observations.
            'c2_servers': [], 'callback_domains': [], 'exfiltration_endpoints': [],
            'obfuscated_code': [], 'suspicious_patterns': [], 'risk_level': 'unavailable',
            'patterns': analyze_kit_patterns(None)}

    def issue(self, reason):
        self.result['status'] = 'partial'
        if reason not in self.result['coverage']['issues']:
            self.result['coverage']['issues'].append(reason)

    def emit(self, source, context, value, **location):
        coverage = self.result['coverage']
        coverage['total_observation_count'] += 1
        if (len(self.result['observations']) >= self.limits.observations
                or len(value) > self.limits.value_chars):
            coverage['omitted_observation_count'] += 1
            self.issue('observation_limit' if len(self.result['observations']) >= self.limits.observations else 'value_limit')
            return
        self.result['observations'].append({
            'source_index': source['index'], 'context': context, 'value': value,
            'interpretation_status': 'not_verified', **location})

    def source(self, kind, index, value, *, path=None, raw=None, error=None):
        sources = self.result['sources']
        record = {'index': len(sources), 'kind': kind, 'input_index': index,
                  'status': 'not_analyzed'}
        if path is not None:
            record['path'] = path
        sources.append(record)
        if raw is not None:
            # Complete bounded raw captures retain provenance even when their
            # replacement-decoded text cannot be admitted for analysis.
            record.update(captured_bytes=len(raw), captured_sha256=hashlib.sha256(raw).hexdigest(),
                          decoding='utf-8 with replacement', decoding_lossy=raw.decode('utf-8', errors='replace').encode('utf-8') != raw)
        if error:
            record['reason'] = error
            self.issue(error)
            return
        if not isinstance(value, str):
            record['reason'] = 'invalid_source_type'
            self.issue(record['reason'])
            return
        # Reject whole oversized sources, never hash/parse a silent prefix.
        if len(value) > self.limits.source_bytes:
            record['reason'] = 'source_byte_limit'
            self.issue(record['reason'])
            return
        try:
            data = value.encode('utf-8')
        except UnicodeEncodeError:
            record['reason'] = 'invalid_unicode'
            self.issue(record['reason'])
            return
        if len(data) > self.limits.source_bytes:
            record['reason'] = 'source_byte_limit'
            self.issue(record['reason'])
            return
        if self.result['coverage']['processed_bytes'] + len(data) > self.limits.total_bytes:
            record['reason'] = 'total_byte_limit'
            self.issue(record['reason'])
            return
        self.result['coverage']['processed_bytes'] += len(data)
        record.update(status='analyzed', text_utf8_sha256=hashlib.sha256(data).hexdigest(),
                      text_utf8_bytes=len(data), hash_scope='complete supplied text encoded as UTF-8')
        try:
            if kind == 'html':
                parser = _HTML(self, record)
                parser.feed(value)
                parser.close()
            elif kind == 'javascript':
                self.scan_js(record, value, 'javascript', 0)
            else:
                for match in CSS_URL.finditer(value):
                    self.emit(record, 'css_url', next(v for v in match.groups() if v is not None).strip(),
                              offset=match.start(), representation='CSS url() argument')
            for match in KEYWORDS.finditer(value):
                self.emit(record, 'lexical_keyword', match.group(), offset=match.start(), representation='supplied text')
        except (ValueError, AssertionError) as exc:
            record.update(status='partial', reason='parse_error', error_type=type(exc).__name__)
            self.issue('parse_error')

    def scan_js(self, source, value, context, offset):
        for match in URL.finditer(value):
            self.emit(source, context + '_url_literal', match.group(), offset=offset + match.start(),
                      representation='literal text; not evaluated')
        for match in MARKERS.finditer(value):
            self.emit(source, context + '_lexical_marker', match.group(), offset=offset + match.start(),
                      representation='literal text; includes comments and strings')


class _HTML(HTMLTextContextParser):
    def __init__(self, inventory, source):
        super().__init__(convert_charrefs=True)
        self.inventory, self.source = inventory, source
        self.script = False

    def close(self):
        super().close()
        if self.script:
            # HTMLParser buffers an unterminated script instead of emitting it.
            # Preserve its literal text without claiming browser behavior.
            if self.rawdata:
                self.handle_data(self.rawdata)
                self.rawdata = ''
            self.inventory.issue('unterminated_inline_script')

    def handle_starttag(self, tag, attrs):
        self.script = tag == 'script' or self.script
        line, column = self.getpos()
        for index, (name, value) in enumerate(attrs):
            if name in {'action', 'formaction', 'src', 'href', 'data'} and value is not None:
                self.inventory.emit(self.source, 'html_attribute', value, tag=tag, attribute=name,
                                    attribute_index=index, line=line, column=column,
                                    representation='HTML parser attribute (character references decoded)')

    def handle_endtag(self, tag):
        if tag == 'script':
            self.script = False

    def handle_comment(self, data):
        for match in URL.finditer(data):
            self.inventory.emit(self.source, 'html_comment_url', match.group(),
                                line=self.getpos()[0], column=self.getpos()[1],
                                comment_offset=match.start(), representation='HTML comment text')

    def handle_data(self, data):
        if self.script:
            # Offsets are within this parser data segment, not the complete file.
            before = len(self.inventory.result['observations'])
            self.inventory.scan_js(self.source, data, 'inline_script', 0)
            for row in self.inventory.result['observations'][before:]:
                row.update(line=self.getpos()[0], column=self.getpos()[1], offset_scope='parser data segment')


def analyze_phishing_kit_content(kit_content, *, limits=None):
    """Accept a scalar or list of text sources for each known content type."""
    inv = _Inventory(limits or KitLimits())
    if not isinstance(kit_content, dict):
        inv.issue('invalid_kit_type')
        return inv.result
    if len(kit_content) != sum(kind in kit_content for kind in KINDS):
        inv.issue('unsupported_content_keys')
    for kind in KINDS:
        if kind not in kit_content:
            continue
        values = kit_content[kind]
        if not isinstance(values, list):
            values = [values]
        remaining = max(0, inv.limits.sources - len(inv.result['sources']))
        if len(values) > remaining:
            inv.result['coverage']['omitted_source_count'] += len(values) - remaining
            inv.issue('source_count_limit')
        for index in range(min(len(values), remaining)):
            inv.source(kind, index, values[index])
    return inv.result


def analyze_captured_kit(directory, *, limits=None):
    """Read only bounded regular captured files, without following symlinks.

    The directory belongs to an already stopped collection. This is static
    ingestion, not sandboxing or a claim that active collection works.
    """
    inv = _Inventory(limits or KitLimits())
    root = Path(directory)
    def reparse(metadata):
        return bool(getattr(metadata, 'st_file_attributes', 0)
                    & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))

    try:
        metadata = root.stat(follow_symlinks=False)
        available = stat.S_ISDIR(metadata.st_mode) and not reparse(metadata) and not root.is_symlink()
    except OSError:
        available = False
    if not available:
        inv.issue('unavailable_capture_directory')
        return inv.result
    pending = [(root, 0)]
    entries_seen = 0
    suffixes = {'.html': 'html', '.js': 'javascript', '.css': 'css'}
    while pending:
        parent, depth = pending.pop()
        entries = []
        entry_limit = False
        try:
            with os.scandir(parent) as scan:
                for entry in scan:
                    if entries_seen >= inv.limits.directory_entries:
                        inv.issue('directory_entry_limit')
                        entry_limit = True
                        break
                    entries_seen += 1
                    entries.append(entry)
        except OSError:
            inv.issue('directory_read_error')
            continue
        for entry in sorted(entries, key=lambda e: e.name):
            try:
                if entry.is_symlink() or reparse(entry.stat(follow_symlinks=False)):
                    inv.issue('symlink_or_reparse_skipped')
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth >= inv.limits.directory_depth:
                        inv.issue('directory_depth_limit')
                    else:
                        pending.append((Path(entry.path), depth + 1))
                    continue
                kind = suffixes.get(Path(entry.name).suffix.lower())
                if kind is None:
                    continue
                if len(inv.result['sources']) >= inv.limits.sources:
                    inv.result['coverage']['omitted_source_count'] += 1
                    inv.issue('source_count_limit')
                    continue
                relpath = Path(entry.path).relative_to(root).as_posix()
                if not entry.is_file(follow_symlinks=False):
                    inv.source(kind, None, None, path=relpath, error='not_regular_file')
                    continue
                # Opening with O_NOFOLLOW where available also rejects replacement
                # symlinks. An external isolation layer is still required for live collection.
                try:
                    fd = os.open(entry.path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                                 | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
                    with os.fdopen(fd, 'rb') as stream:
                        metadata = os.fstat(stream.fileno())
                        if not stat.S_ISREG(metadata.st_mode) or reparse(metadata):
                            inv.source(kind, None, None, path=relpath, error='not_regular_file')
                            continue
                        raw = stream.read(inv.limits.source_bytes + 1)
                except OSError:
                    inv.source(kind, None, None, path=relpath, error='capture_read_error')
                    continue
                if len(raw) > inv.limits.source_bytes:
                    inv.source(kind, None, None, path=relpath, error='source_byte_limit')
                else:
                    inv.source(kind, None, raw.decode('utf-8', errors='replace'), path=relpath, raw=raw)
            except OSError:
                inv.issue('capture_read_error')
        if entry_limit:
            return inv.result
    return inv.result


def publish_captured_kit_inventory(case_dir):
    """Publish the actual static artifact and an unverified campaign reference.

    Used by trace after collection; also usable on stopped local capture files.
    Does not seal the case or claim that collection/detonation occurred.
    """
    from .runtime import atomic_json
    import json
    case = Path(case_dir)
    try:
        campaign = json.loads((case/'campaign_origin.json').read_text(encoding='utf-8'))
    except FileNotFoundError:
        campaign = {}
    if not isinstance(campaign, dict) or not isinstance(campaign.get('static_observations', {}), dict):
        raise ValueError('Invalid campaign static-observation container')
    analysis = analyze_captured_kit(case/'detonation'/'runs')
    campaign.setdefault('static_observations', {})['captured_kit'] = {
        'path': 'phishing_kit_analysis.json', 'status': analysis['status'],
        'verified': False, 'observation_count': len(analysis['observations'])}
    # json.loads accepts non-finite numbers, including exponent overflow.
    # Preflight the final campaign using atomic_json's serialization contract.
    json.dumps(campaign, indent=2, allow_nan=False)
    atomic_json(case/'phishing_kit_analysis.json', analysis)
    atomic_json(case/'campaign_origin.json', campaign)
    return analysis


def analyze_html_for_c2(content):
    return analyze_phishing_kit_content({'html': content})


def analyze_javascript_for_c2(content):
    return analyze_phishing_kit_content({'javascript': content})


def analyze_css_for_c2(content):
    return analyze_phishing_kit_content({'css': content})
