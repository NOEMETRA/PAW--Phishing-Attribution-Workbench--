"""Content-addressed original and explicitly derived opaque byte representations.

No source is executed, rendered, fetched or authenticated by this inventory.
"""
import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import re

INTERPRETATIONS = ('mime', 'html-utf8', 'javascript-utf8', 'posix-shell-utf8', 'elf64-x86_64')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def digest(raw): return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class GraphLimits:
    source_bytes: int = 16*1024**2
    representation_bytes: int = 64*1024**2
    work_bytes: int = 128*1024**2
    nodes: int = 128
    depth: int = 8

    def __post_init__(self):
        caps = {'source_bytes': 64*1024**2, 'representation_bytes': 128*1024**2,
                'work_bytes': 256*1024**2, 'nodes': 256, 'depth': 16}
        for name, maximum in caps.items():
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= maximum: raise ValueError('graph_limit_'+name)
        if self.representation_bytes < self.source_bytes: raise ValueError('graph_original_reservation')


class Graph:
    def __init__(self, raw, limits=GraphLimits()):
        if type(raw) is not bytes or len(raw) > limits.source_bytes: raise ValueError('graph_source_budget')
        self.limits = limits; self.nodes = {}; self.blobs = {}; self.omissions = []; self.omission_count = 0
        self.representation_bytes = 0; self.work_bytes = 0
        self.root = self.add('original', raw, [], 'original-bytes', {}, complete=True)

    def omit(self, parent, transform, reason):
        # The transformation set and traversal must also be bounded by callers;
        # this bounded inventory cannot grow with arbitrary invalid tokens.
        self.omission_count += 1
        if len(self.omissions) < self.limits.nodes:
            self.omissions.append({'parent': parent, 'transform': transform, 'reason': reason})

    def add(self, kind, raw, parents, transform, parameters, *, complete, notes=None):
        if type(raw) is not bytes or type(parents) is not list or any(p not in self.nodes for p in parents):
            raise ValueError('graph_bytes_or_parent')
        if (not parents) != (kind == 'original'): raise ValueError('graph_original_parent_contract')
        if kind == 'original' and self.nodes: raise ValueError('graph_original_already_present')
        if type(complete) is not bool: raise ValueError('graph_native_completion_flag')
        depth = 0 if not parents else 1+max(self.nodes[p]['depth'] for p in parents)
        node = {'kind': kind, 'bytes': len(raw), 'sha256': digest(raw), 'parents': parents,
                'transform': {'name': transform, 'version': 1, 'parameters': parameters},
                'complete_transform': complete, 'origin_verified': False, 'execution_authority': 'none',
                'notes': notes or [], 'depth': depth}
        raw_meta = canonical(node)
        if len(raw_meta) > 8192: raise ValueError('graph_node_metadata_budget')
        # Own the canonical metadata: caller-owned nested collections must not
        # change provenance after its content-addressed identifier is computed.
        node = json.loads(raw_meta)
        identifier = digest(raw_meta)
        if identifier in self.nodes: return identifier
        reason = ('node_count' if len(self.nodes) >= self.limits.nodes else
                  'depth' if depth > self.limits.depth else
                  'representation_bytes' if self.representation_bytes+len(raw) > self.limits.representation_bytes else None)
        if reason:
            self.omit(parents[0] if parents else None, transform, reason)
            return None
        self.nodes[identifier] = node; self.blobs.setdefault(node['sha256'], raw)
        self.representation_bytes += len(raw)
        return identifier

    def payload(self, identifier):
        return self.blobs[self.nodes[identifier]['sha256']]

    def spend(self, parent, transform):
        raw = self.payload(parent)
        if self.work_bytes+len(raw) > self.limits.work_bytes:
            self.omit(parent, transform, 'work_bytes'); return None
        self.work_bytes += len(raw); return raw

    def record(self):
        record = {'schema': 'paw-forensic-representations-v1', 'root': self.root,
                'source_sha256': self.nodes[self.root]['sha256'],
                'nodes': [{'id': key, 'blob_path': 'blobs/'+value['sha256']+'.bin', **value}
                          for key, value in self.nodes.items()],
                'omissions': self.omissions, 'representation_bytes': self.representation_bytes,
                'omission_count': self.omission_count,
                'omissions_not_retained': self.omission_count-len(self.omissions),
                'unique_blob_bytes': sum(map(len, self.blobs.values())), 'work_bytes': self.work_bytes,
                'status': 'partial' if self.omissions or any(not n['complete_transform'] for n in self.nodes.values()) else 'completed',
                'scope': 'byte derivation inventory; associated reports state finite interpretation coverage; no execution or classification',
                'origin_verified': False, 'execution_authority': 'none'}
        return json.loads(canonical(record))


def base64_views(graph, parent):
    name = 'base64-ascii-whitespace'; raw = graph.spend(parent, name)
    if raw is None: return []
    compact = re.sub(b'[ \t\r\n]', b'', raw)
    parameters = {'removed_ascii_whitespace_bytes': len(raw)-len(compact),
                  'whitespace_policy': 'SP_HT_CR_LF_only', 'alphabet': 'RFC4648_standard'}
    created = []
    try: decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        graph.omit(parent, name, 'strict_base64_invalid')
    else:
        node = graph.add('decoded_candidate', decoded, [parent], name, parameters,
                         complete=True, notes=[] if base64.b64encode(decoded) == compact else ['noncanonical_pad_bits_or_spelling'])
        return [node] if node else []
    # Missing padding is an explicit alternative, never the parser-selected
    # original. A remainder of1 cannot be repaired by adding padding.
    if b'=' not in compact and re.fullmatch(b'[A-Za-z0-9+/]*', compact) and len(compact)%4 in {2, 3}:
        count = 4-len(compact)%4
        decoded = base64.b64decode(compact+b'='*count, validate=True)
        node = graph.add('decoded_candidate', decoded, [parent], 'base64-add-missing-padding',
                         {**parameters, 'added_padding_bytes': count}, complete=True,
                         notes=['derived_candidate_not_original_or_authenticated'])
        if node: created.append(node)
    else:
        # Preserve only the valid complete-quartet prefix as a separately
        # partial candidate; the exact omitted suffix range stays explicit.
        match = re.match(b'[A-Za-z0-9+/]*', compact); end = len(match.group())//4*4
        if end:
            decoded = base64.b64decode(compact[:end], validate=True)
            node = graph.add('partial_decoded_candidate', decoded, [parent], 'base64-valid-quartet-prefix',
                             {**parameters, 'normalized_prefix_bytes': end,
                              'normalized_suffix_omitted_bytes': len(compact)-end}, complete=False,
                             notes=['partial_prefix_only_no_missing_bytes_inferred'])
            if node: created.append(node)
    return created


def quoted_printable_view(graph, parent):
    name = 'quoted-printable-preserve-invalid'; raw = graph.spend(parent, name)
    if raw is None: return None
    bad = []; total = escaped = soft = pos = 0; output = bytearray(); alphabet = frozenset(b'0123456789abcdefABCDEF')
    while pos < len(raw):
        at = raw.find(b'=', pos)
        if at < 0: output.extend(raw[pos:]); break
        output.extend(raw[pos:at]); tail = raw[at+1:at+3]
        if tail == b'\r\n': pos = at+3; soft += 1
        elif tail[:1] == b'\n': pos = at+2; soft += 1
        elif len(tail) == 2 and all(b in alphabet for b in tail):
            output.append(int(tail, 16)); pos = at+3; escaped += 1
        else:
            output.append(61); pos = at+1; total += 1
            if len(bad) < 32: bad.append(at)
    return graph.add('decoded_candidate', bytes(output), [parent], name,
                     {'header_mode': False, 'line_break_policy': 'CRLF_and_LF_soft_break',
                      'valid_hex_escapes_decoded': escaped, 'soft_breaks_removed': soft,
                      'invalid_equals_count': total, 'first_invalid_equals_offsets': bad}, complete=not total,
                     notes=['invalid_escapes_preserved_exactly_in_this_derived_candidate'] if total else [])


CHARSETS = {'utf-8': 'utf-8', 'us-ascii': 'ascii', 'iso-8859-1': 'iso-8859-1',
            'windows-1252': 'cp1252', 'utf-16le': 'utf-16-le', 'utf-16be': 'utf-16-be'}


def text_view(graph, parent, charset):
    if type(charset) is not str or charset not in CHARSETS:
        graph.omit(parent, 'charset-to-utf8', 'charset_outside_finite_allowlist'); return None
    raw = graph.spend(parent, 'charset-to-utf8')
    if raw is None: return None
    try: decoded = raw.decode(CHARSETS[charset], errors='strict')
    except UnicodeError:
        graph.omit(parent, 'charset-to-utf8', 'strict_charset_decode_failed'); return None
    return graph.add('utf8_text_candidate', decoded.encode('utf-8', errors='strict'), [parent], 'charset-to-utf8',
                     {'input_charset': charset, 'errors': 'strict', 'newline_translation': False,
                      'bom_removal': False, 'output_charset': 'utf-8'}, complete=True,
                     notes=['explicit_charset_interpretation_not_authenticity'])
