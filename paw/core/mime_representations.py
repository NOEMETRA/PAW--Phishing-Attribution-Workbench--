"""Bounded MIME wire/selected/derived views using the existing PAW parser.

Uses the existing PAW parser/decoder without changing its selection rules.
Wire ranges are exact slices, never serialized messages. Ambiguous or incomplete
framing stays unavailable; parser-selected bytes retain a separate identity.
This module does not execute, render, fetch or authorize any representation.
"""
from dataclasses import dataclass
import hashlib
import re
import sys

from paw.core.parser_mail import parse_message_bytes
from paw.core.mime_analysis import MimeLimits, decoded_payload, TRANSFER_PARTIAL_REASONS
from .representation_graph import base64_views, quoted_printable_view, text_view


@dataclass(frozen=True)
class MimeViewLimits:
    parts: int = 32
    depth: int = 6
    header_bytes: int = 65536
    header_fields: int = 256
    declaration_bytes: int = 256
    alternatives: int = 2

    def __post_init__(self):
        caps = {'parts': 128, 'depth': 16, 'header_bytes': 262144,
                'header_fields': 1024, 'declaration_bytes': 1024, 'alternatives': 4}
        for name, cap in caps.items():
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= cap: raise ValueError('mime_view_limit_'+name)


NEWLINES = re.compile(rb'\r\n|\r|\n')
BOUNDARY = re.compile(rb"[0-9A-Za-z'()+_,./:=? -]{1,70}")
DECLARATIONS = ('content-type', 'content-transfer-encoding', 'content-disposition')


def body_start(raw, start, end, maximum):
    previous = start
    for newline in NEWLINES.finditer(raw, start, min(end, start+maximum+1)):
        if newline.start() == previous: return newline.end()
        previous = newline.end()
    return None


def closed_children(raw, start, end, boundary, count):
    """Map only complete selected framing with exactly the parser child count."""
    if not isinstance(boundary, str): return None
    try: marker = boundary.encode('ascii', 'strict')
    except UnicodeError: return None
    if not BOUNDARY.fullmatch(marker) or marker.endswith(b' '): return None
    pattern = re.compile(rb'(?:\A|(?<=\r)|(?<=\n))--'+re.escape(marker)
                         +rb'(?P<close>--)?[ \t]*(?:\r\n|\r|\n|\Z)')
    spans = []; child_start = None
    for delimiter in pattern.finditer(raw, start, end):
        if child_start is not None:
            child_end = delimiter.start()
            if raw[max(child_start, child_end-2):child_end] == b'\r\n': child_end -= 2
            elif child_end > child_start and raw[child_end-1:child_end] in (b'\r', b'\n'): child_end -= 1
            spans.append((child_start, child_end))
            if len(spans) > count: return None
        if delimiter.group('close'): return spans if len(spans) == count else None
        child_start = delimiter.end()
    return None


def declarations(part, limits):
    fields = []; omitted = 0
    for index, (name, value) in enumerate(part.raw_items()):
        if index >= limits.header_fields: omitted += 1; continue
        if name.lower() not in DECLARATIONS: continue
        # raw_items values are parser-recognized header values, NOT wire spans.
        try: octets = value.encode('ascii', 'surrogateescape')
        except UnicodeError:
            fields.append({'index': index, 'name': name.lower(), 'status': 'octets_unavailable'}); continue
        row = {'index': index, 'name': name.lower(), 'bytes': len(octets),
               'sha256': hashlib.sha256(octets).hexdigest(), 'source': 'parser_raw_value_not_wire_span'}
        if len(octets) > limits.declaration_bytes: row['status'] = 'value_budget'
        elif not octets.isascii():
            row.update(status='non_ascii_octets', value_hex=octets.hex(), value_encoding='hex_original_parser_octets')
        else: row.update(status='captured', value=octets.decode('ascii', 'strict'))
        fields.append(row)
    return fields, omitted


def populate_mime_graph(graph, limits=MimeViewLimits()):
    root = graph.root; raw = graph.spend(root, 'existing-paw-mime-parser')
    report = {'schema': 'paw-forensic-mime-views-v1', 'parts': [], 'issues': [],
              'parser': 'existing_paw_policy_default', 'python_version': sys.version.split()[0],
              'source_sha256': graph.nodes[root]['sha256'], 'status': 'partial',
              'origin_verified': False, 'execution_authority': 'none',
              'scope': 'selected MIME tree and complete selected wire framing only; no alternate boundary trees or embedded-message serialization'}
    if raw is None:
        report['issues'].append('graph_work_budget'); return report
    parser_limits = MimeLimits(max_input_bytes=graph.limits.source_bytes, max_parts=limits.parts,
                               max_depth=limits.depth)
    try: message = parse_message_bytes(raw, parser_limits)
    except (ValueError, RecursionError) as error:
        graph.omit(root, 'existing-paw-mime-parser', type(error).__name__)
        report['issues'].append('parser_unavailable:'+type(error).__name__); return report
    stack = [(message, '0', 0, (0, len(raw)), [])]
    while stack:
        part, path, depth, span, inherited = stack.pop()
        if depth > limits.depth:
            graph.omit(root, 'mime-part-views', 'part_depth'); report['issues'].append('part_depth'); continue
        if len(report['parts']) >= limits.parts:
            graph.omit(root, 'mime-part-views', 'part_count'); report['issues'].append('part_count'); break
        fields, omitted = declarations(part, limits)
        row = {'path': path, 'depth': depth, 'declarations': fields, 'omitted_header_fields': omitted,
               'partial_ancestor_paths': inherited, 'wire_body_node': None, 'parser_selected_node': None,
               'candidate_nodes': [], 'candidate_text_nodes': [], 'issues': []}
        report['parts'].append(row)
        selected_type = part.get_content_type()
        row['selected_content_type'] = selected_type if len(selected_type) <= limits.declaration_bytes else None
        if row['selected_content_type'] is None: row['issues'].append('selected_content_type_budget')
        if omitted: row['issues'].append('header_field_budget')
        if any(field['status'] != 'captured' for field in fields): row['issues'].append('declaration_unavailable')
        if any(sum(field['name'] == name for field in fields) > 1 for name in DECLARATIONS):
            row['issues'].append('duplicate_declarations_first_parser_selection')
        if inherited: row['issues'].append('partial_ancestor_context')
        structural = sorted(set(type(value).__name__ for value in part.defects))
        if structural: row['issues'].append('parser_structure_defects')
        row['structure_defects'] = structural
        body = None
        if span and 'MissingHeaderBodySeparatorDefect' not in structural:
            body = body_start(raw, *span, limits.header_bytes)
            if body is None: row['issues'].append('wire_body_separator_unavailable_or_header_budget')
        else: row['issues'].append('wire_mapping_unavailable')
        children = part.get_payload()
        if part.get_content_maintype() == 'message':
            row['issues'].append('embedded_message_interpretation_not_in_this_scope')
        elif isinstance(children, list):
            mapped = closed_children(raw, body, span[1], part.get_boundary(), len(children)) if body is not None else None
            if mapped is None: row['issues'].append('complete_selected_boundary_mapping_unavailable')
            inherited_next = inherited+[path] if row['issues'] else inherited
            for index in reversed(range(len(children))):
                stack.append((children[index], path+'.'+str(index), depth+1,
                              mapped[index] if mapped is not None else None, inherited_next))
            continue
        if body is not None:
            # Charge scans/copies against the aggregate work budget too.
            if graph.work_bytes+span[1]-body <= graph.limits.work_bytes:
                graph.work_bytes += span[1]-body
                row['wire_body_node'] = graph.add('wire_body_slice', raw[body:span[1]], [root],
                    'exact-original-wire-slice', {'start': body, 'end': span[1], 'part_path': path,
                    'mapping': 'selected_complete_framing', 'interpretation_unique': False}, complete=True)
            else:
                graph.omit(root, 'exact-original-wire-slice', 'work_bytes'); row['issues'].append('graph_work_budget')
        if part.get_content_maintype() == 'message': continue
        # Existing decoder behavior is observed, including its defects and
        # selected-first fallback. Never replace that output with our candidate.
        if graph.spend(root, 'existing-paw-selected-payload') is None:
            row['issues'].append('graph_work_budget'); continue
        try: payload, source = decoded_payload(part)
        except (ValueError, UnicodeError, RecursionError) as error:
            row['issues'].append('parser_payload_unavailable:'+type(error).__name__); continue
        defects = sorted(set(type(value).__name__ for value in part.defects))
        row['payload_defects'] = defects
        if defects: row['issues'].append('parser_payload_defects')
        if type(payload) is bytes:
            parent = row['wire_body_node'] or root
            row['parser_selected_node'] = graph.add('parser_selected_payload', payload, [parent],
                'existing-paw-selected-payload', {'part_path': path, 'byte_source': source,
                'parser': 'email.policy.default', 'python_version': sys.version.split()[0],
                'wire_mapping_available': bool(row['wire_body_node'])},
                complete=not row['issues'] and source not in TRANSFER_PARTIAL_REASONS,
                notes=defects+(['parser_view_not_original_or_unique_interpretation'] if row['issues'] else []))
        # Finite alternatives derive from EXACT encoded wire bytes, never from
        # a repaired serialization or a decoder's replacement characters.
        wire = row['wire_body_node']
        encodings = []
        for field in fields:
            if field['name'] != 'content-transfer-encoding' or field['status'] != 'captured': continue
            candidate = field['value'].strip().lower()
            if candidate not in encodings: encodings.append(candidate)
        for encoding in encodings[:limits.alternatives]:
            if wire is None:
                graph.omit(root, 'mime-transfer-candidate', 'exact_wire_body_unavailable'); continue
            if encoding == 'base64': row['candidate_nodes'].extend(base64_views(graph, wire))
            elif encoding == 'quoted-printable':
                node = quoted_printable_view(graph, wire)
                if node: row['candidate_nodes'].append(node)
            elif encoding not in {'7bit', '8bit', 'binary'}:
                graph.omit(wire, 'mime-transfer-candidate', 'encoding_outside_finite_set')
        if len(encodings) > limits.alternatives:
            graph.omit(wire or root, 'mime-transfer-candidate', 'declaration_alternative_budget')
            row['issues'].append('declaration_alternative_budget')
        selected = row['parser_selected_node']
        charset = part.get_content_charset() or 'us-ascii'
        if selected:
            row['selected_text_node'] = text_view(graph, selected, charset)
        for candidate in row['candidate_nodes']:
            text = text_view(graph, candidate, charset)
            if text: row['candidate_text_nodes'].append(text)
    report['status'] = 'partial' if report['issues'] or any(row['issues'] for row in report['parts']) or graph.record()['status'] == 'partial' else 'completed'
    return report
