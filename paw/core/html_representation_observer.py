"""Bounded lexical HTML observations of an explicitly selected UTF-8 view.

This is neither browser parsing nor DOM recovery. Input scripts, CSS, entities
and references are not executed, fetched or used as host paths. Any malformed
or truncated syntax remains an observation with the original bytes retained.
"""
from dataclasses import dataclass
from html.parser import HTMLParser
import hashlib


@dataclass(frozen=True)
class HTMLLimits:
    input_bytes: int = 1024**2
    tokens: int = 4096
    depth: int = 64
    tag_characters: int = 65536

    def __post_init__(self):
        caps = {'input_bytes': 2*1024**2, 'tokens': 16384, 'depth': 128, 'tag_characters': 131072}
        for name, cap in caps.items():
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= cap: raise ValueError('html_observation_limit_'+name)


class _BoundReached(ValueError): pass


VOID = frozenset('area base br col embed hr img input link meta param source track wbr'.split())


class _Observer(HTMLParser):
    def __init__(self, limits):
        super().__init__(convert_charrefs=False)
        self.limits = limits; self.tokens = 0; self.stack = []; self.events = []
        self.issues = []; self.starts = self.ends = self.scripts = self.references = 0
        self.data_characters = self.comments = self.entities = 0

    def tick(self):
        if self.tokens >= self.limits.tokens: raise _BoundReached('token_count')
        self.tokens += 1

    def issue(self, reason):
        if reason not in self.issues: self.issues.append(reason)

    def start(self, tag, attrs, closed):
        self.tick(); self.starts += 1
        raw = self.get_starttag_text()
        if len(raw) > self.limits.tag_characters: raise _BoundReached('tag_characters')
        # These positions refer to the decoded UTF-8 TEXT representation, never
        # original MIME byte offsets; attributes are parser-normalized values.
        if len(self.events) < 32:
            self.events.append({'kind': 'start', 'tag': tag[:128], 'text_line_column': list(self.getpos()),
                                'raw_tag_utf8_sha256': hashlib.sha256(raw.encode('utf-8')).hexdigest(),
                                'attribute_count': len(attrs)})
        self.scripts += tag == 'script'
        self.references += sum(name in {'src', 'href', 'action', 'formaction', 'poster', 'srcset'} for name, _ in attrs)
        if not closed and tag not in VOID:
            if len(self.stack) >= self.limits.depth: raise _BoundReached('lexical_open_tag_depth')
            self.stack.append(tag)

    def handle_starttag(self, tag, attrs): self.start(tag, attrs, False)
    def handle_startendtag(self, tag, attrs): self.start(tag, attrs, True)

    def handle_endtag(self, tag):
        self.tick(); self.ends += 1
        if not self.stack or self.stack[-1] != tag:
            self.issue('lexical_mismatched_end_tag')
        else: self.stack.pop()

    def handle_data(self, data): self.tick(); self.data_characters += len(data)
    def handle_comment(self, data): self.tick(); self.comments += 1
    def handle_entityref(self, name): self.tick(); self.entities += 1
    def handle_charref(self, name): self.tick(); self.entities += 1
    def handle_decl(self, decl): self.tick()
    def handle_pi(self, data): self.tick(); self.issue('processing_instruction_observed')
    def unknown_decl(self, data): self.tick(); self.issue('unrecognized_declaration_observed')


def observe_html(graph, parent, limits=HTMLLimits()):
    node = graph.nodes[parent]
    if node['kind'] != 'utf8_text_candidate': raise ValueError('html_requires_explicit_utf8_text_view')
    raw = graph.payload(parent)
    result = {'schema': 'paw-forensic-html-lexical-v1', 'representation': parent,
              'representation_sha256': node['sha256'], 'status': 'partial', 'issues': [],
              'scope': 'bounded stdlib HTMLParser lexical events; not browser DOM, validity or execution',
              'positions': 'line/column in selected decoded UTF-8 text, not original wire byte offsets',
              'character_references': 'not resolved in text events; attribute parsing may normalize them',
              'origin_verified': False, 'execution_authority': 'none', 'limits': vars(limits)}
    if len(raw) > limits.input_bytes:
        graph.omit(parent, 'html-lexical-observation', 'html_input_bytes')
        result['issues'].append('html_input_bytes'); return result
    if graph.spend(parent, 'html-lexical-observation') is None:
        result['issues'].append('graph_work_budget'); return result
    try: text = raw.decode('utf-8', 'strict')
    except UnicodeError:
        result['issues'].append('invalid_utf8_text_representation'); return result
    parser = _Observer(limits)
    try:
        # Finite input budget plus the supervising worker's CPU/AS limits bounds
        # parsing work even before callbacks (e.g. a single long start tag).
        parser.feed(text)
        pending = len(parser.rawdata)
        if pending: parser.issue('incomplete_markup_or_raw_text_at_eof')
        parser.close()
        if parser.stack: parser.issue('lexically_unclosed_start_tags')
    except _BoundReached as error:
        parser.issue(str(error)); graph.omit(parent, 'html-lexical-observation', str(error))
    except (ValueError, AssertionError) as error:
        parser.issue('lexical_parser_error:'+type(error).__name__)
    result.update(issues=parser.issues, tokens_observed=parser.tokens, start_tags=parser.starts,
                  end_tags=parser.ends, script_start_tags=parser.scripts,
                  reference_attributes_observed=parser.references, data_characters_observed=parser.data_characters,
                  comments_observed=parser.comments, character_references_observed=parser.entities,
                  first_events=parser.events, lexical_open_tag_count=len(parser.stack),
                  status='partial' if parser.issues else 'observed')
    return result
