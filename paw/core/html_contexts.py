"""Shared lexical HTML text boundaries, not an HTML5 tree builder or renderer."""
from html import unescape
from html.parser import HTMLParser
import re


class HTMLTextContextParser(HTMLParser):
    RCDATA = ('textarea', 'title')
    RAWTEXT = ('script', 'style', 'xmp', 'iframe', 'noembed', 'noframes')
    CDATA_CONTENT_ELEMENTS = RCDATA + RAWTEXT + ('plaintext',)

    def set_cdata_mode(self, elem, *, escapable=False):
        self.cdata_elem = elem.lower()
        # Newer maintenance releases pass escapable and consult _escapable in
        # goahead(). Keep text raw there: text_data() owns once-only RCDATA
        # decoding on both old and new stdlibs, including the optional builder.
        self._escapable = False
        # Only an appropriate end-tag name can leave a text context. Unlike
        # the stdlib matcher, whitespace after '</' is not an end tag, while
        # ASCII whitespace, '/' or '>' after the name permits an end token.
        self.interesting = (re.compile(r'(?!)') if self.cdata_elem == 'plaintext' else
            re.compile(r'</' + re.escape(self.cdata_elem) + r'(?=[\t\n\f\r />])', re.I | re.ASCII))

    def parse_endtag(self, i):
        if not self.cdata_elem:
            return super().parse_endtag(i)
        # Keep quoted '>' inside an ignored end-tag attribute in this token.
        # An incomplete token stays buffered and is emitted literally at EOF.
        quote, state = None, 'name'
        for position in range(i + 2 + len(self.cdata_elem), len(self.rawdata)):
            char = self.rawdata[position]
            if quote:
                if char == quote: quote, state = None, 'name'
            elif char == '>':
                self.handle_endtag(self.cdata_elem)
                self.clear_cdata_mode()
                return position + 1
            elif state == 'before_value':
                if char in '\t\n\f\r ': continue
                if char in "\"'": quote = char
                else: state = 'unquoted'
            elif state == 'unquoted':
                if char in '\t\n\f\r ': state = 'name'
            elif char == '=':
                state = 'before_value'
        if getattr(self, '_at_eof', False):
            # The stdlib EOF recovery can retry every '<' in an incomplete
            # end token, repeatedly scanning the same remaining tail. Retain
            # that entire tail once, without fabricating a closing event.
            self.handle_data(self.rawdata[i:])
            return len(self.rawdata)
        return -1

    def handle_startendtag(self, tag, attrs):
        if tag in self.CDATA_CONTENT_ELEMENTS:
            # These are nonvoid HTML elements: '/>' does not end their text.
            self.handle_starttag(tag, attrs)
            self.set_cdata_mode(tag)
        else:
            super().handle_startendtag(tag, attrs)

    def text_data(self, data):
        """Character references are interpreted once in RCDATA, never RAWTEXT."""
        return unescape(data) if self.cdata_elem in self.RCDATA else data

    def close(self):
        self._at_eof = True
        try:
            super().close()
        finally:
            self._at_eof = False
        # Supported Python versions differ in EOF handling of CDATA buffers.
        # Preserve unclosed source text without inventing an end-tag event.
        if self.cdata_elem and self.rawdata:
            data = self.rawdata
            self.handle_data(data)
            self.updatepos(0, len(data))
            self.rawdata = ''
