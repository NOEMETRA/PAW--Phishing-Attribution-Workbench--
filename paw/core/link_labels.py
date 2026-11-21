"""Bounded static pairing of HTML anchor text and a declared href."""
from .html_contexts import HTMLTextContextParser


class LinkLabels(HTMLTextContextParser):
    _INLINE_TAGS = frozenset({'b','em','font','i','small','span','strong','u'})
    _INERT_TAGS = frozenset({'math','svg','template'})
    _LIMIT = 256
    _VALUE_LIMIT = 4096

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.partial = False
        self._anchor = None
        self._depth = 0
        self._inert = []
        self._count = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._INERT_TAGS:
            self._inert.append(tag)
            self._anchor = None
        if self._inert:
            return
        if tag == 'a':
            self._depth += 1
            self._count += 1
            self._anchor = None
            if self._count > self._LIMIT:
                self.partial = True
                return
            hrefs = [value for name,value in attrs if name == 'href']
            if self._depth != 1 or len(hrefs) != 1 or not hrefs[0]:
                return
            if len(hrefs[0]) > self._VALUE_LIMIT:
                self.partial = True
                return
            self._anchor = (hrefs[0], '', self.getpos())
        elif tag not in self._INLINE_TAGS:
            self._anchor = None

    def handle_data(self, data):
        if self._anchor is None:
            return
        href, label, position = self._anchor
        if len(label)+len(data) > self._VALUE_LIMIT:
            self._anchor = None
            self.partial = True
        else:
            self._anchor = (href, label+data, position)

    def handle_endtag(self, tag):
        if self._inert:
            if tag == self._inert[-1]:
                self._inert.pop()
            return
        if tag == 'a' and self._depth:
            self._depth -= 1
            if self._anchor is not None:
                href, label, position = self._anchor
                self.links.append((href, label.strip(), position))
                self._anchor = None

    def close(self):
        super().close()
        self.partial |= bool(self._depth or self._inert or self.cdata_elem)
