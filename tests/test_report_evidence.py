"""Passive Markdown rendering and JSON recovery, without resource requests."""
import json
import unittest

from markdown_it import MarkdownIt

from paw.core.reporting import markdown_json, markdown_literal


VALUES = [None, False, True, 0, -4, 1.25, '', 'ordinary.example',
          'ricevuta città 日本語', ' leading\tand\r\ntrailing ',
          '\x00\x1b[31m\u202econtrol', '![image](https://image.invalid/pixel)',
          '[link](https://link.invalid/) <img src="https://html.invalid/pixel">',
          '&copy; <script>inert()</script>', '\n```\n# forged heading\n```\n',
          *['`'*count + '|' + '\\'*count + '|tail' for count in range(1, 9)],
          {'observed': ['\n~~~\n# heading', '\n````\n', None, True]}]


class ReportEvidenceContracts(unittest.TestCase):
    def test_scalar_observations_round_trip_in_paragraphs(self):
        parser = MarkdownIt('commonmark')
        for value in VALUES:
            with self.subTest(value=value):
                tokens = parser.parse('Observed: '+markdown_literal(value))
                self.assertEqual([item.type for item in tokens],
                                 ['paragraph_open', 'inline', 'paragraph_close'])
                children = tokens[1].children
                self.assertEqual([item.type for item in children], ['text', 'code_inline'])
                self.assertEqual(json.loads(children[1].content), value)

    def test_table_boundary_preserves_backslashes_pipes_and_types(self):
        parser = MarkdownIt('commonmark').enable('table')
        for value in VALUES:
            with self.subTest(value=value):
                tokens = parser.parse('| Observation |\n| --- |\n| '+markdown_literal(value, table=True)+' |\n')
                cells = [item for item in tokens if item.type == 'inline']
                self.assertEqual(len(cells), 2)
                self.assertEqual([item.type for item in cells[1].children], ['code_inline'])
                self.assertEqual(json.loads(cells[1].children[0].content), value)

    def test_json_sources_cannot_end_the_fence_or_create_markup(self):
        parser = MarkdownIt('commonmark')
        for value in VALUES:
            with self.subTest(value=value):
                tokens = parser.parse(markdown_json({'source': value}))
                self.assertEqual([item.type for item in tokens], ['fence'])
                self.assertEqual(tokens[0].info, 'json')
                self.assertEqual(json.loads(tokens[0].content), {'source': value})
                self.assertNotIn('\x1b', tokens[0].content)
                self.assertNotIn('\u202e', tokens[0].content)


if __name__ == '__main__':
    unittest.main()
