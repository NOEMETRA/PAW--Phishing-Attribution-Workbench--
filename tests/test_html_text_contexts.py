"""Real static parsers, not HTML5 rendering or phishing ground truth."""
import unittest
from unittest.mock import patch
from pathlib import Path
import subprocess
import sys

from paw.core.form_analysis import FormAnalyzer
from paw.core.kit_static import analyze_phishing_kit_content
from paw.core.mime_analysis import HtmlEvidenceParser
from paw.deobfuscate.html import HTMLDeobfuscator
from paw.deobfuscate.core import DeobfuscationEngine
import test_html_url_lists as url_lists
from test_mime_cid import inventory, sample


TEXT_TAGS = ('textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext')
LITERAL = ('<style>p{background:url(https://text.invalid/a)}</style>'
           '<form action="https://form.invalid/a"><input name="password"></form>'
           '<script>eval("https://script.invalid/a")</script>'
           '<img src="cid:logo@local.invalid">'
           '<img src="data:text/plain;base64,YQ==" style="display:none">')


class HTMLTextContexts(unittest.TestCase):
    def parse(self, markup):
        parser = HtmlEvidenceParser(); parser.feed(markup); parser.close()
        return parser

    def test_text_elements_preserve_literal_markup_and_do_not_create_attribute_urls(self):
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                parser = self.parse(f'<{tag}>{LITERAL}</{tag}>')
                self.assertEqual(''.join(parser.text), LITERAL + (f'</{tag}>' if tag == 'plaintext' else ''))
                self.assertEqual(parser.urls, [])

    def test_only_rcdata_decodes_character_references_once(self):
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                parser = self.parse(f'<{tag}>A&amp;amp;&lt;b&gt;</{tag}>')
                expected = 'A&amp;<b>' if tag in ('textarea','title') else 'A&amp;amp;&lt;b&gt;'
                if tag == 'plaintext': expected += '</plaintext>'
                self.assertEqual(''.join(parser.text),expected)

    def test_only_matching_ascii_end_tag_closes_text_and_preserves_url_suffixes(self):
        for tag in TEXT_TAGS[:-1]:
            with self.subTest(tag=tag):
                parser = self.parse(f'<{tag}>https://text.invalid/<b>tail</b></{tag}more></ {tag}>'
                                    f'</{tag.upper()} ><a href="https://after.invalid/">after</a>')
                self.assertEqual(''.join(parser.text),f'https://text.invalid/<b>tail</b></{tag}more></ {tag}>after')
                self.assertEqual(parser.urls,['https://after.invalid/'])

    def test_end_tags_with_ignored_attributes_or_slash_end_the_text_context(self):
        for suffix in (' attr="a>b"', '/', ' attr=unquoted', " attr=unquoted'", " attr'", ' a=one b="two>three"'):
            with self.subTest(suffix=suffix):
                parser = self.parse('<textarea>literal</textarea'+suffix+'><img src="https://after.invalid/">')
                self.assertEqual(''.join(parser.text),'literal')
                self.assertEqual(parser.urls,['https://after.invalid/'])

    def test_nonvoid_selfclosing_slash_cannot_expose_inner_markup(self):
        for tag in TEXT_TAGS + ('script','style'):
            with self.subTest(tag=tag):
                parser = self.parse(f'<{tag}/><img src="https://literal.invalid/a"></{tag}>')
                self.assertEqual(parser.urls,[])
                if tag not in ('script','style'):
                    self.assertIn('<img src=', ''.join(parser.text))

    def test_unclosed_text_and_chunked_references_are_not_lost(self):
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                parser = HtmlEvidenceParser()
                for chunk in (f'<{tag}>https://text.invalid/a?x=1&am', 'p;y=2<im', 'g src="x">'):
                    parser.feed(chunk)
                parser.close()
                entity = '&y=2' if tag in ('textarea','title') else '&amp;y=2'
                self.assertEqual(''.join(parser.text), 'https://text.invalid/a?x=1'+entity+'<img src="x">')
                self.assertEqual(parser.urls,[])

    def test_text_css_is_lexical_text_while_actual_style_keeps_url_argument_boundaries(self):
        helper = url_lists.HTMLURLListContracts()
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                _, _, targets, _, sources = helper.analyze(f'<{tag}><style>url(https://text.invalid/a)</style></{tag}>')
                self.assertEqual(targets,['https://text.invalid/a)'])
                self.assertEqual(sources['unmapped_evidence_count'],0)
        _, _, targets, _, _ = helper.analyze('<style>url(https://text.invalid/a)</style>')
        self.assertEqual(targets,['https://text.invalid/a'])

    def test_visible_text_is_joined_without_inventing_a_second_truncated_url(self):
        mime, _, targets, _, sources = url_lists.HTMLURLListContracts().analyze(
            '<textarea>https://text.invalid/<b>literal</b></textarea>')
        self.assertIn('https://text.invalid/<b>literal</b>',mime['body_text'])
        self.assertEqual(targets,['https://text.invalid/'])
        self.assertEqual(sources['total_link_count'],1)
        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_descriptive_html_has_no_fabricated_forms_scripts_hidden_or_encoded_nodes(self):
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                original = f'<{tag}>{LITERAL}</{tag}>'
                result = HTMLDeobfuscator().deobfuscate_html(original)
                self.assertEqual(result['final_html'],original)
                self.assertEqual(result['form_analysis']['forms'],[])
                self.assertEqual(result['javascript_analysis']['inline_scripts'],[])
                self.assertEqual(result['hidden_elements'],[])
                self.assertEqual(result['encoded_attribute_candidates']['candidates'],[])
                self.assertEqual(len(result['iframe_analysis']['iframes']),int(tag=='iframe'))
                self.assertEqual(result['assessment_status'],'descriptive_only')

    def test_real_outer_attributes_and_siblings_still_remain_observations(self):
        original = ('<form action="https://real.invalid/"><textarea><input type="hidden" value="http fake">'
                    '</textarea><input name="real"></form><script>console.log("real")</script>')
        result = HTMLDeobfuscator().deobfuscate_html(original)
        self.assertEqual([r['name'] for r in result['form_analysis']['forms'][0]['inputs']],['real'])
        self.assertEqual([r['content'] for r in result['javascript_analysis']['inline_scripts']],['console.log("real")'])
        mime,_,targets,_,_=url_lists.HTMLURLListContracts().analyze('<iframe src="https://real.invalid/">'+LITERAL+'</iframe>')
        self.assertEqual(mime['urls'][0],'https://real.invalid/')
        self.assertIn('https://real.invalid/',targets)

    def test_form_and_kit_consumers_do_not_reclassify_text_as_elements(self):
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                markup = f'<{tag}>{LITERAL}</{tag}>'
                forms = FormAnalyzer().analyze_forms(markup)
                self.assertEqual(forms['forms'],[])
                self.assertEqual(forms['script_observations'],[])
                kit = analyze_phishing_kit_content({'html':markup})
                self.assertTrue(kit['observations'])
                self.assertTrue(all(r['context']=='lexical_keyword' for r in kit['observations']))

    def test_cid_attribute_inventory_does_not_invent_nodes_inside_text(self):
        for tag in TEXT_TAGS:
            with self.subTest(tag=tag):
                result = inventory(sample(f'<{tag}><img src="cid:logo@local.invalid"></{tag}>'))
                self.assertEqual(result['total_observation_count'],0)
                self.assertEqual(result['total_link_count'],0)

    def test_each_mime_document_has_independent_unclosed_text_state(self):
        from email.message import EmailMessage
        from paw.core.mime_analysis import analyze_mime
        from paw.core.parser_mail import parse_message_bytes
        message = EmailMessage(); message.set_content('<plaintext>first',subtype='html')
        message.add_alternative('<a href="https://next.invalid/">second</a>',subtype='html')
        mime = analyze_mime(parse_message_bytes(message.as_bytes()))
        self.assertEqual(mime['urls'],['https://next.invalid/'])
        self.assertIn('first',mime['body_text']); self.assertIn('second',mime['body_text'])

    def test_unclosed_script_and_style_keep_hidden_literal_url_candidates_at_eof(self):
        for markup in ('<script>"https://eof.invalid/a"', '<style>url(https://eof.invalid/a)'):
            with self.subTest(markup=markup):
                _,_,targets,_,sources = url_lists.HTMLURLListContracts().analyze(markup)
                self.assertEqual(targets,['https://eof.invalid/a'])
                self.assertEqual(sources['total_link_count'],1)
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_closing_token_resumes_all_element_consumers_after_literal_text(self):
        for closer in ('</textarea>', '</textarea/>', '</textarea a="b>c">'):
            with self.subTest(closer=closer):
                markup = '<textarea><form action="fake"></form>'+closer+'<form action="real"><input name="real"></form>'
                self.assertEqual([r['action'] for r in HTMLDeobfuscator().deobfuscate_html(markup)['form_analysis']['forms']],['real'])
                self.assertEqual([r['action'] for r in FormAnalyzer().analyze_forms(markup)['forms']],['real'])
                kit = analyze_phishing_kit_content({'html':markup})
                self.assertEqual([r['value'] for r in kit['observations'] if r['context']=='html_attribute'],['real'])

    def test_independent_documents_cannot_close_or_swallow_each_others_elements(self):
        for tag in TEXT_TAGS + ('script','style'):
            with self.subTest(tag=tag):
                documents = [f'<{tag}>unclosed', '<form action="real"><input name="real"></form>']
                result = DeobfuscationEngine().analyze_artifacts({'html':documents})
                html = result['deobfuscated_artifacts']['html']
                self.assertEqual(html['html_schema_version'],3)
                self.assertEqual([r['document_index'] for r in html['documents']],[0,1])
                self.assertEqual([r['original_html'] for r in html['documents']],documents)
                self.assertEqual([len(r['form_analysis']['forms']) for r in html['documents']],[0,1])
                self.assertEqual(html['documents'][1]['form_analysis']['forms'][0]['inputs'][0]['name'],'real')
                self.assertEqual(result['coverage']['html']['status'],'descriptive_only')

    def test_missing_optional_parser_propagates_partial_document_coverage(self):
        with patch('paw.deobfuscate.html.HAS_BEAUTIFULSOUP',False):
            result = DeobfuscationEngine().analyze_artifacts({'html':['<p>first</p>','<p>second</p>']})
        html = result['deobfuscated_artifacts']['html']
        self.assertEqual(result['coverage']['html']['status'],'partial')
        self.assertEqual(html['parsing_status'],'not_evaluated')
        self.assertEqual([r['assessment_status'] for r in html['documents']],['partial','partial'])
        self.assertIsNone(result['suspicion_score'])

    def test_bounded_incomplete_end_tag_input_finishes_without_repeated_tail_scans(self):
        code = '''from paw.core.mime_analysis import HtmlEvidenceParser
payload = '</textarea x="' * 50000
parser = HtmlEvidenceParser()
parser.feed('<textarea>' + payload)
parser.close()
assert ''.join(parser.text) == payload
assert parser.urls == []
'''
        result = subprocess.run([sys.executable,'-B','-X','utf8','-c',code],
            cwd=Path(__file__).resolve().parents[1],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
