"""Actual HTML CSS candidate/source views; no browser or resource selection."""
import base64
from html import escape
import unittest

import test_html_url_lists as html_contracts


class CSSURLContextContracts(unittest.TestCase):
    def analyze(self, css, *, attribute=False, **kwargs):
        markup = ('<div style="'+escape(css,quote=True)+'"></div>' if attribute
                  else '<style>'+css+'</style>')
        return html_contracts.HTMLURLListContracts().analyze(markup,**kwargs)

    def test_unquoted_url_syntax_is_not_part_of_the_resource(self):
        for attribute in (False,True):
            for css in ('a{background:url(https://one.invalid/a)}',
                        'a{a:URL(\t https://one.invalid/a \r\n);b:url(https://two.invalid/b)}'):
                with self.subTest(attribute=attribute,css=css):
                    _,_,targets,_,sources = self.analyze(css,attribute=attribute)
                    expected = ['https://one.invalid/a']
                    if 'two.invalid' in css: expected.append('https://two.invalid/b')
                    self.assertEqual(targets,expected)
                    self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_data_and_relative_arguments_cannot_contribute_embedded_http_targets(self):
        css = ('a{a:url(data:text/plain,https://embedded.invalid/a);'
               'b:url(/relative?next=https://query.invalid/b);'
               'c:url("data:text/plain,https://quoted.invalid/c");'
               'd:url("/relative?next=https://relative.invalid/d");'
               'e:url(https://good.invalid/e)}')
        for attribute in (False,True):
            with self.subTest(attribute=attribute):
                _,candidates,targets,evidence,_ = self.analyze(css,attribute=attribute)
                self.assertEqual(candidates,['https://good.invalid/e'])
                self.assertEqual(targets,candidates)
                self.assertEqual([row['url'] for row in evidence],candidates)

    def test_quoted_resource_parentheses_commas_and_apostrophes_are_preserved(self):
        urls = ["https://one.invalid/a(b),c'd?x=a,b#c(d)",'https://two.invalid/a%29b%22c']
        css = 'a{a:url("'+urls[0]+'");b:url(\''+urls[1]+'\')}'
        for attribute in (False,True):
            with self.subTest(attribute=attribute):
                self.assertEqual(self.analyze(css,attribute=attribute)[2],urls)

    def test_attribute_entities_decode_once_and_style_raw_text_stays_literal(self):
        markup = ('<div style="a:url(&quot;https://one.invalid/a?x=1&amp;y=2&quot;)"></div>'
                  '<style>a{b:url("https://two.invalid/a?x=1&amp;y=2")}</style>')
        _,_,targets,_,sources = html_contracts.HTMLURLListContracts().analyze(markup)
        self.assertEqual(targets,['https://one.invalid/a?x=1&y=2','https://two.invalid/a?x=1&amp;y=2'])
        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_invalid_http_and_undecoded_css_escapes_remain_whole_nontarget_evidence(self):
        values = ['https://bad.invalid/%ZZ','https://bad.invalid:bad/a',r'https://escaped.invalid/a\)tail']
        css = 'a{'+''.join('x:url('+value+');' for value in values)+'}'
        _,_,targets,evidence,sources = self.analyze(css)
        self.assertEqual(targets,[])
        self.assertEqual([row['source_url'] for row in evidence],values)
        self.assertTrue(all(not row['network_target'] for row in evidence))
        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_malformed_functions_are_evidence_without_a_valid_looking_prefix_target(self):
        for css in ('url(https://bad.invalid/a(b))','url(https://bad.invalid/a tail)',
                    'url("https://bad.invalid/a"junk)','url(https://bad.invalid/a',
                    'url("https://bad.invalid/a)', 'url(https://bad.invalid/a\'tail)'):
            with self.subTest(css=css):
                _,_,targets,evidence,sources = self.analyze(css)
                self.assertEqual(targets,[])
                self.assertEqual(len(evidence),1)
                self.assertTrue(evidence[0]['source_url'].startswith('url('))
                self.assertFalse(evidence[0]['network_target'])
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_recovered_argument_tokens_keep_original_links(self):
        token = base64.b64encode(b'https://encoded.invalid/a%2Fb').decode()
        css = 'a{a:url(hxxps://one[.]invalid/a%2Fb);b:url('+token+')}'
        _,_,targets,evidence,sources = self.analyze(css)
        self.assertEqual(targets,['https://one.invalid/a%2Fb','https://encoded.invalid/a%2Fb'])
        self.assertEqual([row['source_url'] for row in evidence],['hxxps://one[.]invalid/a%2Fb',token])
        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_nonfunction_literals_and_other_html_contexts_keep_their_original_behavior(self):
        for css,expected in (('/* url(https://comment.invalid/a) */','https://comment.invalid/a)'),
                    ('a{content:"url(https://comment.invalid/a)"}','https://comment.invalid/a)'),
                    ('a{a:myurl(https://comment.invalid/a)}','https://comment.invalid/a)}')):
            with self.subTest(css=css):
                # These remain generic lexical candidates, not interpreted URL arguments.
                self.assertEqual(self.analyze(css)[2],[expected])
        markup = '<a href="https://scalar.invalid/a)">go</a><script>"https://script.invalid/a)"</script>'
        self.assertEqual(html_contracts.HTMLURLListContracts().analyze(markup)[2],
                         ['https://scalar.invalid/a)','https://script.invalid/a)'])

    def test_repeated_css_views_keep_exact_source_retention_counts(self):
        _,_,targets,_,sources = self.analyze('a{a:url(https://one.invalid/a);b:url(https://two.invalid/b)}',
                                           parts=5,max_links=4)
        self.assertEqual(len(targets),2)
        self.assertEqual(sources['total_link_count'],10)
        self.assertEqual(sources['inventoried_link_count'],4)
        self.assertEqual(sources['omitted_link_count'],6)
        for source in sources['sources']:
            if source['kind']=='mime_body':
                self.assertEqual(source['derivation']['method'],'paw_html_url_candidate_views_v5')


if __name__=='__main__': unittest.main()
