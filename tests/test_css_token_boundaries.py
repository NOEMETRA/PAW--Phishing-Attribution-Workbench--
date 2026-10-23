"""Actual CSS candidate/MIME/source views, not browser or accuracy claims."""
import base64
import unittest

import test_css_url_contexts as css_contracts


class CSSTokenBoundaries(unittest.TestCase):
    def analyze(self, css, **kwargs):
        return css_contracts.CSSURLContextContracts().analyze(css, **kwargs)

    def test_hash_and_at_keyword_names_are_not_url_function_tokens(self):
        for attribute in (False,True):
            for prefix in ('#','@'):
                with self.subTest(attribute=attribute,prefix=prefix):
                    _,_,targets,_,sources = self.analyze(prefix+'url(https://literal.invalid/a)',attribute=attribute)
                    self.assertEqual(targets,['https://literal.invalid/a)'])
                    self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_actual_url_function_inside_a_hash_or_keyword_block_is_not_swallowed(self):
        for prefix in ('#','@'):
            with self.subTest(prefix=prefix):
                _,_,targets,evidence,_ = self.analyze(prefix+'url(url(https://actual.invalid/a))')
                self.assertEqual(targets,['https://actual.invalid/a'])
                self.assertEqual(len(evidence),1)

    def test_invalid_identifier_escape_ends_the_name_before_the_next_function(self):
        for newline in ('\n','\r','\f','\r\n'):
            for prefix in ('prefix','#prefix','@prefix',''):
                with self.subTest(newline=newline,prefix=prefix):
                    self.assertEqual(self.analyze(prefix+'\\'+newline+'url(https://actual.invalid/a)')[2],
                                     ['https://actual.invalid/a'])

    def test_valid_identifier_escapes_and_ordinary_names_keep_lexical_identity(self):
        for prefix in ('myurl',r'u\72l',r'prefix\ url',r'#u\72l',r'@u\72l'):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.analyze(prefix+'(https://literal.invalid/a)')[2],
                                 ['https://literal.invalid/a)'])
        self.assertEqual(self.analyze('\\')[2],[])

    def test_comments_after_a_quoted_argument_are_separators_not_argument_text(self):
        for attribute in (False,True):
            for trivia in ('/**/',' /**/\t/* ) \' " ( */\n'):
                with self.subTest(attribute=attribute,trivia=trivia):
                    _,_,targets,evidence,sources = self.analyze('url("https://actual.invalid/a"'+trivia+')',attribute=attribute)
                    self.assertEqual(targets,['https://actual.invalid/a'])
                    self.assertEqual(len(evidence),1)
                    self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_http_mentions_in_argument_trivia_remain_whole_nontarget_evidence(self):
        trivia = ' /* https://comment.invalid/a ) */\t/**/'
        _,_,targets,evidence,sources = self.analyze('url("https://actual.invalid/a"'+trivia+')')
        self.assertEqual(targets,['https://actual.invalid/a'])
        self.assertEqual([row.get('source_url',row['url']) for row in evidence],
                         ['https://actual.invalid/a',trivia])
        self.assertFalse(evidence[1]['network_target'])
        self.assertEqual(sources['total_link_count'],2)
        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_nonnetwork_arguments_do_not_promote_http_mentions_from_comments(self):
        encoded = base64.b64encode(b'https://comment.invalid/a').decode()
        for marker in ('https://comment.invalid/a','hxxps://comment[.]invalid/a',encoded):
            trivia = '/* '+marker+' */'
            for argument in ('/relative?next=https://inner.invalid/a','data:text/plain,https://inner.invalid/a'):
                with self.subTest(argument=argument,marker=marker):
                    _,_,targets,evidence,_ = self.analyze('url("'+argument+'"'+trivia+')')
                    self.assertEqual(targets,[])
                    self.assertEqual([row['source_url'] for row in evidence],[trivia])

    def test_unsupported_quoted_function_is_retained_through_comments_strings_and_blocks(self):
        values = ['url("https://actual.invalid/a"/* ) https://comment.invalid/a */ junk("x)"))',
                  'url("https://actual.invalid/a" extra([x){}]))',
                  'url("https://actual.invalid/a"/**/ "https://extra.invalid/b")']
        for value in values:
            with self.subTest(value=value):
                _,_,targets,evidence,sources = self.analyze(value)
                self.assertEqual(targets,[])
                self.assertEqual([row['source_url'] for row in evidence],[value])
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_incomplete_quoted_functions_retain_the_entire_remaining_source(self):
        for value in ('url("https://actual.invalid/a"/* https://comment.invalid/a )',
                      'url("https://actual.invalid/a" extra([unclosed)',
                      'url("https://actual.invalid/a"/**/'):
            with self.subTest(value=value):
                self.assertEqual([row['source_url'] for row in self.analyze(value)[3]],[value])

    def test_leading_comments_and_unquoted_bad_url_recovery_are_not_reinterpreted(self):
        for value in ('url(/**/"https://actual.invalid/a")','url(https://actual.invalid/a tail)',
                      'url(https://actual.invalid/a("nested"))'):
            with self.subTest(value=value):
                self.assertEqual(self.analyze(value)[2],[])

    def test_recovered_argument_and_entity_identity_remain_source_bound(self):
        encoded = base64.b64encode(b'https://actual.invalid/a%2Fb').decode()
        for value in (encoded,'hxxps://actual[.]invalid/a%2Fb'):
            with self.subTest(value=value):
                _,_,targets,evidence,sources = self.analyze('url("'+value+'"/**/)',attribute=True)
                self.assertEqual(targets,['https://actual.invalid/a%2Fb'])
                self.assertEqual([row['source_url'] for row in evidence],[value])
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_repeated_views_count_targets_and_opaque_trivia_separately(self):
        _,_,targets,_,sources = self.analyze('url("https://actual.invalid/a"/* https://comment.invalid/a */)',
                                           parts=5,max_links=4)
        self.assertEqual(targets,['https://actual.invalid/a'])
        self.assertEqual((sources['total_link_count'],sources['inventoried_link_count'],sources['omitted_link_count']),
                         (10,4,6))
        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_deep_unsupported_component_blocks_are_iterative_and_source_complete(self):
        value = 'url("https://actual.invalid/a" extra('+'['*20000+'x'+']'*20000+'))'
        _,_,targets,evidence,sources = self.analyze(value)
        self.assertEqual(targets,[])
        self.assertEqual([row['source_url'] for row in evidence],[value])
        self.assertEqual(sources['total_link_count'],1)
        self.assertEqual(sources['unmapped_evidence_count'],0)


if __name__=='__main__': unittest.main()
