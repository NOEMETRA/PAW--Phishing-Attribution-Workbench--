"""Whole supplied HTML URL fields, without navigation or browser normalization."""
import base64
from html import escape
import unittest
from urllib.parse import quote

import test_html_url_lists as helpers


FIELDS = [('a','href'),('img','src'),('form','action'),('button','formaction'),
          ('video','poster'),('object','data')]


def markup(tag, name, value):
    return '<'+tag+' '+name+'="'+escape(value,quote=True)+'">go</'+tag+'>'


class HTMLScalarURLContracts(unittest.TestCase):
    def analyze(self, text, **kwargs):
        return helpers.HTMLURLListContracts().analyze(text,**kwargs)

    def test_nonnetwork_relative_and_script_fields_retain_whole_nontarget_values(self):
        values = ['data:text/plain,https://embedded.invalid/a',
                  '/relative?next=https://embedded.invalid/a',
                  '//one.invalid/?next=https://embedded.invalid/a',
                  "javascript:send('https://embedded.invalid/a')"]
        for tag,name in FIELDS:
            for value in values:
                with self.subTest(tag=tag,name=name,value=value):
                    mime,candidates,targets,evidence,sources = self.analyze(markup(tag,name,value))
                    self.assertEqual(mime['urls'],[])
                    self.assertEqual(candidates,[value])
                    self.assertEqual(targets,[])
                    self.assertEqual([row['source_url'] for row in evidence],[value])
                    self.assertFalse(evidence[0]['network_target'])
                    self.assertEqual(evidence[0]['status'],'not_url')
                    self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_valid_resource_apostrophes_commas_entities_and_percent_octets_keep_identity(self):
        value = "HTTPS://one.invalid/O'Reilly,a%29b?x=c'd&y=%22#e'f"
        for tag,name in FIELDS:
            with self.subTest(tag=tag,name=name):
                mime,candidates,targets,_,sources = self.analyze(markup(tag,name,value))
                self.assertEqual(mime['urls'],[value])
                self.assertEqual(candidates,[value])
                self.assertEqual(targets,[value])
                self.assertEqual(sources['total_link_count'],1)

    def test_invalid_fields_are_not_replaced_by_valid_looking_prefixes(self):
        values = ['https://one.invalid/a tail','https://one.invalid/a"tail',
                  'https://one.invalid/a<tail','https://one.invalid/a>tail',
                  ' https://one.invalid/a ','https://one.invalid/a\u00a0tail',
                  'https://one.invalid/a\ttail']
        for tag,name in FIELDS:
            for value in values:
                with self.subTest(tag=tag,value=value):
                    _,candidates,targets,evidence,sources = self.analyze(markup(tag,name,value))
                    self.assertEqual(candidates,[value])
                    self.assertEqual(targets,[])
                    self.assertEqual([row['source_url'] for row in evidence],[value])
                    self.assertEqual(evidence[0]['status'],'not_url' if value.startswith(' ') else 'invalid')
                    self.assertFalse(evidence[0]['network_target'])
                    self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_two_urls_in_one_scalar_field_are_one_invalid_original_value(self):
        value = 'https://one.invalid/a https://two.invalid/b'
        _,_,targets,evidence,_ = self.analyze(markup('a','href',value))
        self.assertEqual(targets,[])
        self.assertEqual([row['source_url'] for row in evidence],[value])

    def test_refanged_and_encoded_whole_fields_keep_distinct_source_links(self):
        target = 'https://one.invalid/a%2Fb?next=https://nested.invalid/c'
        values = [target.replace('https://one.invalid','hxxps://one[.]invalid'),
                  quote(target,safe=''),base64.b64encode(target.encode()).decode()]
        for tag,name in FIELDS:
            with self.subTest(tag=tag,name=name):
                text = ''.join(markup(tag,name,value) for value in values)
                mime,_,targets,evidence,sources = self.analyze(text)
                self.assertEqual(mime['urls'],[])
                self.assertEqual(targets,[target])
                self.assertEqual([row['source_url'] for row in evidence],values)
                self.assertEqual(sources['total_link_count'],3)
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_arbitrary_metadata_attributes_keep_lexical_candidate_extraction(self):
        for name in ('data','data-next','title'):
            with self.subTest(name=name):
                value = 'please inspect https://metadata.invalid/a'
                self.assertEqual(self.analyze(markup('div',name,value))[2],['https://metadata.invalid/a'])

    def test_outer_absolute_query_is_preserved_without_promoting_its_embedded_url(self):
        value = "https://outer.invalid/a?next=https://nested.invalid/O'Reilly,a"
        mime,_,targets,_,_ = self.analyze(markup('a','href',value))
        self.assertEqual(mime['urls'],[value])
        self.assertEqual(targets,[value])

    def test_repeated_scalar_sources_keep_exact_link_and_omission_accounting(self):
        text = markup('a','href','https://one.invalid/a')+markup('img','src','data:text/plain,https://inner.invalid/b')
        _,_,targets,evidence,sources = self.analyze(text,parts=5,max_links=4)
        self.assertEqual(targets,['https://one.invalid/a'])
        self.assertEqual(len(evidence),2)
        self.assertEqual(sources['total_link_count'],10)
        self.assertEqual(sources['inventoried_link_count'],4)
        self.assertEqual(sources['omitted_link_count'],6)
        self.assertEqual(sources['unmapped_evidence_count'],0)
        for source in sources['sources']:
            if source['kind']=='mime_body':
                self.assertEqual(source['derivation']['method'],'paw_html_url_candidate_views_v5')

    def test_empty_and_unrecognized_fields_do_not_invent_http_evidence(self):
        for value in ('','/relative/path','data:text/plain,hello','mailto:user@example.invalid'):
            with self.subTest(value=value):
                _,_,targets,evidence,_ = self.analyze(markup('a','href',value))
                self.assertEqual(targets,[])
                self.assertEqual(evidence,[])


if __name__=='__main__': unittest.main()
