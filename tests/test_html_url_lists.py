"""Actual HTML/MIME candidate views; fixtures do not establish browser selection."""
import base64
from email.message import EmailMessage
from email import policy
from html import escape
from pathlib import Path
import tempfile
import unittest

from paw.core.header_inventory import inventory_headers
from paw.core.mime_analysis import analyze_mime
from paw.core.mime_body_evidence import preserve_body_parts
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_eml_bytes, parse_message_bytes
from paw.core.url_evidence import extract_mime_url_candidates, build_url_evidence
from paw.core.url_sources import inventory_url_sources
from paw.deobfuscate.core import DeobfuscationEngine


class HTMLURLListContracts(unittest.TestCase):
    def analyze(self, markup, parts=1, max_links=4096):
        message = EmailMessage(policy=policy.SMTP)
        message['From'] = 'fixture@example.invalid'
        message.set_content(markup, subtype='html')
        for _ in range(parts-1): message.add_alternative(markup, subtype='html')
        raw = message.as_bytes()
        with offline_policy(), tempfile.TemporaryDirectory() as temporary:
            before = len(violations())
            headers = parse_eml_bytes(raw); parsed = parse_message_bytes(raw)
            mime = analyze_mime(parsed)
            candidates = extract_mime_url_candidates(mime)
            engine = DeobfuscationEngine()
            results = [engine.deobfuscate_url(value) for value in dict.fromkeys(mime['urls']+candidates)]
            targets, evidence = build_url_evidence(mime['urls'], results)
            bodies = preserve_body_parts(mime, raw, Path(temporary)/'mime_body')
            sources = inventory_url_sources(mime,bodies,parsed,headers,
                        inventory_headers(parsed,raw),evidence,max_links=max_links)
            self.assertEqual(parsed._paw_source_bytes, raw)
            self.assertEqual(len(violations()), before)
        return mime, candidates, targets, evidence, sources

    def test_both_list_attributes_exclude_syntactic_trailing_commas(self):
        for tag, name in [('img','srcset'),('source','srcset'),('link','imagesrcset')]:
            with self.subTest(tag=tag, name=name):
                mime, candidates, targets, _, _ = self.analyze(
                    f'<{tag} {name}="https://one.invalid/a, https://two.invalid/b 2x">')
                expected = ['https://one.invalid/a','https://two.invalid/b']
                self.assertEqual(mime['urls'], expected)
                self.assertEqual(candidates, expected)
                self.assertEqual(targets, expected)

    def test_internal_commas_escapes_entities_and_case_retain_resource_identity(self):
        expected = ['HTTPS://one.invalid/a,b%2Cc?x=a,b&y=2#c,d', 'https://two.invalid/x']
        _, _, targets, _, _ = self.analyze('<img SRCSET="'
            +expected[0].replace('&','&amp;')+' 1x, https://two.invalid/x,">')
        self.assertEqual(targets, expected)
        # A comma without whitespace stays inside the URL token.
        _, _, targets, _, _ = self.analyze('<img srcset="https://one.invalid/a,https://two.invalid/b">')
        self.assertEqual(targets, ['https://one.invalid/a,https://two.invalid/b'])

    def test_descriptors_and_nonnetwork_url_components_are_not_outer_candidates(self):
        _, _, targets, evidence, _ = self.analyze(
            '<img srcset="data:text/plain,https://embedded.invalid/a 1x, '
            '/relative?next=https://query.invalid/a 2x, '
            'https://good.invalid/a bad(https://descriptor.invalid/x,y), '
            'https://next.invalid/a 3x">')
        self.assertEqual(targets, ['https://good.invalid/a','https://next.invalid/a'])
        self.assertEqual([item['url'] for item in evidence], targets)

    def test_encoded_and_refanged_tokens_keep_original_source_links(self):
        token = base64.b64encode(b'https://encoded.invalid/a%2Fb').decode()
        value = f'<img srcset="hxxps://refanged[.]invalid/a%2Fb, {token} 2x">'
        _, _, targets, evidence, source = self.analyze(value)
        self.assertEqual(targets, ['https://refanged.invalid/a%2Fb','https://encoded.invalid/a%2Fb'])
        self.assertEqual([item['source_url'] for item in evidence],
                         ['hxxps://refanged[.]invalid/a%2Fb',token])
        self.assertEqual(source['unmapped_evidence_count'],0)
        self.assertEqual(source['total_link_count'],2)

    def test_invalid_and_long_tokens_remain_whole_nontarget_evidence(self):
        for token in ('https://bad.invalid/%ZZ','https://bad.invalid:bad/a',
                      'https://bad.invalid/a\u00a0tail','https://long.invalid/'+'x'*65536):
            with self.subTest(token=token[:70]):
                _, _, targets, evidence, source = self.analyze('<img srcset="'+token+',">')
                self.assertEqual(targets,[])
                self.assertEqual([item['source_url'] for item in evidence],[token])
                self.assertFalse(evidence[0]['network_target'])
                self.assertEqual(source['unmapped_evidence_count'],0)

    def test_scalar_attributes_visible_text_script_and_comments_keep_literal_commas(self):
        url = 'https://literal.invalid/a,'
        for markup in ('<a href="'+url+'">go</a>',url,
                       '<script>"'+url+'"</script>','<!-- '+url+' -->'):
            with self.subTest(markup=markup):
                _, _, targets, _, _ = self.analyze(markup)
                self.assertEqual(targets,[url])

    def test_entity_decoded_markup_delimiters_remain_whole_nontarget_evidence(self):
        for name in ('srcset','imagesrcset'):
            for char in ('"','<','>'):
                for suffix in ('/a'+char+'tail','/?x=a'+char+'tail','/#a'+char+'tail'):
                    token = 'https://bad.invalid'+suffix
                    with self.subTest(name=name, token=token):
                        mime, candidates, targets, evidence, sources = self.analyze(
                            '<img '+name+'="'+escape(token,quote=True)+',">')
                        self.assertEqual(mime['urls'],[token])
                        self.assertEqual(candidates,[token])
                        self.assertEqual(targets,[])
                        self.assertEqual([item['source_url'] for item in evidence],[token])
                        self.assertEqual(evidence[0]['status'],'invalid')
                        self.assertFalse(evidence[0]['network_target'])
                        self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_entity_delimiters_in_recovered_whole_tokens_are_not_targets(self):
        invalid = 'https://bad.invalid/a"tail'
        tokens = ['hxxps://bad[.]invalid/a"tail',base64.b64encode(invalid.encode()).decode()]
        for name in ('srcset','imagesrcset'):
            with self.subTest(name=name):
                _, _, targets, evidence, sources = self.analyze(
                    '<img '+name+'="'+escape(', '.join(tokens),quote=True)+'">')
                self.assertEqual(targets,[])
                self.assertEqual([item['source_url'] for item in evidence],tokens)
                self.assertTrue(all(item['status']=='invalid' and not item['network_target'] for item in evidence))
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_legal_apostrophes_and_percent_encoded_delimiters_keep_target_identity(self):
        tokens = ["https://good.invalid/a'tail?x=b'c#d'e",'https://good.invalid/a%22b%3Cc%3Ed%27e']
        for name in ('srcset','imagesrcset'):
            with self.subTest(name=name):
                _, _, targets, evidence, sources = self.analyze(
                    '<img '+name+'="'+escape(', '.join(tokens),quote=True)+'">')
                self.assertEqual(targets,tokens)
                self.assertTrue(all(item['network_target'] for item in evidence))
                self.assertEqual(sources['unmapped_evidence_count'],0)

    def test_source_links_share_list_grammar_and_exact_retention_accounting(self):
        _, _, targets, evidence, source = self.analyze(
            '<img srcset="https://one.invalid/a, https://two.invalid/b 2x, https://three.invalid/c 3x">',
            parts=5,max_links=4)
        self.assertEqual(len(targets),3)
        self.assertEqual(len(evidence),3)
        self.assertEqual(source['total_link_count'],15)
        self.assertEqual(source['inventoried_link_count'],4)
        self.assertEqual(source['omitted_link_count'],11)
        self.assertEqual(source['unmapped_evidence_count'],0)
        self.assertEqual(source['status'],'limited')
        for item in source['sources']:
            if item['kind']=='mime_body':
                self.assertEqual(item['derivation']['method'],'paw_html_url_candidate_views_v3')

    def test_ascii_whitespace_multiple_separators_and_malformed_descriptors_stay_bounded(self):
        for whitespace in (' ','\t','\r\n','\f'):
            with self.subTest(whitespace=whitespace):
                _, _, targets, _, _ = self.analyze('<img srcset=" ,,, https://one.invalid/a,,,'
                    +whitespace+'https://two.invalid/b ignored(unclosed, https://descriptor.invalid/) ">')
                self.assertEqual(targets,['https://one.invalid/a','https://two.invalid/b'])


if __name__ == '__main__':
    unittest.main()
