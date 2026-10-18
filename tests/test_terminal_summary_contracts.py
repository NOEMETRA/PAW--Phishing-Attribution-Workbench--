"""Actual Rich rendering of presentation fixtures; not analyzed-email verdicts."""
import copy
from contextlib import redirect_stdout
import io
from pathlib import Path
import re
import tempfile
import unittest

from paw.core.authentication import authentication_report, infer_alignment, parse_authentication_results
from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case

with offline_policy():
    from paw.core.trace import print_beautiful_summary


def plain(text):
    return ' '.join(re.sub(r'[\u2500-\u257f]', ' ', text).split())


class TerminalSummaryContracts(unittest.TestCase):
    def render(self, ip='', organization='Fixture organization', reported=True):
        headers={'from':'sender@example.com','from_header_count':1,
                 'authentication_results':[parse_authentication_results(
                     'fixture.example; dmarc=none header.from=example.com')] if reported else []}
        with tempfile.TemporaryDirectory(prefix='paw-summary-presentation-') as temporary, offline_policy():
            case=Path(temporary)/'case-presentation-fixture'
            case.mkdir()
            notes=case/'notes.txt'
            notes.write_bytes(b'Preserve presentation fixture notes')
            auth=infer_alignment(headers,headers['from'],'')
            score=score_case({},auth,{'domain':'example.com'},headers=headers)
            provider={'asn':64500,'asn_org':organization,'cc':'ZZ'}
            before=copy.deepcopy((auth,score,provider))
            count=len(violations())
            output=io.StringIO()
            with redirect_stdout(output):
                print_beautiful_summary(str(case),case.name,score,ip,provider,'example.com',{},auth)
            self.assertEqual((auth,score,provider),before)
            self.assertEqual(notes.read_bytes(),b'Preserve presentation fixture notes')
            self.assertEqual(set(p.name for p in case.iterdir()),{'notes.txt'})
            self.assertEqual(len(violations()),count)
        return plain(output.getvalue()),auth

    def test_reported_none_is_not_a_dns_policy_or_independent_auth_result(self):
        output,auth=self.render()
        self.assertEqual(auth['dmarc']['reported_result'],'none')
        self.assertEqual(auth['dmarc']['policy']['status'],'skipped')
        self.assertIsNone(auth['dmarc']['policy']['policy'])
        self.assertIn(' '.join(authentication_report(auth).split()),output)
        self.assertIn('DMARC reported: none; independent verification: not_evaluated',output)
        self.assertIn('DMARC policy lookup: skipped',output)
        self.assertNotIn('DMARC policy: none',output)
        self.assertNotIn('Auth checks not independently verified',output)

    def test_candidate_and_missing_candidate_have_explicit_source_limits(self):
        for ip,title in (('192.0.2.9','Transmitting candidate (unverified)'),
                         ('','Transmitting candidate unavailable')):
            with self.subTest(ip=ip):
                output,auth=self.render(ip=ip,reported=False)
                self.assertIn(title,output)
                self.assertIn('Received observations are unverified',output)
                self.assertIn('no sender or attacker attribution',output)
                self.assertNotIn('📍 Origin',output)
                self.assertIn(' '.join(authentication_report(auth).split()),output)

    def test_provider_text_is_literal_and_cannot_break_rich_markup(self):
        output,_=self.render(ip='192.0.2.9',organization='Fixture [/bold] [red]organization')
        self.assertIn('Fixture [/bold] [red]organization',output)


if __name__=='__main__':
    unittest.main()
