"""Real header parsing, offline alignment and authenticated signature verification."""
import base64
import unittest
from paw.core.parser_mail import parse_eml_bytes
from paw.core.authentication import (infer_alignment, domain_alignment, parse_dmarc_record,
    parse_authentication_results, parse_arc_chain, fetch_dmarc_policy)
from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case, finalize_score
from paw.core.received import normalize_received
from paw.core.header_forgery import analyze_received_anomalies
from paw.core.dkim_offline import verify_dkim_offline


def email_with(*headers):
    return parse_eml_bytes(('From: sender@example.com\r\n' + '\r\n'.join(headers) + '\r\n\r\nBody').encode())


class AuthenticationContracts(unittest.TestCase):
    def test_typical_dkim_properties_belong_to_their_own_clause(self):
        headers = email_with('Authentication-Results: mx.example; dkim=pass header.d=example.com; spf=fail smtp.mailfrom=other.net; dmarc=pass header.from=example.com')
        self.assertEqual(headers['auth_results']['dkim'], [{'result':'pass','d':'example.com'}])
        self.assertEqual(headers['authentication_results'][0]['authserv_id'], 'mx.example')

    def test_comments_and_quoted_semicolon_do_not_forge_results(self):
        record = parse_authentication_results('mx.example (dkim=pass; forged); spf=fail reason="text; dkim=pass" smtp.mailfrom=example.com')
        self.assertEqual([method['method'] for method in record['methods']], ['spf'])
        self.assertEqual(record['methods'][0]['result'], 'fail')

    def test_malformed_claim_is_not_a_failure_or_success(self):
        record = parse_authentication_results('mx.example; dkim=pass (unterminated')
        self.assertEqual(record['status'], 'invalid')

    def test_quoted_reason_cannot_supply_authentication_identity(self):
        record = parse_authentication_results('mx.example; spf=pass reason="smtp.mailfrom=example.com"')
        self.assertEqual(record['methods'][0]['properties'], {})

    def test_multiple_receivers_never_merge_spf_and_dkim(self):
        headers = email_with('Authentication-Results: one.example; spf=pass smtp.mailfrom=example.com',
            'Authentication-Results: two.example; dkim=pass header.d=example.com')
        with offline_policy(): auth = infer_alignment(headers, headers['from'], '')
        self.assertIsNone(auth['spf']['result'])
        self.assertEqual(len(auth['reported_records']), 2)
        self.assertFalse(auth['trusted'])

    def test_dmarc_passes_reported_alignment_with_either_method(self):
        policy = parse_dmarc_record('v=DMARC1; p=reject; adkim=s; aspf=s')
        for claim in ('dkim=pass header.d=example.com; spf=fail smtp.mailfrom=other.net',
                      'dkim=fail header.d=other.net; spf=pass smtp.mailfrom=example.com'):
            headers = email_with('Authentication-Results: mx.example; ' + claim)
            auth = infer_alignment(headers, headers['from'], '', policy)
            self.assertTrue(auth['dmarc']['reported_alignment'])
            self.assertIsNone(auth['dmarc']['aligned'])
            self.assertIsNone(auth['dmarc']['verification']['result'])

    def test_failed_aligned_signature_cannot_establish_pass(self):
        headers = email_with('Authentication-Results: mx.example; dkim=fail header.d=example.com; spf=fail smtp.mailfrom=example.com')
        auth = infer_alignment(headers, headers['from'], '', parse_dmarc_record('v=DMARC1; p=reject'))
        self.assertFalse(auth['dmarc']['reported_alignment'])

    def test_return_path_cannot_replace_authenticated_spf_identity(self):
        headers = email_with('Authentication-Results: mx.example; spf=pass')
        auth = infer_alignment(headers, headers['from'], '<sender@example.com>', parse_dmarc_record('v=DMARC1; p=reject'))
        self.assertIsNone(auth['spf']['aligned'])
        self.assertIsNone(auth['dmarc']['reported_alignment'])

    def test_relaxed_alignment_uses_organizational_domain_offline(self):
        before = len(violations())
        with offline_policy():
            self.assertTrue(domain_alignment('mail.example.co.uk', 'news.example.co.uk'))
            self.assertFalse(domain_alignment('evil-example.co.uk', 'example.co.uk'))
            self.assertFalse(domain_alignment('example.co.uk.attacker.com', 'example.co.uk'))
            self.assertFalse(domain_alignment('mail.example.com', 'example.com', 's'))
        self.assertEqual(len(violations()), before)

    def test_missing_or_duplicate_from_is_not_aligned(self):
        headers = email_with('From: second@example.com', 'Authentication-Results: mx.example; dkim=pass header.d=example.com')
        auth = infer_alignment(headers, headers['from'], '', parse_dmarc_record('v=DMARC1; p=none'))
        self.assertIsNone(auth['from_domain'])
        self.assertIsNone(auth['dmarc']['reported_alignment'])

    def test_dmarc_skipped_is_not_policy_none(self):
        with offline_policy(): policy = fetch_dmarc_policy('example.com')
        self.assertEqual(policy['status'], 'skipped')
        self.assertIsNone(policy['policy'])

    def test_dmarc_invalid_tags_are_not_a_valid_policy(self):
        for text in ('v=DMARC1; p=reject; p=none', 'v=DMARC1; adkim=s', 'v=DMARC1; p=none; aspf=x'):
            self.assertEqual(parse_dmarc_record(text)['status'], 'invalid')

    def test_received_spf_softfail_is_not_truncated_to_fail(self):
        headers = email_with('Received-SPF: softfail (receiver: fail mentioned in comment); client-ip=192.0.2.1')
        self.assertEqual(headers['received_spf'][0]['result'], 'softfail')

    def test_arc_uses_i_instance_and_never_verifies_cv_claim(self):
        headers = {'arc': {'seals':['i=1; cv=none;', 'i=2; cv=pass;'],
            'message_signatures':['i=1; a=rsa-sha256;', 'i=2; a=rsa-sha256;'],
            'auth_results':['i=1; mx1; spf=fail', 'i=2; mx2; spf=pass']}}
        arc = parse_arc_chain(headers)
        self.assertEqual(arc['structure_status'], 'parsed')
        self.assertEqual(arc['last_auth_result'], headers['arc']['auth_results'][1])
        self.assertEqual(arc['verification']['status'], 'not_evaluated')

    def test_arc_missing_or_duplicate_sets_are_invalid_structure(self):
        for seals in (['i=2; cv=pass;'], ['i=1; cv=none;', 'i=1; cv=none;']):
            self.assertEqual(parse_arc_chain({'arc':{'seals':seals}})['structure_status'], 'invalid')

    def test_untrusted_pass_fail_and_missing_have_identical_auth_score(self):
        scores = []
        for claim in ('', 'Authentication-Results: mx.example; spf=pass; dkim=pass header.d=example.com',
                      'Authentication-Results: mx.example; spf=fail; dkim=fail header.d=example.com; dmarc=fail'):
            headers = email_with(claim)
            with offline_policy(): auth = infer_alignment(headers, headers['from'], '')
            result = score_case({}, auth, {'domain':'example.com'})
            scores.append(result['score'])
            self.assertEqual(result['assessment_status'], 'partial')
        self.assertEqual(len(set(scores)), 1)

    def test_unknown_hop_diagnostics_do_not_count_as_mismatches(self):
        self.assertEqual(score_case({}, {}, {}), score_case({'fqdn_ok':None, 'helo_ptr_match':None}, {}, {}))

    def test_score_and_verdict_recomputed_after_extra_signals(self):
        result = finalize_score({'score':0.65, 'decision':'Inconclusive'}, 'strict', .1)
        self.assertEqual(result['decision'], 'Likely malicious infrastructure')
        self.assertEqual(finalize_score(result, additional=1)['score'], 1)

    def test_received_order_is_preserved_despite_claimed_dates(self):
        lines = ['from late.example (192.0.2.2) by mx.example; Wed, 8 Oct 2025 09:00:00 +0000',
                 'from early.example (192.0.2.1) by late.example; Wed, 8 Oct 2025 10:00:00 +0000']
        with offline_policy(): received = normalize_received(lines)
        self.assertEqual([hop['raw'] for hop in received['ordered_hops']], list(reversed(lines)))
        self.assertTrue(analyze_received_anomalies(received['ordered_hops'])['non_monotonic_dates'])

    def test_naive_received_date_is_not_assumed_to_be_utc(self):
        with offline_policy(): received = normalize_received(['from mail.example by mx.example; Wed, 8 Oct 2025 10:00:00'])
        self.assertIsNone(received['ordered_hops'][0]['date'])

    def test_absent_received_has_no_fabricated_negative_result(self):
        self.assertEqual(analyze_received_anomalies([])['status'], 'not_evaluated')


class RealDkimContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import dkim
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.records = {'test._domainkey.example.com': b'v=DKIM1; k=rsa; p=' + base64.b64encode(public)}
        raw = b'From: sender@example.com\r\nTo: recipient@example.net\r\nSubject: Real signature verification\r\n\r\nOriginal body\r\n'
        cls.signed = dkim.sign(raw, b'test', b'example.com', private, include_headers=[b'from', b'to', b'subject']) + raw

    def test_real_signature_verifies_with_local_key_under_no_egress(self):
        before = len(violations())
        with offline_policy(): result = verify_dkim_offline(self.signed, self.records)
        self.assertEqual(result['result'], 'pass')
        self.assertEqual(len(violations()), before)

    def test_real_body_tampering_fails_signature(self):
        with offline_policy(): result = verify_dkim_offline(self.signed.replace(b'Original body', b'Tampered body'), self.records)
        self.assertEqual(result['result'], 'fail')

    def test_missing_local_key_is_not_signature_failure(self):
        with offline_policy(): result = verify_dkim_offline(self.signed, {'other.example': b'v=DKIM1; p='})
        self.assertEqual(result['status'], 'not_evaluated')
        self.assertIsNone(result['result'])

    def test_tampered_body_with_missing_key_is_still_not_evaluated(self):
        with offline_policy():
            result = verify_dkim_offline(self.signed.replace(b'Original body', b'Tampered body'),
                {'other._domainkey.example.com': b'v=DKIM1; p='})
        self.assertEqual(result['status'], 'not_evaluated')
        self.assertIsNone(result['result'])

    def test_malformed_local_public_key_is_not_a_signature_failure(self):
        with offline_policy():
            result = verify_dkim_offline(self.signed, {'test._domainkey.example.com':b'v=DKIM1; p=invalid'})
        self.assertEqual(result['status'], 'not_evaluated')
        self.assertIsNone(result['result'])
        self.assertEqual(result['signatures'][0]['status'], 'error')

    def test_signature_failure_with_unverified_local_key_does_not_add_risk(self):
        with offline_policy():
            passed = verify_dkim_offline(self.signed, self.records)
            failed = verify_dkim_offline(self.signed.replace(b'Original body', b'Tampered body'), self.records)
        good = score_case({}, {'dkim':{'verification':passed}}, {'domain':'example.com'})
        bad = score_case({}, {'dkim':{'verification':failed}}, {'domain':'example.com'})
        self.assertEqual(bad['score'], good['score'])
        self.assertEqual(failed['key_provenance_status'], 'unverified')
        self.assertIn('dkim_key_provenance', bad['coverage']['not_evaluated'])
        self.assertEqual(bad['assessment_status'], 'partial')
        self.assertNotIn('dkim', bad['coverage']['not_evaluated'])


if __name__ == '__main__': unittest.main()
