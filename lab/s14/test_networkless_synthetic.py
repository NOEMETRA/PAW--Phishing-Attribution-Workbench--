"""HTTP200 metadata authorizes only a fixed benign offline fixture, not body acceptance."""
import copy
import unittest
from networkless_synthetic import header_authority


def observed():
    return {'status': 'refused', 'reason': 'response_budget', 'observation': {
        'http_status': 200, 'tls_verified': True, 'tls_hostname': 'www.squishylab.fun',
        'requests': 1, 'redirects': 0, 'body_bytes_read': 8193,
        'certificate_sha256': 'a' * 64, 'elapsed_seconds': .5}}


class HeaderAuthority(unittest.TestCase):
    def test_refused_body_stays_refused_under_benign_only_authority(self):
        fetch = observed(); before = copy.deepcopy(fetch)
        value = header_authority(fetch)
        self.assertFalse(value['body_accepted'])
        self.assertEqual(value['application_fetch_result'], 'FAIL_RESPONSE_BUDGET')
        self.assertIn('fixed benign', value['authority_scope'])
        self.assertEqual(fetch, before)

    def test_redirect_or_unverified_wrong_scope_or_budget_never_authorizes(self):
        for key, value in [('http_status', 308), ('tls_verified', False), ('tls_hostname', 'other.invalid'),
                           ('requests', 2), ('redirects', 1), ('body_bytes_read', 8194),
                           ('certificate_sha256', 'not-a-certificate'), ('elapsed_seconds', 6)]:
            fetch = observed(); fetch['observation'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): header_authority(fetch)

    def test_arbitrary_failure_or_success_cannot_impersonate_budget_refusal(self):
        for key, value in [('reason', 'timeout'), ('status', 'completed')]:
            fetch = observed(); fetch[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): header_authority(fetch)


if __name__ == '__main__': unittest.main()
