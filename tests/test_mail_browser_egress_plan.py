"""Preparation only: no DNS, socket, browser, Root or real email fixture."""
import copy
import hashlib
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lab/s14'))
import uplink_policy as policy


def selection(url='https://owned.invalid/path?opaque=owned%2Ftoken'):
    return {'email_sha256': 'a'*64, 'case_manifest_sha256': 'b'*64,
            'url_evidence_sha256': 'c'*64, 'url_index': 2, 'url': url}


class MailBrowserPlan(unittest.TestCase):
    def test_actual_prepare_and_validate_never_resolve_or_open_socket(self):
        with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')), \
             patch.object(socket, 'socket', side_effect=AssertionError('socket')):
            plan = policy.prepare_mail_browser_plan([selection()])
            self.assertEqual(policy.validate_mail_browser_plan(plan), plan)
        self.assertEqual(plan['state'], 'PREPARED_NOT_ACTIVE')
        self.assertEqual(plan['network_authority'], 'none')

    def test_exact_case_url_and_query_bytes_stay_bound(self):
        source = selection(); plan = policy.prepare_mail_browser_plan([source])
        target = plan['targets'][0]
        self.assertEqual(target['url'], source['url'])
        self.assertEqual(target['endpoint']['url_sha256'], hashlib.sha256(source['url'].encode()).hexdigest())
        source['url'] = 'https://other.invalid/'
        self.assertNotEqual(target['url'], source['url'])

    def test_clear_http_is_explicit_not_silently_upgraded(self):
        row = policy.mail_browser_endpoint('http://owned.invalid/a')
        self.assertEqual((row['scheme'], row['port'], row['url']), ('http', 80, 'http://owned.invalid/a'))

    def test_no_userinfo_literals_alternate_ports_or_schemes(self):
        for url in ['file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@owned.invalid/',
                    'http://127.0.0.1/', 'http://2130706433/', 'http://0x7f.1/',
                    'http://0x7f.0x0.0x0.0x1/', 'http://[::1]/',
                    'https://owned.invalid:444/', 'http://owned.invalid:443/',
                    'https://owned.invalid%2fother.invalid/', 'https://owned.invalid/#x',
                    'https://OWNED.invalid/', 'https://owned.invalid/#']:
            with self.subTest(url=url), self.assertRaises(ValueError): policy.mail_browser_endpoint(url)

    def test_control_space_unicode_backslash_and_budget_refuse(self):
        for url in ['https://owned.invalid/\nX:x', 'https://owned.invalid/a b',
                    'https://owned.invalid/π', 'https://owned.invalid\\@other.invalid/',
                    'https://owned.invalid/'+'a'*2048, True, None]:
            with self.subTest(url=url), self.assertRaises(ValueError): policy.mail_browser_endpoint(url)

    def test_hash_index_and_extra_fields_refuse(self):
        for key, value in [('email_sha256', 'A'*64), ('case_manifest_sha256', ''),
                           ('url_evidence_sha256', 'z'*64), ('url_index', True),
                           ('url_index', -1), ('url_index', 4096), ('command', '/bin/sh')]:
            row = selection(); row[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): policy.prepare_mail_browser_plan([row])

    def test_finite_count_and_duplicate_parent_refuse(self):
        for rows in [[], {}, [selection()]*2, [selection()]*4]:
            with self.assertRaises(ValueError): policy.prepare_mail_browser_plan(rows)

    def test_every_claimed_authority_and_control_reduction_refuses(self):
        good = policy.prepare_mail_browser_plan([selection()])
        for key, value in [('state', 'ACTIVE'), ('execution_authority', 'granted'),
                           ('network_authority', 'granted'), ('approved', True)]:
            changed = copy.deepcopy(good); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): policy.validate_mail_browser_plan(changed)
        changed = copy.deepcopy(good); changed['required_controls']['root_protected_exact_hash_approval'] = False
        with self.assertRaises(ValueError): policy.validate_mail_browser_plan(changed)

    def test_budget_expansion_and_boolean_numeric_spelling_refuse(self):
        good = policy.prepare_mail_browser_plan([selection()])
        for key in good['limits']:
            changed = copy.deepcopy(good); changed['limits'][key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError): policy.validate_mail_browser_plan(changed)
        changed = copy.deepcopy(good); changed['limits']['requests'] = True
        with self.assertRaises(ValueError): policy.validate_mail_browser_plan(changed)

    def test_endpoint_or_parent_substitution_refuses(self):
        good = policy.prepare_mail_browser_plan([selection()])
        changed = copy.deepcopy(good); changed['targets'][0]['endpoint']['host'] = 'other.invalid'
        with self.assertRaises(ValueError): policy.validate_mail_browser_plan(changed)
        # Changing a parent and recomputing the plan is syntactically valid; it
        # is never proof that the new parent exists or has approved execution.
        other = selection(); other['email_sha256'] = 'd'*64
        plan = policy.prepare_mail_browser_plan([other])
        self.assertNotEqual(plan, good); self.assertEqual(plan['execution_authority'], 'none')

    def test_existing_one_get_endpoint_is_not_relaxed(self):
        for url in ['http://owned.invalid/', 'https://owned.invalid/path?token=x']:
            with self.assertRaises(ValueError): policy.endpoint(url)


if __name__ == '__main__': unittest.main()
