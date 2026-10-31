"""Selected-parent custody, no real email, Root, browser or remote lookup."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import blake3
from paw.core import mail_browser_custody as m
from paw.core import mail_browser_owned as owned
from paw.core.evidence import seal_case
from test_mail_browser_owned import owned_case
from test_synthetic_bridge import inventory


def content_hash(raw):
    return blake3.blake3(raw).hexdigest()


class Custody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = owned_case(self.root)
        self.before = inventory(self.case)

    def tearDown(self):
        self.temp.cleanup()

    def request(self):
        raw = m.prepare(self.case, 0, now=100)
        return m.validate(raw, content_hash, now=100), raw

    def test_whole_stopped_case_verified_and_no_authority_is_created(self):
        with patch('socket.socket', side_effect=AssertionError('socket forbidden')):
            value, raw = self.request()
        self.assertEqual(value['execution_authority'], 'none')
        self.assertEqual(value['state'], 'PREPARED_NOT_ACTIVE')
        self.assertEqual(base64.b64decode(value['source_b64']), owned.SOURCE)
        self.assertEqual(inventory(self.case), self.before)
        self.assertLess(len(raw), m.REQUEST_MAX)

    def test_stable_approval_selection_excludes_only_request_clock_and_nonce(self):
        value, _ = self.request()
        other = copy.deepcopy(value)
        other.update(request_id='a'*32, created_at=101, expires_at=1001)
        self.assertEqual(m.selection(value), m.selection(other))
        m.require_selection(other, m.selection(value))
        for key, changed in [('url', 'https://foreign.invalid/'), ('source_sha256', '0'*64),
                             ('url_index', 1), ('case_reference', {**value['case_reference'], 'case_id':'case-other'}),
                             ('snapshot_sha256', {}), ('limits', {**m.LIMITS, 'requests':33})]:
            bad = copy.deepcopy(other); bad[key] = changed
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'protected_authority'):
                m.require_selection(bad, m.selection(value))

    def test_valid_synthetic_foreign_source_can_be_prepared_but_owned_admission_stays_closed(self):
        source = b'From: fixture@other.invalid\r\nSubject: harmless unexecuted fixture\r\n\r\nSynthetic only.\r\n'
        (self.case/'input.eml').write_bytes(source)
        manifest = json.loads((self.case/'manifest.json').read_bytes())
        manifest['inputs'] = [{'path':'input.eml', 'size':len(source), 'blake3':content_hash(source)}]
        (self.case/'manifest.json').write_text(json.dumps(manifest))
        (self.case/'url_evidence.json').write_text('[{"url":"http://other.invalid/path/token","network_target":true}]')
        seal_case(self.case)
        raw = m.prepare(self.case, 0, now=100)
        value = m.validate(raw, content_hash, now=100)
        self.assertEqual(value['url'], 'http://other.invalid/path/token')
        with self.assertRaises(ValueError):
            owned.validate_request(raw, now=100)

    def test_self_consistent_sha256_cannot_substitute_the_blake3_index(self):
        value, _ = self.request()
        changed = b'From: altered@fixture.invalid\r\n\r\nSynthetic other bytes'
        value['source_b64'] = base64.b64encode(changed).decode()
        value['source_sha256'] = m.digest(changed)
        with self.assertRaisesRegex(ValueError, 'selected_piece_hash'):
            m.validate(m.canonical(value), content_hash, now=100)

    def test_changed_selected_url_with_recomputed_sha256_still_fails_blake3(self):
        value, _ = self.request()
        rows = [{'url':'https://foreign.invalid/', 'network_target':True}]
        raw = m.canonical(rows); value['url'] = rows[0]['url']
        value['pieces_b64']['url_evidence.json'] = base64.b64encode(raw).decode()
        value['snapshot_sha256']['url_evidence.json'] = m.digest(raw)
        with self.assertRaisesRegex(ValueError, 'selected_piece_hash'):
            m.validate(m.canonical(value), content_hash, now=100)

    def test_corrupt_root_or_wrong_hash_implementation_refuses(self):
        value, raw = self.request()
        value['case_reference']['merkle_root_blake3'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'index_root'):
            m.validate(m.canonical(value), content_hash, now=100)
        with self.assertRaises(ValueError):
            m.validate(raw, m.digest, now=100)
        with self.assertRaises(ValueError):
            m.validate(raw, None, now=100)

    def test_exact_shapes_budgets_and_clock(self):
        value, raw = self.request()
        mutations = [{'execution_authority':'approved'}, {'profile':'owned'}, {'source_sha256':'0'*64},
                     {'url_index':True}, {'created_at':True}, {'expires_at':1001},
                     {'limits':{**m.LIMITS, 'browser_seconds':True}}, {'request_id':'../outside'},
                     {'pieces_b64':{}}, {'extra':'authority'}]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.validate(m.canonical({**value, **change}), content_hash, now=100)
        for malformed in [raw+b'\n', b'{"a":1,"a":2}', b'x'*(m.REQUEST_MAX+1)]:
            with self.assertRaises(ValueError):
                m.validate(malformed, content_hash, now=100)
        for now in [99, 1000, 1001]:
            with self.assertRaisesRegex(ValueError, 'expired'):
                m.validate(raw, content_hash, now=now)

    def test_live_or_changed_parent_refuses_and_source_is_never_executed(self):
        owner = self.root/'jobs/analysis_ownedfixture/supervisor.json'
        owner.write_text('{"tree_stopped":false}')
        with self.assertRaises(RuntimeError):
            m.prepare(self.case, 0)
        owner.write_text('{"tree_stopped":true}')
        (self.case/'score.json').write_text('tampered')
        with self.assertRaises(ValueError):
            m.prepare(self.case, 0)


if __name__ == '__main__':
    unittest.main()
