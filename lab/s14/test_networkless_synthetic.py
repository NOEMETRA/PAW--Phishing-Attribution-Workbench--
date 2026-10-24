"""HTTP200 metadata authorizes only a fixed benign offline fixture, not body acceptance."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import networkless_synthetic as fixture
from networkless_synthetic import CONTROLLED_PRODUCER_SOURCES, header_authority, verify_prior_sources


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

    def test_frozen_producer_export_is_complete_and_matches_current_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'sources').mkdir(); content = b'inert producer snapshot'
            manifest = {n: hashlib.sha256(content).hexdigest() for n in CONTROLLED_PRODUCER_SOURCES}
            current = root / 'current'; current.mkdir()
            for name in manifest:
                (root / 'sources' / name).write_bytes(content); (current / name).write_bytes(content)
            with mock.patch.object(fixture, 'HERE', current):
                verify_prior_sources(root, manifest)
                (current / 'controlled_uplink.py').write_bytes(b'changed current producer')
                with self.assertRaisesRegex(ValueError, 'current_producer_source_changed'): verify_prior_sources(root, manifest)

    def test_missing_or_unlisted_prior_sources_refuse_before_vm_initialization(self):
        from gw_validation import Matrix
        for mutation in ['empty', 'missing_producer', 'unlisted']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root / 'sources').mkdir(); content = b'inert'
                manifest = {n: hashlib.sha256(content).hexdigest() for n in CONTROLLED_PRODUCER_SOURCES}
                for name in manifest: (root / 'sources' / name).write_bytes(content)
                if mutation == 'empty': manifest = {}
                elif mutation == 'missing_producer': del manifest['controlled_uplink.py']; (root / 'sources/controlled_uplink.py').unlink()
                else: (root / 'sources/unlisted.py').write_bytes(content)
                report = dict(fetch=observed(), result='FAIL', host_before={}, host_after={}, source_hashes=manifest)
                report.update({k: True for k in ['writers_stopped', 'host_network_restored', 'source_freeze_unchanged', 'base_unchanged']})
                (root / 'results.json').write_text(json.dumps(report))
                class Prior:
                    def stat(self): return SimpleNamespace(st_uid=0, st_mode=0o700)
                    def __truediv__(self, name): return root / name
                args = SimpleNamespace(owner=None, prior=Prior())
                original = Path.read_text
                def read(path, *a, **kw): return 'unconfined' if str(path) == '/proc/self/attr/current' else original(path, *a, **kw)
                with mock.patch.object(fixture.os, 'geteuid', return_value=0), mock.patch.object(Path, 'read_text', read), \
                     mock.patch.object(Matrix, '__init__') as initialize:
                    with self.assertRaisesRegex(ValueError, 'source_inventory'): fixture.host(args)
                    initialize.assert_not_called()

    def test_arbitrary_failure_or_success_cannot_impersonate_budget_refusal(self):
        for key, value in [('reason', 'timeout'), ('status', 'completed')]:
            fetch = observed(); fetch[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): header_authority(fetch)


if __name__ == '__main__': unittest.main()
