"""Algorithm vectors and real SQLite compatibility, not classifier calibration."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from paw.core import index
from paw.core.network_policy import offline_policy, violations


class SimHashContracts(unittest.TestCase):
    def test_single_feature_matches_sha256_bits_and_not_md5(self):
        self.assertEqual(index.simhash('alpha'), '8ed3f6ad685b959e')
        self.assertNotEqual(index.simhash('alpha'), hashlib.md5(b'alpha').hexdigest()[:16])

    def test_equal_weights_use_bitwise_intersection_for_zero_ties(self):
        # Two independent known SHA-256 token vectors; zero votes clear bits.
        expected = int('8ed3f6ad685b959e',16) & int('f44e64e75f3948e9',16)
        self.assertEqual(index.simhash('alpha beta'), f'{expected:016x}')

    def test_frequency_changes_votes(self):
        self.assertEqual(index.simhash('alpha alpha beta'), '8ed3f6ad685b959e')
        self.assertEqual(index.simhash('alpha beta beta'), 'f44e64e75f3948e9')

    def test_word_bag_reordering_whitespace_and_case_do_not_avalanche(self):
        a = 'alpha beta gamma delta epsilon zeta eta theta'
        b = 'THETA\teta zeta epsilon DELTA gamma beta alpha!!!'
        self.assertEqual(index.simhash(a), '4e9f24054bbbc890')
        self.assertEqual(index.simhash(a), index.simhash(b))

    def test_unicode_casefold_and_words(self):
        self.assertEqual(index.simhash('Straße ΑΒΓ'), index.simhash('STRASSE αβγ'))
        self.assertEqual(index.simhash('你好'), hashlib.sha256('你好'.encode()).hexdigest()[:16])
        self.assertNotEqual(index.simhash('e\u0301'), index.simhash('é'))

    def test_no_features_is_unavailable_and_limits_are_explicit(self):
        for text in ('', ' \r\n\t', '!<>@---'):
            self.assertIsNone(index.simhash(text))
        self.assertEqual(index.simhash('a' * index.SIMHASH_MAX_CHARS),
                         hashlib.sha256(('a'*index.SIMHASH_MAX_CHARS).encode()).hexdigest()[:16])
        with self.assertRaises(ValueError): index.simhash('a'*(index.SIMHASH_MAX_CHARS+1))
        for value in (None, b'alpha', [], 1):
            with self.assertRaises(TypeError): index.simhash(value)

    def test_no_egress_has_no_network_attempts(self):
        before = len(violations())
        with offline_policy(True):
            self.assertEqual(index.simhash('alpha'), '8ed3f6ad685b959e')
        self.assertEqual(len(violations()), before)

    def test_query_annotation_does_not_modify_legacy_or_unknown_versions(self):
        legacy = {'id':'old', 'simhash':'0123456789abcdef'}
        self.assertEqual(index.describe_fingerprint(legacy)['simhash_method'], 'legacy_md5_prefix_64')
        self.assertEqual(legacy, {'id':'old', 'simhash':'0123456789abcdef'})
        unknown = {**legacy, 'simhash_method':'future-method', 'simhash_status':'future-status'}
        self.assertEqual(index.describe_fingerprint(unknown)['simhash_method'], 'future-method')
        self.assertEqual(index.describe_fingerprint(unknown)['similarity_validation'], 'not_validated')

    def test_real_migration_preserves_old_rows_and_versions_new_values(self):
        previous_cwd, previous_db = Path.cwd(), index._db
        index._db = None
        try:
            with tempfile.TemporaryDirectory(prefix='paw-simhash-') as directory:
                try:
                    os.chdir(directory)
                    Path('cases').mkdir()
                    with closing(sqlite3.connect('cases/index.db')) as old:
                        old.execute('CREATE TABLE cases (id TEXT PRIMARY KEY, created_utc TEXT, origin_ip TEXT, asn INTEGER, org TEXT, cc TEXT, from_domain TEXT, nrd_days INTEGER, score REAL, simhash TEXT)')
                        old.execute('CREATE TABLE indicators (case_id TEXT, type TEXT, value TEXT, PRIMARY KEY(case_id,type,value))')
                        old.execute("INSERT INTO cases VALUES ('old',datetime('now'),'192.0.2.1',NULL,'','','example.com',NULL,0.2,'0123456789abcdef')")
                        old.execute("INSERT INTO indicators VALUES ('old','domain','example.com')")
                        old.commit()
                        before = old.execute('SELECT * FROM cases').fetchone()
                    index.upsert_case('case-new', {}, {'subject':'alpha alpha beta'},
                                      {'domain':'example.com'}, {'score':0.2})
                    index.upsert_case('case-empty', {}, {}, {'domain':'example.com'}, {'score':0})
                    index.upsert_case('case-large', {}, {'subject':'a'*(index.SIMHASH_MAX_CHARS+1)},
                                      {'domain':'example.com'}, {'score':0})
                    conn = index.db()
                    self.assertEqual(conn.execute('SELECT * FROM cases WHERE id="old"').fetchone(),
                                     before+(None,None))
                    index._init_db(conn)  # repeated additive migration is idempotent
                    rows = {row['id']:row for row in index.query_recent('domain','example.com')}
                    self.assertEqual(rows['old']['simhash'], before[-1])
                    self.assertEqual(rows['old']['simhash_status'], 'legacy_not_similarity_fingerprint')
                    self.assertEqual(rows['new']['simhash'], '8ed3f6ad685b959e')
                    self.assertEqual(rows['new']['simhash_method'], index.SIMHASH_METHOD)
                    self.assertEqual(rows['new']['simhash_scope'], index.SIMHASH_SCOPE)
                    self.assertIsNone(rows['empty']['simhash'])
                    self.assertEqual(rows['empty']['simhash_status'], 'not_evaluated_no_features')
                    self.assertIsNone(rows['large']['simhash'])
                    self.assertEqual(rows['large']['simhash_status'], 'unavailable_input_limit')
                finally:
                    if index._db is not None: index._db.close()
                    index._db = None
                    os.chdir(previous_cwd)
        finally:
            index._db = previous_db


if __name__ == '__main__': unittest.main()
