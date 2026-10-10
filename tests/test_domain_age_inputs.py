"""Real scorer and SQLite contracts for supplied ages; no registry simulation."""
from contextlib import closing
import os
from pathlib import Path
import tempfile
import unittest

from paw.core import index
from paw.core.scoring import score_case


class DomainAgeInputContracts(unittest.TestCase):
    def score(self, value):
        return score_case({}, {}, {'domain':'example.com','nrd_days':value},
                          headers={'from':'a@example.com'})['score_components']['sender_domain_heuristics']

    def test_negative_and_boolean_inputs_do_not_add_age_points(self):
        for value in (-1,-.1,True,False):
            with self.subTest(value=value): self.assertEqual(self.score(value),0)

    def test_strings_and_containers_are_unavailable_without_crashing(self):
        for value in ('0','7','',[],{}):
            with self.subTest(value=value): self.assertEqual(self.score(value),0)

    def test_nonfinite_and_fractional_inputs_are_unavailable(self):
        for value in (float('nan'),float('inf'),float('-inf'),.5,6.9,29.5):
            with self.subTest(value=value): self.assertEqual(self.score(value),0)

    def test_valid_whole_days_preserve_boundaries(self):
        for value,weight in ((0,.35),(6,.35),(7,.15),(29,.15),(30,0),(365,0),(0.0,.35),(7.0,.15)):
            with self.subTest(value=value): self.assertAlmostEqual(self.score(value),weight)

    def test_missing_age_adds_no_points(self):
        self.assertEqual(self.score(None),0)
        score=score_case({}, {}, {'domain':'example.com'},headers={'from':'a@example.com'})
        self.assertEqual(score['score_components']['sender_domain_heuristics'],0)

    def test_real_index_preserves_unknown_and_invalid_as_sql_null(self):
        original_cwd,original_db=Path.cwd(),index._db
        index._db=None
        values=[{}, {'nrd_days':None}]+[{'nrd_days':v} for v in (
            -1,-.1,True,False,'0','',[],{},float('nan'),float('inf'),float('-inf'),.5,2**63,10**100)]
        try:
            with tempfile.TemporaryDirectory(prefix='paw-age-input-') as temporary:
                try:
                    os.chdir(temporary)
                    for number,dominfo in enumerate(values):
                        supplied={'domain':'example.com',**dominfo}; original=dict(supplied)
                        index.upsert_case('case-'+str(number),{}, {},supplied,{'score':0})
                        self.assertEqual(supplied,original)
                    with closing(index.db().execute('SELECT nrd_days, typeof(nrd_days) FROM cases')) as cursor:
                        rows=cursor.fetchall()
                    self.assertEqual(rows,[(None,'null')]*len(values))
                finally:
                    if index._db is not None: index._db.close()
                    index._db=None
                    os.chdir(original_cwd)
        finally:
            index._db=original_db

    def test_real_index_accepts_whole_days_and_storage_boundary(self):
        original_cwd,original_db=Path.cwd(),index._db
        index._db=None
        values=(0,6,7,29,30,365,7.0,2**63-1)
        try:
            with tempfile.TemporaryDirectory(prefix='paw-age-input-') as temporary:
                try:
                    os.chdir(temporary)
                    for number,value in enumerate(values):
                        index.upsert_case('case-'+str(number),{}, {},{'nrd_days':value},{'score':0})
                    with closing(index.db().execute('SELECT nrd_days, typeof(nrd_days) FROM cases ORDER BY rowid')) as cursor:
                        rows=cursor.fetchall()
                    self.assertEqual(rows,[(int(value),'integer') for value in values])
                finally:
                    if index._db is not None: index._db.close()
                    index._db=None
                    os.chdir(original_cwd)
        finally:
            index._db=original_db


if __name__=='__main__': unittest.main()
