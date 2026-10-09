"""Real local timestamp calculations; no mocked registry responses or labels."""
from datetime import datetime, timedelta, timezone
import unittest
from paw.core.network_policy import offline_policy, violations
from paw.core.profiler import nrd_days
from paw.core.scoring import score_case


class DomainAgeContracts(unittest.TestCase):
    reference=datetime(2026,10,10,tzinfo=timezone.utc)

    def observe(self,created,reference_time=None):
        from paw.core.profiler import observe_domain_age
        return observe_domain_age(created,reference_time=self.reference if reference_time is None else reference_time)

    def score_age(self,age):
        return score_case({}, {}, {'domain':'example.com','nrd_days':age},headers={'from':'a@example.com'})['score_components']['sender_domain_heuristics']

    def test_far_future_timestamp_does_not_become_new_domain(self):
        age=nrd_days('2099-01-01T00:00:00Z')
        self.assertIsNone(age)
        self.assertEqual(self.score_age(age),0)

    def test_subsecond_future_timestamp_is_invalid_not_zero(self):
        record=self.observe('2026-10-10T00:00:00.000001Z')
        self.assertEqual(record['status'],'invalid')
        self.assertEqual(record['reason_code'],'future_timestamp')
        self.assertIsNone(record['age_days'])
        self.assertEqual(self.score_age(record['age_days']),0)

    def test_same_instant_with_timezone_offset_has_age_zero(self):
        record=self.observe('2026-10-10T02:00:00+02:00')
        self.assertEqual(record['age_days'],0)
        self.assertEqual(record['created_utc'],'2026-10-10T00:00:00+00:00')
        self.assertEqual(record['status'],'observed_unverified')

    def test_valid_age_and_existing_threshold_weights_are_preserved(self):
        for days,weight in ((0,.35),(6,.35),(7,.15),(29,.15),(30,0),(365,0)):
            with self.subTest(days=days):
                created=(self.reference-timedelta(days=days)).isoformat()
                record=self.observe(created)
                self.assertEqual(record['age_days'],days)
                self.assertAlmostEqual(self.score_age(record['age_days']),weight)
                self.assertEqual(nrd_days(created,reference_time=self.reference),days)

    def test_fractional_past_day_is_floored_after_future_check(self):
        record=self.observe('2026-10-09T00:00:00.000001Z')
        self.assertEqual(record['age_days'],0)

    def test_missing_timestamp_is_unavailable(self):
        for created in (None,''):
            record=self.observe(created)
            self.assertEqual(record['status'],'unavailable')
            self.assertEqual(record['reason_code'],'timestamp_unavailable')
            self.assertIsNone(record['age_days'])
            self.assertEqual(self.score_age(record['age_days']),0)

    def test_naive_timestamp_does_not_guess_timezone(self):
        for created in ('2026-10-09','2026-10-09T00:00:00'):
            record=self.observe(created)
            self.assertEqual(record['status'],'invalid')
            self.assertEqual(record['reason_code'],'timezone_missing')
            self.assertIsNone(record['age_days'])

    def test_malformed_or_nonstring_timestamp_is_invalid(self):
        for created in ('bad','2026-02-30T00:00:00Z','2026-10-09T00:00:00+25:00',True,0,[],{}):
            record=self.observe(created)
            self.assertEqual(record['status'],'invalid')
            self.assertEqual(record['reason_code'],'invalid_timestamp')
            self.assertIsNone(record['age_days'])

    def test_invalid_or_naive_reference_is_not_replaced_with_current_time(self):
        for reference in ('bad','2026-10-10',self.reference.replace(tzinfo=None),True):
            record=self.observe('2026-10-09T00:00:00Z',reference_time=reference)
            self.assertEqual(record['status'],'invalid')
            self.assertEqual(record['reason_code'],'invalid_reference_time')
            self.assertIsNone(record['reference_time'])
            self.assertIsNone(record['age_days'])

    def test_stored_reference_reproduces_observation(self):
        first=self.observe('2026-10-01T00:00:00Z')
        second=self.observe('2026-10-01T00:00:00Z',reference_time=first['reference_time'])
        self.assertEqual(first,second)
        self.assertFalse(first['verified'])
        self.assertEqual(first['source'],'supplied_registration_timestamp')

    def test_no_egress_and_legacy_missing_input(self):
        before=len(violations())
        with offline_policy(True):
            record=self.observe('2099-01-01T00:00:00Z')
            self.assertIsNone(nrd_days(None))
        self.assertIsNone(record['age_days'])
        self.assertEqual(len(violations()),before)


if __name__=='__main__': unittest.main()
