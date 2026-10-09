"""Claimed header timing must not invent delays, manipulation or malicious relays."""
import unittest
from paw.core.received import normalize_received
from paw.core.header_forgery import analyze_received_anomalies, received_score_components
from paw.core.network_policy import offline_policy, violations

REFERENCE = '2026-10-09T12:00:00+00:00'


def chain(dates, ips=None):
    ips = ips or ['8.8.8.8']*len(dates)
    lines = ['from sender.example ('+ip+') by mx.example'+('; '+date if date else '')
             for date,ip in zip(dates,ips)]
    with offline_policy(True):
        return normalize_received(list(reversed(lines)))['ordered_hops']


class ReceivedTimingContracts(unittest.TestCase):
    def test_first_hop_has_no_fabricated_zero_delta(self):
        hop, = chain(['Wed, 8 Oct 2025 10:00:00 +0000'])
        self.assertIsNone(hop['skew_s'])
        self.assertEqual(hop['timing_observation']['status'],'not_evaluated')

    def test_delta_does_not_bridge_a_missing_middle_timestamp(self):
        hops = chain(['Wed, 8 Oct 2025 10:00:00 +0000',None,'Wed, 8 Oct 2025 12:00:00 +0000'])
        self.assertEqual([h['skew_s'] for h in hops],[None,None,None])
        self.assertEqual([h['header_index'] for h in hops],[2,1,0])

    def test_timezone_offsets_compare_instants_without_reordering(self):
        hops = chain(['Wed, 8 Oct 2025 08:00:00 +0000','Wed, 8 Oct 2025 10:00:00 +0200'])
        self.assertEqual(hops[1]['skew_s'],0)
        self.assertEqual(hops[1]['timing_observation']['result'],'equal')
        self.assertFalse(hops[1]['timing_observation']['verified'])

    def test_naive_and_invalid_dates_leave_comparison_unavailable(self):
        for date in ('Wed, 8 Oct 2025 10:00:00','Wed, 8 Oct 2025 10:00:00 -0000','not a date',None):
            with self.subTest(date=date):
                hops = chain(['Wed, 8 Oct 2025 08:00:00 +0000',date])
                self.assertIsNone(hops[1]['skew_s'])
                self.assertEqual(hops[1]['timing_observation']['status'],'not_evaluated')

    def test_unknown_gap_cannot_establish_non_monotonic_chain(self):
        hops = chain(['Wed, 8 Oct 2025 10:00:00 +0000',None,'Wed, 8 Oct 2025 09:00:00 +0000'])
        result = analyze_received_anomalies(hops)
        self.assertIsNone(result['non_monotonic_dates'])
        self.assertEqual(result['timing_observations']['comparison_status'],'not_evaluated')

    def test_backward_claim_is_visible_without_numeric_risk(self):
        hops = chain(['Wed, 8 Oct 2025 10:00:00 +0000','Wed, 8 Oct 2025 09:00:00 +0000'])
        result = analyze_received_anomalies(hops)
        self.assertTrue(result['non_monotonic_dates'])
        self.assertEqual(hops[1]['skew_s'],-3600)
        self.assertIsNone(result['impossible_negative_skew'])
        self.assertEqual(received_score_components(result)['received_non_monotonic_dates'],0)

    def test_equal_timestamps_and_repeated_ip_do_not_prove_suspicious_relay(self):
        result = analyze_received_anomalies(chain(['Wed, 8 Oct 2025 10:00:00 +0000']*2))
        self.assertIsNone(result['suspicious_relay_chain'])
        self.assertNotIn('suspicious_relay_chain',result['spoofing_patterns'])
        repeat, = result['timing_observations']['repeated_ip_claims']
        self.assertEqual(repeat['ip'],'8.8.8.8')
        self.assertEqual(repeat['header_indices'],[1,0])
        self.assertFalse(repeat['verified'])

    def test_long_claimed_interval_does_not_prove_manipulation(self):
        result = analyze_received_anomalies(chain(['Wed, 8 Oct 2025 10:00:00 +0000',
                                                  'Wed, 8 Oct 2025 14:00:00 +0000']))
        self.assertIsNone(result['timestamp_manipulation'])
        self.assertNotIn('timestamp_manipulation',result['spoofing_patterns'])
        pair, = result['timing_observations']['adjacent_pairs']
        self.assertEqual(pair['delta_seconds'],14400)

    def test_single_future_claim_records_reference_without_manipulation(self):
        result = analyze_received_anomalies(chain(['Wed, 8 Oct 2099 10:00:00 +0000']),reference_time=REFERENCE)
        self.assertIsNone(result['timestamp_manipulation'])
        timing = result['timing_observations']
        self.assertEqual(timing['reference_time'],REFERENCE)
        self.assertTrue(timing['timestamps'][0]['after_reference'])
        self.assertFalse(timing['verified'])

    def test_legacy_naive_iso_claim_is_not_an_aware_comparison(self):
        result = analyze_received_anomalies([{'date':'2025-10-08T10:00:00+00:00'},
                                             {'date':'2025-10-08T09:00:00'}])
        self.assertIsNone(result['non_monotonic_dates'])
        self.assertEqual(result['timing_observations']['adjacent_pairs'][0]['status'],'not_evaluated')

    def test_empty_chain_has_no_false_temporal_result(self):
        result = analyze_received_anomalies([])
        self.assertIsNone(result['non_monotonic_dates'])
        self.assertEqual(result['timing_observations']['status'],'unavailable')
        self.assertEqual(result['timing_observations']['adjacent_pairs'],[])

    def test_observations_match_persisted_hop_pairs_without_network(self):
        before = len(violations())
        with offline_policy(True):
            hops = chain(['Wed, 8 Oct 2025 10:00:00 +0000','Wed, 8 Oct 2025 10:00:03 +0000'])
            result = analyze_received_anomalies(hops,reference_time=REFERENCE)
        self.assertEqual(len(violations()),before)
        self.assertEqual(result['timing_observations']['adjacent_pairs'],[hops[1]['timing_observation']])

    def test_partial_chain_does_not_report_whole_chain_monotonic(self):
        hops = chain(['Wed, 8 Oct 2025 10:00:00 +0000',None,
                      'Wed, 8 Oct 2025 12:00:00 +0000','Wed, 8 Oct 2025 12:00:01 +0000'])
        result = analyze_received_anomalies(hops,reference_time=REFERENCE)
        self.assertIsNone(result['non_monotonic_dates'])
        self.assertEqual(result['timing_observations']['comparison_status'],'partial')
        self.assertEqual([hop['skew_s'] for hop in hops],[None,None,None,1])

    def test_naive_reference_is_rejected_instead_of_assuming_utc(self):
        with self.assertRaises(ValueError):
            analyze_received_anomalies([],reference_time='2026-10-09T12:00:00')


if __name__ == '__main__':
    unittest.main()
