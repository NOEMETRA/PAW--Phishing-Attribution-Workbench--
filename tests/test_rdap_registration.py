"""Supplied protocol objects are contracts, not registry or phishing ground truth."""
import copy
import unittest
from paw.core.network_policy import offline_policy, violations
from paw.core.profiler import domain_rdap, _domain_registration, observe_domain_age
from paw.core.rdap_registration import observe_rdap_registration
from paw.core.scoring import score_case


def response(name='example.com',date='2026-10-01T00:00:00Z'):
    return {'objectClassName':'domain','ldhName':name,
            'events':[{'eventAction':'registration','eventDate':date}]}


class RegistrationContracts(unittest.TestCase):
    def observe(self,data,domain='example.com'):
        with offline_policy(True): return observe_rdap_registration(domain,data)

    def unavailable(self,data,reason,domain='example.com'):
        record=self.observe(data,domain)
        self.assertIsNone(record['created'])
        self.assertEqual(record['reason_code'],reason)
        self.assertFalse(record['verified'])
        age=observe_domain_age(record['created'],reference_time='2026-10-10T00:00:00Z')['age_days']
        score=score_case({}, {}, {'domain':'example.com','nrd_days':age},headers={'from':'a@example.com'})
        self.assertEqual(score['score_components']['sender_domain_heuristics'],0)
        return record

    def test_exact_domain_and_one_registration_event(self):
        record=self.observe(response())
        self.assertEqual(record['created'],'2026-10-01T00:00:00Z')
        self.assertTrue(record['domain_match'])
        self.assertEqual(record['status'],'observed_unverified')
        self.assertFalse(record['verified'])

    def test_dns_case_and_single_root_dot(self):
        record=self.observe(response('EXAMPLE.COM.'),'Example.Com.')
        self.assertTrue(record['domain_match'])
        self.assertEqual(record['returned_ldh_name'],'EXAMPLE.COM.')
        self.assertEqual(record['returned_domain'],'example.com')

    def test_unrelated_similar_and_parent_domains_are_not_bound(self):
        for name in ('other.com','example.com.attacker.test','notexample.com','com'):
            with self.subTest(name=name): self.unavailable(response(name),'domain_mismatch')
        self.unavailable(response(),'domain_mismatch',domain='mail.example.com')
        self.assertTrue(self.observe(response('mail.example.com'),'mail.example.com')['domain_match'])

    def test_no_identity_guess_from_unicode_or_links(self):
        data=response(); data.pop('ldhName'); data['unicodeName']='example.com'
        data['links']=[{'rel':'self','href':'https://example.com'}]
        self.unavailable(data,'ldh_name_unavailable_or_invalid')

    def test_ldh_requires_ascii_and_unambiguous_syntax(self):
        for name in (None,True,[],{},'',' example.com','example.com ','example.com..','exa_mple.com','bücher.com'):
            with self.subTest(name=name): self.unavailable(response(name),'ldh_name_unavailable_or_invalid')

    def test_unicode_query_can_bind_to_supplied_ascii_ace_name(self):
        record=self.observe(response('xn--bcher-kva.com'),'bücher.com')
        self.assertTrue(record['domain_match'])
        self.assertEqual(record['requested_domain'],'xn--bcher-kva.com')

    def test_domain_object_class_required(self):
        for kind in (None,'entity','nameserver','Domain',[],{}):
            data=response(); data['objectClassName']=kind
            with self.subTest(kind=kind): self.unavailable(data,'not_domain_object')

    def test_invalid_input_object_and_query(self):
        for data in ([],True,42,'bad'):
            self.unavailable(data,'invalid_response_object')
        self.unavailable(None,'response_unavailable')
        for domain in ('a/b',b'example.com',True,42,[],{},None):
            self.unavailable(response(),'invalid_requested_domain',domain=domain)

    def test_nonstring_collector_query_rejected_before_http_or_dns(self):
        for domain in (b'example.com',True,42,[],{},None):
            record=domain_rdap(domain)
            self.assertEqual(record['reason'],'invalid-domain')
            self.assertIsNone(record['created'])
            lookup=_domain_registration(domain,'http://127.0.0.1:1/')
            self.assertEqual(lookup['rdap_registration']['reason_code'],'invalid_requested_domain')
            self.assertIsNone(lookup['created'])

    def test_absent_registration_and_unrelated_events(self):
        for events in (None,[],[{'eventAction':'last changed','eventDate':'2026-10-01T00:00:00Z'}]):
            data=response(); data['events']=events
            self.unavailable(data,'registration_event_unavailable')

    def test_multiple_registration_events_preserved_without_last_wins(self):
        for date in ('2026-10-01T00:00:00Z','2026-10-09T00:00:00Z'):
            data=response(); data['events'].append({'eventAction':'registration','eventDate':date})
            record=self.unavailable(data,'ambiguous_registration_events')
            self.assertEqual([v['event_date'] for v in record['registration_events']],['2026-10-01T00:00:00Z',date])
            self.assertEqual([v['event_index'] for v in record['registration_events']],[0,1])

    def test_malformed_events_or_missing_date_do_not_select_an_age(self):
        for events in ({},'',True,[None],[{} ,'bad']):
            data=response(); data['events']=events
            self.unavailable(data,'invalid_events')
        for date in (None,'',True,{},[]):
            self.unavailable(response(date=date),'invalid_registration_date')

    def test_nested_entity_dates_are_not_domain_registration(self):
        data=response(); data.pop('events'); data['entities']=[response()]
        self.unavailable(data,'registration_event_unavailable')

    def test_future_timestamp_stays_reported_but_not_usable_age(self):
        record=self.observe(response(date='2099-01-01T00:00:00Z'))
        self.assertIsNotNone(record['created'])
        age=observe_domain_age(record['created'],reference_time='2026-10-10T00:00:00Z')
        self.assertEqual(age['reason_code'],'future_timestamp')
        self.assertIsNone(age['age_days'])

    def test_input_object_unchanged_and_no_network(self):
        data=response(); original=copy.deepcopy(data); before=len(violations())
        self.observe(data)
        self.assertEqual(data,original)
        self.assertEqual(len(violations()),before)

    def test_collectors_skip_before_network_under_no_egress(self):
        before=len(violations())
        with offline_policy(True):
            record=domain_rdap('example.com')
            lookup=_domain_registration('example.com','http://127.0.0.1:1/')
        self.assertEqual(record['status'],'skipped')
        self.assertEqual(record['reason'],'no-egress')
        self.assertIsNone(record['created'])
        self.assertEqual(lookup['rdap_registration']['reason_code'],'no_egress')
        self.assertIsNone(lookup['created'])
        self.assertEqual(len(violations()),before)


if __name__=='__main__': unittest.main()
