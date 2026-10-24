"""Pure registry/profile admission: no DNS, packet or rule installation."""
import copy
import socket
import unittest
from unittest.mock import patch
from uplink_policy import (Refused,make_profile,validate,address,endpoint,admit,
                            lease_transaction,match_uplink,live_readiness)

def fixture():return make_profile('out0','02:00:00:00:42:01','198.18.42.1','198.18.42.2',emulation=True)
def candidate():return make_profile('wlp4s0','02:00:00:00:42:01','192.168.1.137','192.168.1.1','00000000-0000-0000-0000-000000000001','02:00:00:00:42:02')
def plan(p):return admit(p,p['targets'][0]['id'],p['targets'][0]['url'],p['targets'][0]['pinned_ipv4'],0,30,30)

class UplinkPolicy(unittest.TestCase):
    def test_candidate_has_no_implicit_public_address_or_live_enable(self):
        p=candidate()
        with patch.object(socket,'socket',side_effect=AssertionError('No network')):
            self.assertFalse(live_readiness(p)['enabled'])
            self.assertEqual(p['targets'][0]['url'],'https://httpbingo.org/get')
            with self.assertRaisesRegex(Refused,'pinning_pending'):plan(p)
        p['enabled']=True
        with self.assertRaises(Refused):validate(p)

    def test_special_purpose_addresses_and_alternate_encodings(self):
        for value in ['0.0.0.0','10.1.1.1','100.64.0.1','127.0.0.1','169.254.169.254',
                      '172.17.0.1','192.0.0.9','192.0.2.10','192.88.99.1','192.168.1.1',
                      '198.18.43.10','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255',
                      '127.1','2130706433','0x7f000001','0177.0.0.1','::ffff:8.8.8.8',True,None]:
            with self.subTest(value=value),self.assertRaises(Refused):address(value)
        self.assertEqual(address('8.8.8.8'),'8.8.8.8')

    def test_exact_url_no_credentials_query_redirect_or_nonhttps(self):
        self.assertEqual(endpoint('https://httpbingo.org/get')['path'],'/get')
        for url in ['http://httpbingo.org/get','https://httpbingo.org:8443/get','https://u@httpbingo.org/get',
                    'https://httpbingo.org/get?token=x','https://httpbingo.org/get#x',
                    'https://httpbingo.org./get','https://%68ttpbingo.org/get','https://[::1]/',
                    'https://HTTPBINGO.ORG/get','https://httpbingo.org/%2e/get','https://httpbingo.org/../get',
                    'https://httpbingo.org/get\r\nX:y']:
            with self.subTest(url=url),self.assertRaises(Refused):endpoint(url)
        with self.assertRaises(Refused):admit(fixture(),'owned-fixture','https://allow.fixture.invalid/other',['198.18.43.10'],0,30,30)

    def test_dns_mixed_rebinding_and_lifetimes(self):
        p=fixture()
        good=plan(p);self.assertEqual(good['lease_seconds'],5)
        for values in [[],['198.18.43.10','127.0.0.1'],['198.18.43.11'],['198.18.43.10']*2,[{}],['::ffff:198.18.43.10']]:
            with self.subTest(values=values),self.assertRaises(Refused):admit(p,'owned-fixture',p['targets'][0]['url'],values,0,30,30)
        for age,ttl,remaining in [(10,30,30),(-1,30,30),(2,1,30),(0,0,30),(0,30,0),(0,30,float('nan')),(True,30,30)]:
            with self.subTest(age=age,ttl=ttl,remaining=remaining),self.assertRaises(Refused):admit(p,'owned-fixture',p['targets'][0]['url'],['198.18.43.10'],age,ttl,remaining)
        self.assertEqual(admit(p,'owned-fixture',p['targets'][0]['url'],['198.18.43.10'],1,3,30)['lease_seconds'],2)

    def test_forged_plan_cannot_open_other_ip_host_port_or_duration(self):
        p=fixture();good=plan(p);self.assertEqual(lease_transaction(p,good).count('add element'),2)
        for key,value in [('address','198.18.43.11'),('all_addresses',['198.18.43.11']),('host','other.fixture.invalid'),
                          ('target_id','other'),('port',80),('lease_seconds',11),('method','POST'),
                          ('tls_hostname','other.fixture.invalid'),('profile_sha256','0'*64),('redirects',1)]:
            forged={**good,key:value}
            with self.subTest(key=key),self.assertRaises(Refused):lease_transaction(p,forged)

    def test_network_binding_drift(self):
        p=candidate();self.assertTrue(match_uplink(p,p['uplink']))
        for key,value in [('interface','eth0'),('next_hop','192.168.2.1'),('host_ipv4','192.168.1.138'),
                          ('bssid','02:00:00:00:42:03'),('connection_uuid','00000000-0000-0000-0000-000000000002')]:
            with self.subTest(key=key),self.assertRaises(Refused):match_uplink(p,{**p['uplink'],key:value})

    def test_delayed_or_prior_boot_plan_cannot_be_reopened(self):
        p=fixture()
        with patch('uplink_policy.time.monotonic',return_value=100):good=plan(p)
        with patch('uplink_policy.time.monotonic',return_value=110),self.assertRaisesRegex(Refused,'stale_plan'):lease_transaction(p,good)
        with patch('uplink_policy.time.monotonic',return_value=101):
            self.assertIn('timeout 4000ms',lease_transaction(p,good))
            with patch('uplink_policy.boot_id',return_value='different-boot'),self.assertRaisesRegex(Refused,'other_boot'):lease_transaction(p,good)

    def test_ambiguous_schema_and_budget_expansion_refuse(self):
        for key,value in [('schema',True),('targets',{}),('extra',1)]:
            p=fixture();p[key]=value
            with self.subTest(key=key),self.assertRaises(Refused):validate(p)
        for key,value in [('redirects',1),('lease_seconds',11),('request_count',5),('response_bytes',65537),('job_seconds',61)]:
            p=fixture();p['budgets'][key]=value
            with self.subTest(key=key),self.assertRaises(Refused):validate(p)
        p=fixture();p['targets'][0]['pinned_ipv4']=[{}]
        with self.assertRaises(Refused):validate(p)

if __name__=='__main__':unittest.main()
