"""Real policy operations and deterministic evidence checks; no mocked outputs."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from paw.core.network_policy import EgressDenied, offline_policy
from paw.core.scoring import score_case
from paw.core.ja3_fingerprinting import JA3FingerprintAnalyzer
from paw.core.attribution_matrix import AttributionMatrix
from paw.intelligence.criminal_hunter import CriminalHunter
from paw.core.verify import verify_case
import blake3

class ExecutionContracts(unittest.TestCase):
    def test_offline_denies_real_socket_creation(self):
        with offline_policy():
            with self.assertRaises(EgressDenied): socket.socket()

    def test_offline_denies_real_dns_resolution(self):
        with offline_policy():
            with self.assertRaises(EgressDenied): socket.getaddrinfo('example.invalid',443)

    def test_offline_denies_real_subprocess_launch(self):
        with offline_policy():
            with self.assertRaises(EgressDenied): subprocess.run([sys.executable,'-c','pass'])

    def test_offline_covers_worker_threads(self):
        results = []
        def attempt():
            try: socket.socket()
            except EgressDenied: results.append('blocked')
        with offline_policy():
            thread = threading.Thread(target=attempt)
            thread.start()
            thread.join()
        self.assertEqual(results,['blocked'])

    def test_unknown_ptr_does_not_raise_risk(self):
        auth = {'dkim':{'present':True,'aligned':True}}
        neutral = score_case({}, auth, {'domain':'ordinary.example'})
        unknown = score_case({'helo_ptr_match':None}, auth, {'domain':'ordinary.example'})
        self.assertEqual(neutral,unknown)

    def test_enrichment_file_presence_does_not_raise_risk(self):
        base = score_case({}, {}, {'domain':'ordinary.example'})
        covered = score_case({}, {}, {'domain':'ordinary.example'}, det_summary={
            'enrichment':{'enrichment_files':{'attribution_matrix':'matrix.json','tls_fingerprints':'tls.json'}}})
        self.assertEqual(base, covered)

    def test_ja3_matches_published_wire_order_vector(self):
        analyzer = JA3FingerprintAnalyzer()
        hello = {'version':769,'cipher_suites':[47,53,5,10,49161,49162,49171,49172,50,56,19,4],
            'extensions':[0,10,11],'elliptic_curves':[23,24,25],'ec_point_formats':[0]}
        self.assertEqual(analyzer._extract_ja3_from_client_hello(hello),'ada70206e40642a3e4461f35503241d5')
        hello['cipher_suites'].insert(0,0x0a0a)
        self.assertEqual(analyzer._extract_ja3_from_client_hello(hello),'ada70206e40642a3e4461f35503241d5')

    def test_http_logs_do_not_establish_ja3(self):
        result = JA3FingerprintAnalyzer().analyze_ja3_from_network_logs([{'url':'https://ordinary.example','method':'GET'}])
        self.assertEqual(result['status'],'unavailable')
        self.assertEqual(result['ja3_fingerprints'],[])

    def test_unsourced_operator_profiles_are_absent(self):
        self.assertEqual(AttributionMatrix().known_operators,{})

    def test_domain_brand_cannot_establish_named_actor(self):
        result = CriminalHunter()._identify_threat_actor_patterns('paypal.example', [])
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['threat_actor'], 'Unknown')
        self.assertEqual(result['confidence'], 0.0)

    def test_ip_substring_cannot_establish_asn(self):
        result = CriminalHunter()._identify_infrastructure_clusters('example.invalid', [{'ip':'35.200.1.1'}])
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['asn_clusters'], {})

    def test_computer_clock_cannot_establish_attacker_activity(self):
        result = CriminalHunter()._behavioral_pattern_analysis('example.invalid')
        self.assertEqual(result['timing_analysis']['status'], 'unavailable')
        self.assertNotIn('activity_score', result)

    def test_real_evidence_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'evidence').mkdir()
            evidence = root/'input.eml'
            evidence.write_bytes(b'Original evidence bytes')
            digest = blake3.blake3(evidence.read_bytes()).hexdigest()
            (root/'evidence/merkle_index.json').write_text(json.dumps({'input.eml':digest}))
            (root/'evidence/merkle_root.bin').write_text(blake3.blake3(digest.encode()).hexdigest())
            self.assertTrue(verify_case(directory))
            evidence.write_bytes(b'Altered evidence bytes')
            self.assertFalse(verify_case(directory))

if __name__ == '__main__': unittest.main()
