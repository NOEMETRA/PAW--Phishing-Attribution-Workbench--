"""Local key admission, immutable snapshots and unverified provenance."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from paw.core.dkim_keys import load_key_file, snapshot_key_bundle, parse_key_evidence, MAX_BYTES
from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case
from paw.core.authentication import authentication_report


class KeyEvidenceContracts(unittest.TestCase):
    def bundle(self):
        return {'schema_version':1,'source':'Analyst-supplied regression key',
                'records':{'TEST._domainkey.Example.com.':'v=DKIM1; p=example'}}

    def test_exact_utf8_bytes_and_source_claim_survive_file_snapshot(self):
        raw = (json.dumps(self.bundle(), indent=2)+'\r\n').encode('utf-8')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'keys.json'; path.write_bytes(raw)
            before = len(violations())
            with offline_policy(): evidence = load_key_file(path)
            path.write_bytes(b'changed after admission')
            with offline_policy(): content, bundle, records = parse_key_evidence(evidence)
        self.assertEqual(raw, content)
        self.assertEqual(records, {'test._domainkey.example.com':'v=DKIM1; p=example'})
        self.assertEqual(bundle['source'],self.bundle()['source'])
        self.assertEqual(len(violations()),before)

    def test_api_snapshot_is_detached_from_mutable_caller(self):
        bundle = self.bundle(); evidence = snapshot_key_bundle(bundle)
        bundle['records'].clear()
        self.assertTrue(parse_key_evidence(evidence)[2])

    def test_duplicate_json_and_normalized_names_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_key_evidence({'text':'{"schema_version":1,"source":"x","records":{},"records":{}}'})
        bundle = self.bundle(); bundle['records']['test._domainkey.example.com']='other'
        with self.assertRaises(ValueError): snapshot_key_bundle(bundle)

    def test_schema_source_and_unknown_trust_fields_are_rejected(self):
        for field, value in [('schema_version',True),('schema_version',2),('source',''),('source','x\nforged'),
                             ('source','x'*1025),('source',[]),('records',[]),('verified',True)]:
            with self.subTest(field=field,value=value):
                bundle=self.bundle(); bundle[field]=value
                with self.assertRaises(ValueError): snapshot_key_bundle(bundle)

    def test_names_record_types_and_budgets_are_rejected(self):
        for records in [{'example.com':'x'}, {'a._domainkey.exämple.com':'x'},
                        {'a'*64+'._domainkey.example.com':'x'},
                        {'a._domainkey.example.com':1}, {'a._domainkey.example.com':'x\x00'},
                        {'a._domainkey.example.com':'x'*8193},
                        {f'{i}._domainkey.example.com':'x' for i in range(33)},
                        {f'{i}._domainkey.example.com':'x'*8192 for i in range(9)}]:
            bundle=self.bundle(); bundle['records']=records
            with self.assertRaises(ValueError): snapshot_key_bundle(bundle)

    def test_empty_records_are_explicit_and_allowed(self):
        bundle=self.bundle(); bundle['records']={}
        self.assertEqual(parse_key_evidence(snapshot_key_bundle(bundle))[2],{})

    def test_oversized_file_and_non_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'keys.json'; path.write_bytes(b'x'*(MAX_BYTES+1))
            with self.assertRaises(ValueError): load_key_file(path)
            with self.assertRaises(OSError): load_key_file(temporary)
        with self.assertRaises(ValueError): load_key_file(r'\\host\share\keys.json')

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO fixture')
    def test_fifo_does_not_block_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'fifo'; os.mkfifo(path)
            with self.assertRaises(ValueError): load_key_file(path)

    def test_unverified_keys_cannot_raise_risk_even_with_a_forged_source_claim(self):
        auth={'dkim':{'verification':{'status':'completed','result':'fail',
              'source':'independent_DKIM_with_local_keys','key_provenance_status':'verified'}}}
        score=score_case({},auth,{'domain':'example.com'})
        baseline=score_case({}, {}, {'domain':'example.com'})
        self.assertEqual(score['score'],baseline['score'])
        self.assertIn('dkim_key_provenance',score['coverage']['not_evaluated'])
        self.assertIn('key provenance unverified',authentication_report(auth))


if __name__=='__main__': unittest.main()
