"""Owned manifest admission only; no HTML/JS execution, VM or root authority."""
import json
import unittest
import test_browser_contract as support
import browser_validation_inputs as inputs


class OwnedInputs(unittest.TestCase):
    def test_fresh_finite_manifest_and_frames_are_exact_owned_bytes(self):
        raw=inputs.make('a'*16);value=inputs.parse(raw)
        self.assertEqual(len(value['inputs']),len(inputs.CASES))
        self.assertEqual([v['case'] for v in value['inputs']],list(inputs.CASES))
        identifiers=set()
        for entry in value['inputs']:
            frame=inputs.frame(entry,value['nonce']);parsed=support.contract.validate_frame(frame)
            self.assertEqual(parsed['source']['data_hex'],entry['source_hex'])
            self.assertEqual(parsed['source']['sha256'],entry['source_sha256'])
            identifiers.add(parsed['request_id'])
        self.assertEqual(len(identifiers),len(inputs.CASES))

    def test_validation_manifest_cannot_admit_arbitrary_or_relabelled_sources(self):
        for mutation in ['source','hash','case','nonce','scope']:
            value=json.loads(inputs.make('b'*16))
            if mutation=='source':value['inputs'][0]['source_hex']=b'not approved owned source'.hex()
            elif mutation=='hash':value['inputs'][0]['source_sha256']='0'*64
            elif mutation=='case':value['inputs'][0]['case']='real-analysis'
            elif mutation=='nonce':value['nonce']='../escape'
            else:value['scope']='real source accepted'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):inputs.parse(inputs.canonical(value))

    def test_old_timing_sensitive_memory_probe_is_not_admitted_as_the_new_probe(self):
        value=json.loads(inputs.make('c'*16));memory=next(v for v in value['inputs'] if v['case']=='memory')
        old=b'<title>owned-memory</title><script>const a=[];for(;;){a.push(new Uint8Array(64*1024*1024).fill(7));}</script>'
        self.assertNotEqual(bytes.fromhex(memory['source_hex']),old)
        memory.update(source_hex=old.hex(),source_sha256=inputs.digest(old))
        with self.assertRaisesRegex(ValueError,'exact_generated_bytes'):inputs.parse(inputs.canonical(value))


if __name__=='__main__':unittest.main()
