import base64
import hashlib
import unittest

from paw.core.representation_graph import Graph, GraphLimits
from paw.core.javascript_representation_observer import browser_bytes, observe_javascript, MAX_SOURCE


class JavaScriptRepresentation(unittest.TestCase):
    def test_embedding_round_trips_exact_bom_crlf_unicode_and_markup_bytes(self):
        raw = '\ufeffconsole.log("owned π");\r\n// </script><img src="https://example.invalid/">'.encode('utf-8')
        value=Graph(raw);result=observe_javascript(value,value.root);node=value.nodes[result['browser_representation']]
        wrapper=value.payload(result['browser_representation'])
        encoded=wrapper.split(b'base64,',1)[1].split(b'"',1)[0]
        self.assertEqual(base64.b64decode(encoded,validate=True),raw)
        self.assertNotIn(b'<img',wrapper);self.assertEqual(wrapper.count(b'<script '),1)
        self.assertEqual(value.payload(value.root),raw);self.assertEqual(node['parents'],[value.root])
        self.assertEqual(node['transform']['parameters']['source_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(node['kind'],'browser_html_candidate');self.assertTrue(node['complete_transform'])
        self.assertFalse(node['origin_verified']);self.assertEqual(node['execution_authority'],'none')
        self.assertIn('new document/origin',result['environment'])

    def test_invalid_utf8_and_oversize_preserve_original_and_record_omissions(self):
        for raw,reason in [(b'\xff','javascript_strict_utf8_required'),(b'x'*(MAX_SOURCE+1),'javascript_source_bytes')]:
            value=Graph(raw);result=observe_javascript(value,value.root)
            self.assertEqual(result['status'],'partial');self.assertIsNone(result['browser_representation'])
            self.assertEqual(value.payload(value.root),raw);self.assertIn(reason,result['issues'])
            self.assertEqual(value.record()['status'],'partial');self.assertEqual(len(value.nodes),1)

    def test_graph_work_node_and_aggregate_budgets_refuse_without_replacing_original(self):
        raw=b'console.log("owned")'
        for limits in [GraphLimits(source_bytes=64,representation_bytes=64),
                       GraphLimits(source_bytes=64,nodes=1),GraphLimits(source_bytes=64,work_bytes=1)]:
            value=Graph(raw,limits);result=observe_javascript(value,value.root)
            self.assertIsNone(result['browser_representation']);self.assertEqual(result['status'],'partial')
            self.assertEqual(value.payload(value.root),raw);self.assertEqual(len(value.nodes),1)

    def test_empty_and_maximum_source_have_bounded_separate_wrappers(self):
        for raw in [b'',b'A'*MAX_SOURCE]:
            wrapper=browser_bytes(raw);self.assertLessEqual(len(wrapper),512*1024)
            self.assertEqual(base64.b64decode(wrapper.split(b'base64,',1)[1].split(b'"',1)[0],validate=True),raw)


if __name__ == '__main__': unittest.main()
