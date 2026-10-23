"""Per-source links to existing URL records, with explicit claim/limit boundaries."""
import base64
import asyncio
import copy
import hashlib
import json
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import tempfile
import unittest
import sys

from paw.core.header_inventory import inventory_headers, HeaderInventoryLimits
from paw.core.mime_analysis import analyze_mime, extract_urls
from paw.core.mime_body_evidence import preserve_body_parts
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_message_bytes, parse_eml_bytes
from paw.core.url_evidence import build_url_evidence, extract_mime_url_candidates
from paw.core.url_sources import inventory_url_sources, url_source_coverage
from paw.core.runtime import supervise, RunLimits, preserve_interrupted
from paw.core.verify import verify_case
from paw.deobfuscate.url import URLDeobfuscator


URL='https://shared-source.invalid/a?x=1&y=2'


def message():
    value=EmailMessage(policy=policy.SMTP)
    value['From']='outer@example.invalid';value['Subject']='Notice '+URL
    value.set_content('First '+URL+'\nAgain '+URL)
    value.add_alternative('<a href="'+URL.replace('&','&amp;')+'">'+URL.replace('&','&amp;')+'</a>', subtype='html')
    value.add_attachment('Excluded https://attached-only.invalid/',filename='letter.txt')
    return value


def run(raw, *, limits=None, extra=(), **kwargs):
    msg=parse_message_bytes(raw); headers=parse_eml_bytes(raw); mime=analyze_mime(msg)
    header=inventory_headers(msg,raw,limits) if limits else inventory_headers(msg,raw)
    observed=list(dict.fromkeys(mime['urls']+extract_urls(headers.get('subject',''))+extract_urls(headers.get('from',''))))
    candidates=list(dict.fromkeys(observed+extract_mime_url_candidates(mime,headers.get('subject',''))))
    decoder=URLDeobfuscator()
    targets,evidence=build_url_evidence(observed,[decoder.deobfuscate_url(c) for c in candidates])
    evidence+=list(extra); before=copy.deepcopy(evidence)
    with tempfile.TemporaryDirectory() as temp:
        body=preserve_body_parts(mime,raw,Path(temp)/'mime_body')
        inventory=inventory_url_sources(mime,body,msg,headers,header,evidence,**kwargs)
    assert evidence==before
    return inventory,evidence,targets


def contexts(inventory,index):
    sources=inventory['sources']
    return {(sources[link['source_index']]['kind'], sources[link['source_index']].get('part_id'),
             sources[link['source_index']].get('field')) for link in inventory['links'] if link['url_evidence_index']==index}


class URLSourceTests(unittest.TestCase):
    def test_shared_target_retains_all_part_and_selected_subject_sources(self):
        inventory,evidence,targets=run(message().as_bytes())
        self.assertEqual(targets,[URL]);self.assertEqual(len(evidence),1)
        self.assertEqual(contexts(inventory,0),{('mime_body','0.0.0',None),('mime_body','0.0.1',None),('selected_header','0','subject')})
        self.assertEqual(inventory['total_link_count'],3)
        self.assertEqual(inventory['mapped_evidence_count'],1)
        self.assertEqual(inventory['status'],'completed')
        self.assertFalse(inventory['verified'])

    def test_colliding_derived_target_matches_original_candidate_not_target_substring(self):
        value=EmailMessage(policy=policy.SMTP)
        raw='hxxps://example[.]invalid/a'
        encoded=base64.b64encode(b'https://example.invalid/a').decode()
        value.set_content(raw);value.add_alternative('<div data-next="'+encoded+'"></div>',subtype='html')
        inventory,evidence,targets=run(value.as_bytes())
        self.assertEqual(targets,['https://example.invalid/a'])
        for index,record in enumerate(evidence):
            linked=contexts(inventory,index)
            if record['source_url']==raw: self.assertEqual(linked,{('mime_body','0.0',None)})
            else: self.assertEqual(linked,{('mime_body','0.1',None)})

    def test_invalid_and_unresolved_sources_remain_linked_without_becoming_targets(self):
        raw=b'From: outer@example.invalid\r\n\r\nhxxps://bad[.]invalid/%ZZ aHR0c!!!'
        inventory,evidence,targets=run(raw)
        self.assertEqual(targets,[]);self.assertEqual(len(evidence),2)
        self.assertEqual(inventory['mapped_evidence_count'],2)
        self.assertEqual(inventory['status'],'completed')
        self.assertTrue(all(not record['network_target'] for record in evidence))

    def test_html_charrefs_split_visible_text_comments_and_script_candidates(self):
        bodies=['<p>https://split.invalid/<b>tail</b></p>',
                '<!-- hxxps://comment[.]invalid/ --><script>"aHR0cHM6Ly9zY3JpcHQuaW52YWxpZC8="</script>',
                '<a href="https://entity.invalid/?x=1&amp;y=2">go</a>',
                '<div xmlns="https://vocabulary.invalid/">text</div>']
        for body in bodies:
            value=EmailMessage(policy=policy.SMTP);value.set_content(body,subtype='html')
            with self.subTest(body=body):
                inventory,evidence,_=run(value.as_bytes())
                self.assertEqual(inventory['unmapped_evidence_count'],0)
                self.assertTrue(all(contexts(inventory,i)=={('mime_body','0',None)} for i in range(len(evidence))))
                source=inventory['sources'][0]
                self.assertEqual(source['representation'],'html_parser_derived_url_candidate_views')
                self.assertEqual(source['derivation'],{'method':'paw_html_url_candidate_views_v5','persisted':False})
                self.assertEqual(source['derived_from']['representation'],'per_part_charset_decoded_text')
                self.assertNotIn('text_path',source)
                if 'xmlns' in body:self.assertEqual(evidence,[])

    def test_html_parser_input_hash_is_separate_from_nonliteral_candidates(self):
        markup='<a href="https://entity.invalid/?x=1&amp;y=2">go</a><p>https://split.invalid/<b>tail</b></p>'
        value=EmailMessage(policy=policy.SMTP);value.set_content(markup,subtype='html')
        raw=value.as_bytes();msg=parse_message_bytes(raw);mime=analyze_mime(msg)
        inventory,evidence,_=run(raw)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);body=preserve_body_parts(mime,raw,root/'mime_body')
            source=inventory['sources'][0]['derived_from']
            data=(root/source['text_path']).read_bytes()
            self.assertEqual(source['text_sha256'],hashlib.sha256(data).hexdigest())
            self.assertEqual(source['text_sha256'],body['parts'][0]['text_sha256'])
            self.assertEqual({r['url'] for r in evidence},{'https://entity.invalid/?x=1&y=2','https://split.invalid/tail'})
            self.assertTrue(all(r['url'] not in data.decode('utf-8') for r in evidence))
        plain,_,_=run(b'\r\nhttps://plain.invalid/')
        self.assertEqual(plain['sources'][0]['representation'],'per_part_charset_decoded_text')
        self.assertNotIn('derived_from',plain['sources'][0])

    def test_plain_js_independent_html_state_and_attached_scope(self):
        value=EmailMessage(policy=policy.SMTP);value.set_content('<script>unclosed',subtype='html')
        value.add_alternative('<a href="hxxps://later[.]invalid/">go</a>',subtype='html')
        value.add_alternative('const u="https://js-source.invalid/";',subtype='javascript')
        inner=EmailMessage();inner.set_content('https://embedded-only.invalid/')
        value.add_attachment(inner,filename='inner.eml')
        inventory,evidence,targets=run(value.as_bytes())
        self.assertEqual(set(targets),{'https://later.invalid/','https://js-source.invalid/'})
        self.assertEqual(inventory['unmapped_evidence_count'],0)
        self.assertFalse(any('embedded' in str(record) for record in evidence))

    def test_first_selected_header_occurrences_only_and_unknown_fields_excluded(self):
        raw=(b'X-Unknown: https://unknown-only.invalid/\r\n'
             b'Subject: https://first.invalid/\r\nSubject: https://second-only.invalid/\r\n'
             b'From: "https://display.invalid/" <outer@example.invalid>\r\n\r\nbody')
        inventory,evidence,targets=run(raw)
        self.assertEqual(set(targets),{'https://first.invalid/','https://display.invalid/'})
        sources=[s for s in inventory['sources'] if s['kind']=='selected_header']
        self.assertEqual([(s['field'],s['header_index']) for s in sources],[('subject',1),('from',3)])
        self.assertTrue(all(contexts(inventory,i)=={('selected_header','0','subject' if 'first' in r['url'] else 'from')} for i,r in enumerate(evidence)))

    def test_header_inventory_limits_do_not_fabricate_captured_fields(self):
        inventory,_,_=run(message().as_bytes(),limits=HeaderInventoryLimits(max_fields=1))
        selected={s['field']:s for s in inventory['sources'] if s['kind']=='selected_header'}
        self.assertEqual(selected['subject']['header_inventory_status'],'not_inventoried')
        self.assertEqual(inventory['mapped_evidence_count'],1)

    def test_link_budget_keeps_order_counts_and_partial_unmapped_prefix(self):
        extras=[{'url':'https://unmapped.invalid/'+str(i),'provenance':'observed'} for i in range(5)]
        inventory,_,_=run(message().as_bytes(),max_links=2,max_unmapped=2,extra=extras)
        self.assertEqual(inventory['total_link_count'],3)
        self.assertEqual(inventory['inventoried_link_count'],2)
        self.assertEqual(inventory['omitted_link_count'],1)
        self.assertEqual(inventory['unmapped_evidence_count'],5)
        self.assertEqual(inventory['unmapped_evidence_indexes'],[1,2])
        self.assertEqual(inventory['omitted_unmapped_index_count'],3)
        self.assertEqual(inventory['status'],'partial')
        limited,_,_=run(message().as_bytes(),max_links=2)
        self.assertEqual(limited['status'],'limited')
        self.assertEqual(limited['links'],inventory['links'])
        self.assertEqual(limited['mapped_evidence_count'],1)

    def test_zero_urls_and_invalid_limit_admission(self):
        inventory,evidence,targets=run(b'\r\nbody')
        self.assertEqual(evidence,[]);self.assertEqual(targets,[])
        self.assertEqual(inventory['total_link_count'],0)
        self.assertEqual(inventory['status'],'completed')
        for name in ('max_links','max_unmapped'):
            for value in (0,-1,True,1.5,None):
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):run(b'\r\nbody',**{name:value})

    def test_source_binding_and_coverage_no_egress(self):
        raw=message().as_bytes();msg=parse_message_bytes(raw);mime=analyze_mime(msg)
        header=inventory_headers(msg,raw)
        with tempfile.TemporaryDirectory() as temp:
            body=preserve_body_parts(mime,raw,Path(temp)/'mime_body')
            wrong=copy.deepcopy(body);wrong['source']['sha256']='0'*64
            with self.assertRaises(ValueError):inventory_url_sources(mime,wrong,msg,{},header,[])
            unbound=BytesParser(policy=policy.default).parsebytes(raw)
            with self.assertRaises(ValueError):inventory_url_sources(mime,body,unbound,{},header,[])
        before=len(violations())
        with offline_policy():inventory,_,_=run(raw)
        self.assertEqual(len(violations()),before)
        coverage=url_source_coverage(inventory)
        self.assertEqual(coverage['artifact'],'url_source_inventory.json')
        for key in ('status','source_count','total_link_count','omitted_link_count','unmapped_evidence_count'):
            self.assertEqual(coverage[key],inventory[key])


class URLSourceInterruptionTests(unittest.IsolatedAsyncioTestCase):
    async def interrupt_after(self, artifact):
        # Pause real serialization/writes/publication in the guarded trace.
        # These hooks supply no analysis output; the supervisor kills the tree.
        script='''from paw.core.runtime import wait_for_gate, mark_stage
wait_for_gate()
import time, sys, json
from pathlib import Path
import paw.core.trace as trace
write=trace.write_json
publish=trace.atomic_json
write_text=Path.write_text
encode=json.JSONEncoder.iterencode
mode=sys.argv[1]
def pause():
    mark_stage('url_source_pause')
    Path('ready').touch()
    while True: time.sleep(.1)
def observe(path,value):
    write(path,value)
    if Path(path).name==mode: pause()
def observe_publish(path,value):
    publish(path,value)
    if Path(path).name==mode: pause()
def observe_encode(self,value,_one_shot=False):
    for chunk in encode(self,value,_one_shot):
        yield chunk
        if mode=='catalog_encoding' and isinstance(value,dict) and value.get('scope')=='existing_url_records_in_supported_outer_message_views': pause()
def observe_text(path,value,*args,**kwargs):
    temporary=path.name.startswith('url_source_inventory.json.') and path.suffix=='.tmp'
    if temporary and mode=='catalog_partial_temporary':
        with path.open('w',encoding='utf-8') as stream:
            stream.write(value[:32]);stream.flush()
        pause()
    result=write_text(path,value,*args,**kwargs)
    if temporary and mode=='catalog_before_replace': pause()
    return result
trace.write_json=observe
trace.atomic_json=observe_publish
json.JSONEncoder.iterencode=observe_encode
Path.write_text=observe_text
trace.trace_one('input.eml','en',False,False,False,True)
'''
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);raw=message().as_bytes();(root/'input.eml').write_bytes(raw)
            control=root/'control';cancel=asyncio.Event()
            task=asyncio.create_task(supervise([sys.executable,'-X','utf8','-c',script,artifact],
                cwd=root,control=control,limits=RunLimits(wall_seconds=30,stage_seconds=20),
                cancel=cancel,env={'PYTHONPATH':str(Path(__file__).resolve().parents[1]),'PYTHONDONTWRITEBYTECODE':'1'}))
            try:
                end=asyncio.get_running_loop().time()+25
                while not (root/'ready').exists() and not task.done() and asyncio.get_running_loop().time()<end:
                    await asyncio.sleep(.05)
            finally:
                cancel.set();outcome=await task
            self.assertTrue((root/'ready').exists(),(control/'worker.log').read_text())
            self.assertEqual(outcome['status'],'cancelled');self.assertTrue(outcome['tree_stopped'])
            cases=preserve_interrupted(root,control,outcome['status'],outcome['error'])
            self.assertEqual(len(cases),1);self.assertEqual(cases[0]['integrity'],'sealed_partial')
            case=root/'cases'/cases[0]['case_id'];self.assertTrue(verify_case(case))
            self.assertEqual((case/'input.eml').read_bytes(),raw)
            self.assertTrue(json.loads((case/'manifest.json').read_text())['policy']['no_egress'])
            if artifact!='url_source_inventory.json':
                self.assertFalse((case/'url_source_inventory.json').exists())
                for name in ('headers.json','url_evidence.json','mime_body_evidence.json','header_inventory.json'):
                    json.loads((case/name).read_text())
                fragments=list(case.glob('url_source_inventory.json.*.tmp'))
                if artifact in {'catalog_partial_temporary','catalog_before_replace'}:
                    self.assertEqual(len(fragments),1)
                    data=fragments[0].read_bytes()
                    if artifact=='catalog_partial_temporary':
                        self.assertGreater(len(data),0)
                        with self.assertRaises(json.JSONDecodeError):json.loads(data)
                    else:
                        self.assertEqual(json.loads(data)['scope'],'existing_url_records_in_supported_outer_message_views')
                    await asyncio.sleep(.15)
                    self.assertEqual(fragments[0].read_bytes(),data)
                    self.assertTrue(verify_case(case))
                else:self.assertEqual(fragments,[])
                return
            inventory=json.loads((case/'url_source_inventory.json').read_text())
            self.assertEqual(list(case.glob('url_source_inventory.json.*.tmp')),[])
            references={'input.eml',inventory['url_evidence_artifact']}
            for source in inventory['sources']:
                references.add(source['artifact'])
                if source.get('header_inventory_artifact'):references.add(source['header_inventory_artifact'])
                text_source=source.get('derived_from',source)
                if text_source.get('text_path'):references.add(text_source['text_path'])
            before={name:(case/name).read_bytes() for name in references}
            await asyncio.sleep(.15)
            self.assertEqual(before,{name:(case/name).read_bytes() for name in references})
            self.assertTrue(verify_case(case))

    async def test_interruption_before_inventory_publishes_no_links(self):
        await self.interrupt_after('headers.json')

    async def test_interruption_after_inventory_retains_all_referenced_sources(self):
        await self.interrupt_after('url_source_inventory.json')

    async def test_interruption_during_catalog_encoding_publishes_no_catalog(self):
        await self.interrupt_after('catalog_encoding')

    async def test_interruption_during_temporary_write_publishes_no_catalog(self):
        await self.interrupt_after('catalog_partial_temporary')

    async def test_interruption_before_atomic_replace_publishes_no_catalog(self):
        await self.interrupt_after('catalog_before_replace')


if __name__=='__main__':unittest.main()
