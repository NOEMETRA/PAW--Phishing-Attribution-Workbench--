"""Saved evidence admission and projections; fixtures are not accuracy labels."""
import asyncio
import copy
import io
from contextlib import closing, redirect_stdout
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from markdown_it import MarkdownIt
from paw.core.consumer_views import (assessment_view, verdict_color, read_artifact_json,
                                     read_artifact_text, ReadBudget)
from paw.core.scoring import score_case, finalize_score
from paw.core.network_policy import offline_policy
from paw.core import index
from paw.core.exporter import export_case
from paw.core.signature import sign_file_pgp
from paw.core.graphs import detonation_box, canary_box
from paw.core.reporting import rekor_report, publication_json
from paw.core.kit_static import analyze_phishing_kit_content
from paw.core.abuse import generate_abuse_package


def score_at(profile, value):
    with offline_policy():
        score = score_case({}, {}, {'domain':'example.invalid'}, profile=profile)
    return finalize_score(score, additional=value-score['raw_score'])


def blocks(text):
    tokens = MarkdownIt('commonmark').parse(text)
    assert not any(child.type in {'image','link_open','html_inline','html_block'}
                   for token in tokens for child in [token]+(token.children or []))
    return [json.loads(token.content) for token in tokens if token.type=='fence']


class ConsumerViews(unittest.TestCase):
    def test_profile_boundaries_and_rounding_use_the_recorded_decision(self):
        for profile, suspicious, malicious in [('default',.55,.72),('strict',.52,.68),('conservative',.58,.76)]:
            for value,color in [(suspicious-.0001,'white'),(suspicious,'yellow'),(malicious-.0001,'yellow'),(malicious,'red')]:
                score=score_at(profile,value); before=copy.deepcopy(score)
                self.assertEqual(verdict_color(score), color, (profile,value))
                self.assertEqual(assessment_view(score)['decision'], score['decision'])
                self.assertEqual(score,before)
        self.assertEqual(verdict_color(score_at('strict',.5192)), 'white')

    def test_legacy_display_does_not_invent_profile_decision_or_coverage(self):
        view=assessment_view({'score':.72,'decision':'recorded legacy claim'})
        self.assertEqual(view['status'],'legacy_display_only')
        self.assertEqual(view['display_score'],.72)
        for key in ('decision','decision_score','profile','thresholds','coverage'): self.assertIsNone(view[key])
        self.assertEqual(verdict_color({'score':.99}), 'white')
        for value in (None,[],{}, {'score':True},{'score':float('inf')},{'score':'0.5'},{'score':10**400}):
            self.assertIsNone(assessment_view(value)['decision_score'])

    def test_actual_rich_cells_and_stored_hypothesis_are_literal_and_profile_consistent(self):
        from paw.core import trace
        from rich.text import Text
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'attribution_matrix.json').write_text(json.dumps({'operator_hypothesis':
                {'confidence':[1], 'hypothesis':'[/bold]\n\x1b[31m'}}),encoding='utf-8')
            (root/'received_anomalies.json').write_text('{"timing_observations":[]}',encoding='utf-8')
            for profile,value,color in [('strict',.69,'red'),('conservative',.74,'yellow')]:
                captured=[]
                class Capture:
                    def print(self,item=None,*args,**kwargs): captured.append(item)
                with patch.object(trace,'Console',Capture),offline_policy():
                    trace.print_beautiful_summary(str(root),'[red]fixture',score_at(profile,value),'',{},'',{}, {})
                table=next(item for item in captured if type(item).__name__=='Table')
                cell=table.columns[1]._cells[3]
                self.assertIsInstance(cell,Text)
                self.assertEqual(cell.style,color)
                panel=next(item for item in captured if getattr(item,'title',None)=='Stored operator hypothesis (unverified)')
                self.assertIn('\\u001b',panel.renderable.plain)
                self.assertNotIn('\x1b',panel.renderable.plain)

    def test_inconsistent_current_metadata_is_not_presented_as_a_valid_verdict(self):
        for key,value in [('decision','Inconclusive'),('decision_score',.2),('profile','unknown'),
                          ('thresholds',{}),('coverage',[]),('calibrated',True),('score_components',{'x':True})]:
            score=score_at('strict',.8); score[key]=value
            self.assertEqual(assessment_view(score)['status'],'invalid',(key,value))
            self.assertEqual(verdict_color(score),'white')

    def test_strict_json_shape_duplicates_nonfinite_unicode_and_unchanged_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'source.json'
            for raw in (b'[1]',b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}',
                        b'{"x":"\xff"}',b'{"x":"\\ud800"}',b'{"\\ud800":0}',b'{'):
                path.write_bytes(raw)
                with self.assertRaises((ValueError,UnicodeError)): read_artifact_json(path)
                self.assertEqual(path.read_bytes(),raw)
            path.write_text('[1]',encoding='utf-8')
            self.assertEqual(read_artifact_json(path,list),[1])
            path.write_text('{"zero":0,"false":false,"empty":[]}',encoding='utf-8')
            self.assertEqual(read_artifact_json(path),{'zero':0,'false':False,'empty':[]})

    def test_file_and_aggregate_byte_node_depth_limits_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'source.json'; path.write_text('{"x":123}',encoding='utf-8')
            with patch('paw.core.consumer_views.MAX_ARTIFACT_BYTES',4), self.assertRaises(ValueError): read_artifact_json(path)
            budget=ReadBudget(bytes=10)
            self.assertEqual(read_artifact_json(path,budget=budget),{'x':123})
            with self.assertRaises(ValueError): read_artifact_json(path,budget=budget)
            with self.assertRaises(ValueError): read_artifact_json(path,budget=ReadBudget(nodes=1))
            path.write_text('{"x":{"y":1}}',encoding='utf-8')
            with patch('paw.core.consumer_views.MAX_JSON_DEPTH',1), self.assertRaises(ValueError): read_artifact_json(path)
            with self.assertRaises(ValueError): read_artifact_text(path.parent)

    def test_text_newline_view_preserves_existing_api_behavior_and_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'report.md'; raw=b'first\r\nsecond\rtail\n'; path.write_bytes(raw)
            self.assertEqual(read_artifact_text(path),'first\nsecond\ntail\n')
            self.assertEqual(path.read_bytes(),raw)
            path.write_bytes(b'{"source":"escaped\\r\\nvalue"}\r\n')
            self.assertEqual(read_artifact_json(path),{'source':'escaped\r\nvalue'})

    @unittest.skipIf(os.name=='nt','Native FIFO/symlink admission exercised on POSIX CI')
    def test_links_and_fifos_reject_before_blocking_or_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); source=root/'source'; source.write_text('{}')
            link=root/'link'; link.symlink_to(source)
            fifo=root/'fifo'; os.mkfifo(fifo)
            for path in (link,fifo):
                with self.assertRaises(ValueError): read_artifact_json(path)
            case=root/'case'; case.mkdir(); parent_link=case/'report'; parent_link.symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError): read_artifact_json(parent_link/'source',root=case)

    def test_sqlite_missing_score_is_null_and_query_projection_is_read_only(self):
        with closing(sqlite3.connect(':memory:')) as connection:
            index._init_db(connection)
            with patch.object(index,'db',return_value=connection): index.upsert_case('case-empty',{}, {}, {}, {})
            self.assertIsNone(connection.execute('SELECT score FROM cases').fetchone()[0])
        row={'id':'old','score':.72}; before=copy.deepcopy(row)
        view=index.describe_fingerprint(row)
        self.assertEqual(row,before)
        self.assertEqual(view['assessment_view']['status'],'legacy_display_only')
        self.assertIsNone(view['assessment_view']['decision'])
        view=index.describe_fingerprint({'id':'bad','score':float('inf')})
        self.assertIsNone(view['score']); self.assertEqual(view['score_source']['representation'],'inf')
        json.dumps(view,allow_nan=False)

    def test_dynamic_sections_are_literal_complete_stored_values_without_risk_inference(self):
        marker='![literal](https://inert.invalid/pixel)<b>literal</b>\n```\n\x1b[31m'
        data={'endpoints':[{'host':marker,'ips':[marker], 'count':'unverified'}]*14,'downloads':[marker]}
        self.assertEqual(blocks(detonation_box(data)),[data])
        visitors=[{'ip':marker,'reputation':{'score':8,'category':marker}}]
        self.assertEqual(blocks(canary_box([marker],visitors)),[{'ip_values':[marker],'visitor_records':visitors}])
        self.assertEqual(blocks(canary_box([],visitors))[0]['visitor_records'],visitors)
        self.assertNotIn('High risk',canary_box([marker],visitors))
        for value in ([{'shape':'legacy'}], {'endpoints':'wrong list'}, 'legacy scalar'):
            self.assertEqual(blocks(detonation_box(value)),[value])

    def test_provider_tree_size_is_not_inclusion_verification(self):
        from paw.core.rekor import verify_inclusion_proof
        anchor={'entry_uuid':'![literal](https://inert.invalid/)', 'logIndex':0}
        proof={'treeSize':123,'hashes':[]}
        record=blocks(rekor_report(anchor,proof))[0]
        self.assertEqual(record['anchor'],anchor); self.assertEqual(record['proof'],proof)
        self.assertEqual(record['verification']['status'],'not_evaluated')
        self.assertIsNone(record['verification']['result'])
        with offline_policy(): self.assertIsNone(verify_inclusion_proof(object(),object()))

    def test_content_verification_does_not_substitute_for_or_fail_on_unavailable_rekor(self):
        from paw.core.evidence import seal_case
        from paw.core.verify import verify_case
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'evidence').mkdir(); (root/'input.eml').write_bytes(b'Original bytes')
            (root/'evidence/rekor_anchor.json').write_bytes(b'{')
            (root/'evidence/rekor_proof.json').write_bytes(b'[1]')
            seal_case(root); output=io.StringIO()
            with redirect_stdout(output): self.assertTrue(verify_case(root))
            self.assertIn('Rekor inclusion: NOT_EVALUATED',output.getvalue())
            self.assertNotIn('Rekor inclusion: OK',output.getvalue())
            (root/'input.eml').write_bytes(b'Tampered')
            with redirect_stdout(output): self.assertFalse(verify_case(root))

    def test_large_or_non_json_publication_is_unavailable_without_clipping_source(self):
        source={'text':'x'*(256*1024)}; before=copy.deepcopy(source)
        self.assertEqual(blocks(publication_json(source))[0]['status'],'not_evaluated')
        self.assertEqual(source,before)
        for source in ({'value':float('nan')},object()):
            self.assertEqual(blocks(publication_json(source))[0]['status'],'not_evaluated')

    def test_pgp_request_rejects_before_source_key_or_output_access(self):
        with patch('builtins.open',side_effect=AssertionError('I/O')):
            with self.assertRaisesRegex(RuntimeError,'PGP signing unavailable'):
                sign_file_pgp(object(),object(),object(),object())
        with patch.dict(os.environ,{'PAW_PGP_PRIV':'private-placeholder'}), patch('pathlib.Path.resolve',side_effect=AssertionError('path inspected')):
            with self.assertRaisesRegex(RuntimeError,'PGP signing unavailable'): export_case(object(),'zip')

    def test_kit_css_preserves_narrow_capture_and_explicit_non_target_disposition(self):
        value='url("https://resource.invalid/a"/* https://comment.invalid/a */)'
        result=analyze_phishing_kit_content({'css':value})
        row,=result['observations']
        self.assertEqual(row['value'],'"https://resource.invalid/a"/* https://comment.invalid/a */')
        self.assertFalse(row['network_target'])
        self.assertEqual(row['resource_interpretation'],'not_evaluated')
        self.assertEqual(result['risk_level'],'unavailable')

    def test_plain_review_drafts_preserve_recorded_score_and_literal_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'report').mkdir()
            score=score_at('strict',.5192)
            marker='literal\nForged line\x1b[31m'
            (root/'headers.json').write_text(json.dumps({'from':marker}),encoding='utf-8')
            (root/'report/score.json').write_text(json.dumps(score),encoding='utf-8')
            for language in ('en','it'):
                text=Path(generate_abuse_package(root,language)).read_text(encoding='utf-8')
                self.assertIn('"decision_score": 0.5192',text)
                self.assertIn('"coverage":',text)
                self.assertIn('literal\\nForged line\\u001b[31m',text)
                self.assertNotIn('\x1b',text)


class HistoricalApiViews(unittest.IsolatedAsyncioTestCase):
    async def test_bad_manifest_and_score_shapes_do_not_abort_neighbor_listing(self):
        from paw.web import api
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,manifest,score in [('case-bad',[1],{'score':float('nan')}),('case-good',{'created_utc':'unverified'},score_at('strict',.2))]:
                case=root/name; (case/'report').mkdir(parents=True)
                (case/'manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
                (case/'headers.json').write_text('{}')
                (case/'report/score.json').write_text(json.dumps(score),encoding='utf-8')
            async def completed(_directory): return 'completed'
            with patch.object(api,'CASES_DIR',root),patch.object(api,'stable_case_status',completed):
                listing=await api.list_cases(limit=20,offset=0)
            rows={row['case_id']:row for row in listing['cases']}
            self.assertIn('manifest.json',rows['case-bad']['artifact_errors'])
            self.assertIn('score.json',rows['case-bad']['artifact_errors'])
            self.assertEqual(rows['case-bad']['assessment_view']['status'],'not_evaluated')
            self.assertEqual(rows['case-good']['assessment_view']['status'],'consistent_current_metadata')
            json.dumps(listing,allow_nan=False)

    async def test_detail_bad_containers_and_report_encoding_are_explicit(self):
        from paw.web import api
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); case=root/'case-fixture'; (case/'report').mkdir(parents=True)
            values={'headers.json':'[1]','attachments.json':'{}','execution.json':'[1]',
                    'report/score.json':'{"score":0.72,"decision":"legacy"}'}
            for name,value in values.items(): (case/name).write_text(value,encoding='utf-8')
            (case/'report/technical.md').write_bytes(b'\xff')
            before={name:(case/name).read_bytes() for name in values}
            async def completed(_directory): return 'completed'
            with patch.object(api,'CASES_DIR',root),patch.object(api,'require_stable_case',completed):
                detail=await api.get_case_detail(case.name)
            self.assertIsNone(detail['attachments']); self.assertIsNone(detail['execution'])
            self.assertIsNone(detail['technical_report']); self.assertEqual(detail['score']['decision'],'legacy')
            self.assertIsNone(detail['assessment_view']['decision'])
            self.assertEqual(detail['assessment_view']['status'],'legacy_display_only')
            self.assertEqual(before,{name:(case/name).read_bytes() for name in values})

    async def test_request_byte_budget_reports_unread_sources_and_preserves_neighbors(self):
        from paw.web import api
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); case=root/'case-fixture'; case.mkdir()
            (case/'manifest.json').write_text('{"created_utc":"source"}',encoding='utf-8')
            (case/'headers.json').write_text('{"subject":"literal"}',encoding='utf-8')
            async def completed(_directory): return 'incomplete'
            with patch.object(api,'CASES_DIR',root),patch.object(api,'stable_case_status',completed),patch.object(api,'ReadBudget',return_value=ReadBudget(bytes=30)):
                listing=await api.list_cases(limit=20,offset=0)
            self.assertIn('headers.json',listing['cases'][0]['artifact_errors'])
            self.assertEqual(listing['cases'][0]['created_at'],'source')


if __name__=='__main__': unittest.main()
