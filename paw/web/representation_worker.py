"""Bounded explicit forensic representations in a supervised process; no execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone
import sys

from paw.core.runtime import wait_for_gate, mark_stage, atomic_json
from paw.core.network_policy import offline_policy


def write_bytes(path, data):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    path.chmod(0o400)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request'); parser.add_argument('result'); args = parser.parse_args()
    request = json.loads(Path(args.request).read_bytes()); result = {'status': 'failed', 'analysis_kind': 'forensic_representations'}
    try:
        wait_for_gate()
        if os.name != 'posix': raise ValueError('forensic_runtime_requires_posix_limits')
        import resource
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        memory = min(256*1024**2, hard) if hard != resource.RLIM_INFINITY else 256*1024**2
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 11))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (80*1024**2, 80*1024**2))
        with offline_policy(True):
            from ..core import source_inspection as source
            from ..core.representation_graph import Graph, GraphLimits, text_view
            from ..core.mime_representations import populate_mime_graph
            from ..core.html_representation_observer import observe_html
            if set(request) != {'source', 'case_id', 'analysis_job', 'interpretation'}: raise ValueError('forensic_request_shape')
            if request['interpretation'] not in {'mime', 'html-utf8'}: raise ValueError('forensic_interpretation')
            identifier = request['case_id']
            if not isinstance(identifier, str) or not re.fullmatch(r'case-forensic-[0-9a-f]{32}', identifier):
                raise ValueError('forensic_case_identifier')
            if request['analysis_job'] != 'analysis_'+identifier[14:]: raise ValueError('forensic_job_binding')
            mark_stage('forensic_acquisition')
            limits = source.SourceLimits(input_bytes=8*1024**2)
            capture = source.acquire_source(request['source'], limits)
            case = Path.cwd()/'cases'/identifier
            case.parent.mkdir(mode=0o700, exist_ok=True); case.mkdir(mode=0o700)
            mark_stage('forensic_original', identifier)
            atomic_json(case/'execution.json', {'status': 'running', 'assessment_status': 'not_evaluated',
                        'sample_execution': 'not_performed', 'no_egress': True, 'analysis_kind': 'forensic_representations'})
            write_bytes(case/'source.bin', capture.raw)
            graph = Graph(capture.raw, GraphLimits(source_bytes=8*1024**2,
                          representation_bytes=24*1024**2, work_bytes=64*1024**2, nodes=64))
            atomic_json(case/'manifest.json', {'schema': 'paw-forensic-case-v1',
                        'case_id': identifier, 'case_kind': 'forensic_representations',
                        'analysis_job': request['analysis_job'], 'created_utc': datetime.now(timezone.utc).isoformat(),
                        'source_name': capture.display_name,
                        'source': {'path': 'source.bin', 'bytes': len(capture.raw), 'sha256': capture.sha256},
                        'representation_root': graph.root, 'requested_interpretation': request['interpretation'],
                        'classification': 'not_evaluated', 'execution_authority': 'none'})
            reports = {}; mark_stage('forensic_representations', identifier)
            if request['interpretation'] == 'mime':
                reports['mime'] = populate_mime_graph(graph)
                parents = []
                for row in reports['mime']['parts']:
                    if row.get('selected_content_type') != 'text/html': continue
                    parents.append((row.get('selected_text_node'), 'parser_selected', row['path']))
                    parents.extend((node, 'derived_candidate', row['path']) for node in row['candidate_text_nodes'])
            else: parents = [(text_view(graph, graph.root, 'utf-8'), 'requested_utf8', None)]
            reports['html'] = [dict(observe_html(graph, node), view_role=role, mime_part_path=path)
                               for node, role, path in parents if node]
            mark_stage('forensic_blobs', identifier); (case/'blobs').mkdir(mode=0o700)
            for digest, blob in graph.blobs.items():
                if hashlib.sha256(blob).hexdigest() != digest: raise ValueError('forensic_blob_hash')
                write_bytes(case/'blobs'/(digest+'.bin'), blob)
            (case/'report').mkdir(mode=0o700)
            record = graph.record()
            atomic_json(case/'report/representations.json', record)
            atomic_json(case/'report/interpretations.json', reports)
            # Every graph ID, blob digest, and exact original must survive disk
            # serialization before the existing PAW integrity/export functions.
            for node in record['nodes']:
                data = (case/node['blob_path']).read_bytes()
                if len(data) != node['bytes'] or hashlib.sha256(data).hexdigest() != node['sha256']:
                    raise ValueError('forensic_persisted_blob_changed')
            if (case/'source.bin').read_bytes() != capture.raw: raise ValueError('forensic_original_changed')
            partial = record['status'] == 'partial' or any(report.get('status') == 'partial' for report in reports['html']) or reports.get('mime', {}).get('status') == 'partial'
            atomic_json(case/'execution.json', {'status': 'completed', 'assessment_status': 'not_evaluated',
                        'sample_execution': 'not_performed', 'no_egress': True, 'analysis_kind': 'forensic_representations',
                        'coverage': 'partial' if partial else 'bounded_views_observed',
                        'limits': {'cpu_seconds': 10, 'address_space_bytes': memory,
                                   'network_isolation': 'application_policy_only',
                                   'graph': vars(graph.limits)}})
            mark_stage('forensic_sealing', identifier)
            from paw.core.evidence import seal_case
            from paw.core.verify import verify_case
            from paw.core.exporter import export_case
            seal_case(case)
            if not verify_case(case): raise ValueError('forensic_case_seal_failed')
            mark_stage('forensic_zip_export', identifier)
            archive = Path(export_case(case, 'zip'))
            if archive.stat().st_size > 80*1024**2: raise ValueError('forensic_export_budget')
            result = {'status': 'completed', 'analysis_kind': 'forensic_representations', 'case_id': identifier, 'case_ids': [identifier],
                      'source_sha256': capture.sha256, 'source_bytes': len(capture.raw),
                      'graph_nodes': len(record['nodes']), 'coverage': 'partial' if partial else 'bounded_views_observed',
                      'sample_execution': 'not_performed', 'classification': 'not_evaluated', 'zip': str(archive)}
            mark_stage('completed', identifier)
    except Exception as error:
        result = {'status': 'failed', 'analysis_kind': 'forensic_representations', 'error': type(error).__name__+':'+str(error)}
    atomic_json(args.result, result)
    return 0 if result['status'] == 'completed' else 1


if __name__ == '__main__': raise SystemExit(main())
