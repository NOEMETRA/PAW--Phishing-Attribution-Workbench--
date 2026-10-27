"""Supervised bounded byte-source worker; never interprets or executes the input."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from paw.core.runtime import wait_for_gate, mark_stage, atomic_json, tighten_posix_limit
from paw.core.network_policy import offline_policy


def main():
    # This dedicated process must create private artifacts from the first byte,
    # even with an existing shared case store and a permissive caller umask.
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('request'); parser.add_argument('result')
    args = parser.parse_args(); request = json.loads(Path(args.request).read_bytes()); result = {'status': 'failed'}
    try:
        wait_for_gate()
        effective_memory = effective_cpu = effective_file = None
        if os.name == 'posix':
            import resource
            effective_memory, _ = tighten_posix_limit(resource.RLIMIT_AS, 256*1024**2)
            effective_cpu, _ = tighten_posix_limit(resource.RLIMIT_CPU, 10, 11)
            tighten_posix_limit(resource.RLIMIT_CORE, 0)
            effective_file, _ = tighten_posix_limit(resource.RLIMIT_FSIZE, 65*1024**2)
        with offline_policy(True):
            from ..core import source_inspection as module
            limits = module.SourceLimits(**request['source_limits'])
            mark_stage('source_acquisition'); captured = module.acquire_source(request['source'], limits)
            mark_stage('byte_observation'); report = module.inspect_capture(captured, limits=limits)
            identifier = request['case_id']
            if not identifier.startswith('case-source-') or len(identifier) != 44 or any(c not in '0123456789abcdef' for c in identifier[12:]):
                raise ValueError('source_case_identifier')
            analysis_job = request['analysis_job']
            if analysis_job != 'analysis_'+identifier[12:]: raise ValueError('source_job_binding')
            case = Path.cwd()/'cases'/identifier
            case.parent.mkdir(mode=0o700, exist_ok=True); case.mkdir(mode=0o700)
            mark_stage('source_evidence', identifier)
            atomic_json(case/'execution.json', {'status': 'running', 'analysis_kind': 'source_byte_observation',
                        'sample_execution': 'not_performed', 'assessment_status': 'not_evaluated', 'no_egress': True})
            atomic_json(case/'manifest.json', {'schema': 'paw-source-inspection-case-v1', 'case_id': identifier,
                        'analysis_job': analysis_job, 'created_utc': datetime.now(timezone.utc).isoformat(),
                        'source_name': captured.display_name, 'source': {'path': 'source.bin', 'bytes': len(captured.raw),
                        'sha256': captured.sha256}, 'case_kind': 'opaque_source_inspection', 'classification': 'not_evaluated'})
            with (case/'source.bin').open('xb') as stream:
                stream.write(captured.raw); stream.flush(); os.fsync(stream.fileno())
            (case/'source.bin').chmod(0o400)
            (case/'report').mkdir(mode=0o700); atomic_json(case/'report/source-inspection.json', report)
            if (case/'source.bin').read_bytes() != captured.raw: raise ValueError('source_case_copy_changed')
            atomic_json(case/'execution.json', {'status': 'completed', 'analysis_kind': 'source_byte_observation',
                        'sample_execution': 'not_performed', 'assessment_status': 'not_evaluated', 'no_egress': True,
                        'limits': {'source': asdict(limits), 'cpu_seconds': effective_cpu,
                                   'address_space_bytes': effective_memory, 'file_bytes': effective_file,
                                   'process_bounds': 'supervised_worker' if os.environ.get('PAW_START_GATE') else 'direct_posix_limits_only',
                                   'network_isolation': 'application_policy_only'}})
            mark_stage('source_sealing', identifier)
            from paw.core.evidence import seal_case
            from paw.core.verify import verify_case
            from paw.core.exporter import export_case
            seal_case(case)
            if not verify_case(case): raise ValueError('source_case_integrity_failed')
            mark_stage('source_zip_export', identifier); archive = Path(export_case(case, 'zip'))
            if archive.stat().st_size > 65*1024**2: raise ValueError('source_zip_output_budget')
            # A valid seal is content integrity, not input authenticity or a
            # finding that an unknown source was fully interpreted or safe.
            result = {'status': 'completed', 'case_id': identifier, 'case_ids': [identifier], 'source_sha256': captured.sha256,
                      'source_bytes': len(captured.raw), 'zip': str(archive), 'sample_execution': 'not_performed',
                      'classification': 'not_evaluated', 'analysis_kind': 'source_byte_observation'}
            mark_stage('completed', identifier)
    except Exception as error:
        result = {'status': 'failed', 'error': type(error).__name__+':'+str(error), 'analysis_kind': 'source_byte_observation'}
    atomic_json(args.result, result)
    return 0 if result['status'] == 'completed' else 1


if __name__ == '__main__': raise SystemExit(main())
