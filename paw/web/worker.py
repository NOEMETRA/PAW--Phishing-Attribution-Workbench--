"""One real analysis per process; logs and results have separate files."""
import argparse
import json
from pathlib import Path
import sys
from ..core.network_policy import offline_policy
from ..core.runtime import wait_for_gate, mark_stage
from ..core.batch import BatchAnalysisError


def successful_inputs(paths):
    return [{'input':json.loads((Path(path)/'manifest.json').read_text(encoding='utf-8')).get('source_name'),
             'case_id':Path(path).name} for path in paths]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('request')
    parser.add_argument('result')
    args = parser.parse_args()
    request = json.loads(Path(args.request).read_text(encoding='utf-8'))
    try:
        wait_for_gate()
        mark_stage('imports')
        with offline_policy(request['no_egress']):
            from ..core.trace import trace_sources
            from ..core.verify import verify_case
            paths = trace_sources(request['file_path'], request.get('lang', 'en'),
                request.get('stix', True), request.get('abuse', True),
                request.get('anchor', False), request['no_egress'], request['profile'], request.get('deob_weight', .30))
            if not paths or not all(verify_case(path) for path in paths):
                raise RuntimeError('Analysis did not produce verifiable evidence')
            result = {'status': 'completed', 'case_ids': [Path(p).name for p in paths],
                      'successful_inputs':successful_inputs(paths)}
            mark_stage('completed')
    except BatchAnalysisError as exc:
        from ..core.verify import verify_case
        verified = []
        failures = list(exc.failures)
        for path in exc.case_paths:
            try:
                if not verify_case(path): raise RuntimeError('Evidence verification failed')
                verified.append(Path(path).name)
            except Exception as error:
                failures.append({'case_id':Path(path).name, 'error':f'{type(error).__name__}: {error}'})
        result = {'status':'partial' if verified else 'failed', 'case_ids':verified,
                  'error':str(exc), 'failed_inputs':failures, 'selected_inputs':exc.inputs,
                  'successful_inputs':successful_inputs([path for path in exc.case_paths if Path(path).name in verified])}
    except Exception as exc:
        result = {'status': 'failed', 'error': f'{type(exc).__name__}: {exc}'}
    Path(args.result).write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 0 if result['status'] == 'completed' else 1

if __name__ == '__main__':
    sys.exit(main())
