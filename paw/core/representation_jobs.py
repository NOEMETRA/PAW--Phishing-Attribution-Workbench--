"""Supervised explicit representation analysis using existing evidence/job contracts."""
import asyncio
import contextlib
import os
from pathlib import Path
import sys
import uuid

from paw.core.runtime import RunLimits, atomic_json, supervise, read_progress, preserve_interrupted
from paw.core.process_recovery import process_identity

REPRESENTATION_RUN_LIMITS = RunLimits(wall_seconds=45, stage_seconds=15, memory_bytes=256*1024**2,
                             artifact_bytes=96*1024**2, artifact_files=160, log_bytes=128*1024)

def inspect_representations(source, workspace, interpretation):
    if interpretation not in {'mime', 'html-utf8'}: raise ValueError('forensic_interpretation_required')
    from . import source_inspection as module
    source = module.admit_path(source).absolute()
    workspace = Path(workspace).absolute(); workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    identifier = uuid.uuid4().hex; case_id = 'case-forensic-'+identifier
    analysis_id = 'analysis_'+identifier
    control = workspace/'jobs'/analysis_id; control.mkdir(mode=0o700, parents=True)
    state = workspace/'jobs'/(analysis_id+'.json')
    job = {'origin': 'cli', 'kind': 'forensic_representations', 'status': 'running',
           'no_egress': True, 'assessment_status': 'not_evaluated', 'filename': source.name,
           'supervisor_owner': process_identity(os.getpid(), dedicated_group=False)}
    atomic_json(state, job)
    request, result = control/'request.json', control/'result.json'
    limits = REPRESENTATION_RUN_LIMITS
    value = {}; complete = False; interrupted = False
    try:
        atomic_json(request, {'source': str(source), 'case_id': case_id, 'analysis_job': analysis_id,
                             'interpretation': interpretation})
        outcome = asyncio.run(supervise([sys.executable, '-P', '-B', '-m', 'paw.web.representation_worker', str(request), str(result)], cwd=workspace, control=control, limits=limits,
            env={'PYTHONPATH': str(Path(__file__).resolve().parents[2])}))
        value = read_progress(result)
        complete = outcome['status'] == 'exited' and outcome['returncode'] == 0 and outcome['tree_stopped'] is True and value.get('status') == 'completed'
        if complete: job.update(status='completed', case_ids=[case_id])
        else: job.update(status='failed' if outcome['status'] == 'exited' else outcome['status'],
                         error=value.get('error') or outcome.get('error') or 'Forensic worker did not complete')
    except KeyboardInterrupt:
        interrupted = True; job.update(status='cancelled', error='Forensic CLI interrupted by operator')
    except Exception as error:
        job.update(status='failed', error=type(error).__name__+':'+str(error))
    finally:
        outcome = read_progress(control/'supervisor.json'); job['supervisor'] = outcome
        if not complete:
            # Existing integrity helpers emit diagnostics; keep the
            # CLI's machine-readable stdout to one JSON result on interrupts too.
            with contextlib.redirect_stdout(sys.stderr):
                job['partial_cases'] = preserve_interrupted(workspace, control, job['status'], job.get('error'))
            value.update(status=job['status'], error=job.get('error'), partial_cases=job['partial_cases'])
        atomic_json(state, job)
    return {'returncode': 0 if complete else (130 if interrupted else 1), 'analysis_id': analysis_id, 'supervisor': outcome,
                      'worker': value, 'control': str(control), 'job_state': str(state)}
