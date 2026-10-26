"""Owned process cancel/deadline/worker-loss for forensic cases; no VM or input execution."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import uuid

import psutil

REPO = Path(__file__).resolve().parents[1]


async def one(workspace, source, mode, env):
    from paw.core.runtime import RunLimits, atomic_json, supervise, read_progress, preserve_interrupted
    from paw.core.verify import verify_case
    from paw.core.job_registry import require_stopped_case
    from paw.core.process_recovery import process_identity
    output = workspace/mode; output.mkdir(mode=0o700)
    token = uuid.uuid4().hex; identifier = 'case-forensic-'+token; job_id = 'analysis_'+token
    control = output/'jobs'/job_id; control.mkdir(mode=0o700, parents=True)
    state = output/'jobs'/(job_id+'.json')
    job = {'origin': 'cli', 'kind': 'forensic_representations', 'status': 'running',
           'supervisor_owner': process_identity(os.getpid(), dedicated_group=False)}
    atomic_json(state, job)
    atomic_json(control/'request.json', {'source': str(source), 'case_id': identifier,
                                       'analysis_job': job_id, 'interpretation': 'mime'})
    cancel = asyncio.Event()
    task = asyncio.create_task(supervise([sys.executable, '-P', '-B', '-m', 'paw.web.representation_worker',
        str(control/'request.json'), str(control/'result.json')], cwd=output, control=control, cancel=cancel, env=env,
        limits=RunLimits(wall_seconds=10, stage_seconds=1 if mode == 'deadline' else 5,
                         memory_bytes=256*1024**2, artifact_bytes=96*1024**2, artifact_files=160, log_bytes=128*1024)))
    stopped = None
    try:
        end = time.monotonic()+5
        while time.monotonic() < end:
            assert not task.done(), 'Worker ended before owned fault injection: '+mode
            if read_progress(control/'progress.json').get('stage') == 'forensic_representations':
                identity = read_progress(control/'process.json'); pid = identity['pid']; process = psutil.Process(pid)
                assert process.ppid() == os.getpid() and os.getpgid(pid) == pid
                assert process.create_time() == identity['created_at']
                os.kill(pid, signal.SIGSTOP); stopped = pid; break
            await asyncio.sleep(.002)
        assert stopped is not None, 'Owned fault stage not reached: '+mode
        case = output/'cases'/identifier
        assert (case/'source.bin').read_bytes() == source.read_bytes()
        try: require_stopped_case(case)
        except RuntimeError: pass
        else: raise AssertionError('Live forensic case was exposed before known stop')
        if mode == 'cancel': cancel.set()
        if mode == 'worker-loss': os.kill(stopped, signal.SIGKILL)
        outcome = await task
    finally:
        if not task.done(): cancel.set(); await task
    assert outcome['tree_stopped'] is True
    assert outcome['status'] == {'cancel': 'cancelled', 'deadline': 'timed_out', 'worker-loss': 'exited'}[mode], outcome
    if mode == 'worker-loss': assert outcome['returncode'] == -signal.SIGKILL
    status = 'failed' if mode == 'worker-loss' else outcome['status']
    partial = preserve_interrupted(output, control, status, 'Owned '+mode+' fixture')
    job.update(status=status, supervisor=outcome, partial_cases=partial); atomic_json(state, job)
    assert len(partial) == 1 and partial[0]['integrity'] == 'sealed_partial'
    assert verify_case(case); require_stopped_case(case)
    execution = read_progress(case/'execution.json')
    assert execution['assessment_status'] == 'partial' and execution['status'] != 'completed'
    assert not psutil.pid_exists(stopped)
    return {'mode': mode, 'status': 'PASS', 'outcome': outcome, 'partial': partial,
            'known_stopped': True, 'partial_seal_verified': True, 'source_copy_exact': True}


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed', action='store_true'); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    assert os.name == 'posix', 'Forensic fault acceptance requires POSIX controls'
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    if not args.installed:
        env['PYTHONPATH'] = str(REPO); sys.path.insert(0, str(REPO))
    import paw
    if args.installed:
        assert Path(paw.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        assert not Path(paw.__file__).resolve().is_relative_to(REPO)
    workspace = args.output.absolute() if args.output else Path(tempfile.mkdtemp(prefix='paw-forensic-faults-'))
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = workspace/'owned-long-qp.eml'
    raw = b'Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n'+b'='*(4*1024**2)
    with source.open('xb') as stream: stream.write(raw)
    source.chmod(0o400); digest = hashlib.sha256(raw).hexdigest()
    results = [await one(workspace, source, mode, env) for mode in ('cancel', 'deadline', 'worker-loss')]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    evidence = {'schema': 'paw-forensic-fault-acceptance-v1', 'status': 'PASS', 'installed': args.installed,
                'source_sha256': digest, 'results': results, 'root_used': False, 'vm_used': False, 'sample_execution': 'not_performed'}
    (workspace/'results.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps({'status': 'PASS', 'owned_faults': len(results), 'results': str(workspace/'results.json')}))


if __name__ == '__main__': asyncio.run(main())
