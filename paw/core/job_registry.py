"""Common case ownership for CLI/API and conservative legacy control discovery."""
from pathlib import Path
from .runtime import read_progress


def validate_job_id(identifier):
    if not isinstance(identifier,str) or not identifier.startswith('analysis_') or not identifier[9:].isalnum():
        raise ValueError('Invalid analysis ID')
    return identifier


def control_path(data_dir, jobs_dir, identifier):
    validate_job_id(identifier)
    current = Path(jobs_dir)/identifier
    legacy = Path(data_dir)/'.paw-jobs'/identifier[9:]
    if not current.exists() and legacy.is_dir(): return legacy
    return current


def controls(data_dir, jobs_dir):
    for directory in Path(jobs_dir).glob('analysis_*'):
        if directory.is_dir() and directory.name[9:].isalnum():
            yield directory.name,directory
    for directory in (Path(data_dir)/'.paw-jobs').glob('*'):
        if directory.is_dir() and directory.name.isalnum():
            yield 'analysis_'+directory.name,directory


def case_owner(directory, data_dir, jobs_dir):
    identifier = read_progress(Path(directory)/'manifest.json').get('analysis_job')
    if identifier: return validate_job_id(identifier)
    for identifier,control in controls(data_dir,jobs_dir):
        if Path(directory).name in read_progress(control/'progress.json').get('case_ids',[]):
            return identifier
    return None


def job_state(data_dir, jobs_dir, identifier):
    validate_job_id(identifier)
    state = Path(jobs_dir)/(identifier+'.json')
    job = {}
    if state.exists():
        job = read_progress(state)
        if job.get('origin') != 'legacy_cli': return job
    control = control_path(data_dir,jobs_dir,identifier)
    if not control.is_dir(): raise FileNotFoundError(identifier)
    # Old CLI controls have no job state or recorded supervisor identity. Discover
    # them, but never kill a potentially live CLI to make its files readable.
    # Synthesized API state is only a discovery cache. Old CLI supervisors do not
    # update that cache, so always consult their current shutdown acknowledgment.
    job.update(origin='legacy_cli',status='recovery_blocked')
    outcome = read_progress(control/'supervisor.json')
    job['supervisor'] = outcome
    if outcome.get('tree_stopped') is True:
        result = read_progress(control/'result.json')
        if outcome.get('status') == 'exited' and outcome.get('returncode') == 0 and result.get('status') == 'completed':
            job.update(result)
            job.pop('error',None)
            job.pop('partial_cases',None)
        else:
            job.update(status='interrupted',error='Legacy CLI worker stopped')
    return job


def require_stopped_case(directory):
    """Read-only guard for CLI verify/export; internal worker checks remain local."""
    directory = Path(directory).resolve()
    data_dir = directory.parent.parent if directory.parent.name == 'cases' else directory.parent
    identifier = case_owner(directory,data_dir,data_dir/'jobs')
    if identifier:
        control = control_path(data_dir,data_dir/'jobs',identifier)
        job = job_state(data_dir,data_dir/'jobs',identifier)
        if (read_progress(control/'supervisor.json').get('tree_stopped') is not True
                or job.get('status') in {'running','queued','recovery_blocked'}):
            raise RuntimeError('Worker shutdown not confirmed; evidence access blocked')
