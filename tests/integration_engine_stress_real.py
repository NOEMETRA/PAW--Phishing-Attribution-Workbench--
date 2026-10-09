"""Bounded real CLI workloads; constructed fixtures are not a labelled corpus.

Run from any directory. Requires psutil only for the external observer. No
mocked worker, network service, or analysis results. Every analysis is offline.
"""
import argparse
from email.message import EmailMessage
from email import policy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import psutil

REPO = Path(__file__).resolve().parents[1]


def message(body='Meeting at ten tomorrow. Thank you.', subject='Project meeting'):
    item = EmailMessage(policy=policy.SMTP)
    item['From'] = 'Colleague <colleague@example.org>'
    item['To'] = 'recipient@example.net'
    item['Subject'] = subject
    item['Date'] = 'Fri, 09 Oct 2026 10:00:00 +0000'
    item.set_content(body)
    return item


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else value.as_bytes())
    return path


def read(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def scenarios(root, suite):
    source = next((REPO/'inbox').glob('*.eml'))
    normal = save(root/'fixtures'/'normal.eml', message())
    result = []
    def add(name, path, count=1, command='full', **kwargs):
        result.append(dict(name=name, input=path, expected_count=count, command=command, **kwargs))
    if suite in {'all', 'batch'}:
        upper = root/'fixtures'/'mixed_extensions'
        save(upper/'a.eml', normal.read_bytes())
        save(upper/'b.EML', normal.read_bytes())
        save(upper/'c.EmL', normal.read_bytes())
        add('batch_mixed_extensions', upper, 3)
        broken = root/'fixtures'/'mixed_failure'
        save(broken/'a.eml', normal.read_bytes())
        save(broken/'b.eml', b'')
        save(broken/'c.eml', normal.read_bytes())
        add('batch_bad_middle', broken, 2, expected_failure=True)
        unsupported = root/'fixtures'/'mixed_msg'
        save(unsupported/'a.MSG', b'unsupported MSG fixture')
        save(unsupported/'b.eml', normal.read_bytes())
        add('batch_msg_first', unsupported, 1, expected_failure=True)
        add('batch_empty', root/'fixtures'/'empty', 0, expected_failure=True)
        (root/'fixtures'/'empty').mkdir(parents=True, exist_ok=True)
    if suite in {'all', 'loads'}:
        for index in range(3):
            add(f'original_repeat_{index+1}', source, provenance='original public repository EML; label not adjudicated')
        for command in ('quick', 'analyze', 'forensic', 'trace'):
            add('preset_'+command, normal, command=command)
        claim=message()
        claim['Authentication-Results']='untrusted.example; dkim=pass header.i=@example.org'
        add('auth_claim_without_d',save(root/'fixtures'/'auth_claim.eml',claim))
        for count in (5, 20, 50):
            directory = root/'fixtures'/f'batch_{count}'
            for index in range(count):
                save(directory/f'{index:03}.eml', message(subject=f'Project meeting {index}'))
            add(f'batch_{count}', directory, count, wall=120)
        for count in (100, 1000):
            item = save(root/'fixtures'/f'urls_{count}.eml', message('\n'.join(
                f'https://example.invalid/path/{index}' for index in range(count))))
            add(f'urls_{count}', item, expected_urls=count)
        for size in (512*1024, 1800*1024):
            # Repeated ordinary text is a real CPU/size workload, not a threat label.
            item = save(root/'fixtures'/f'text_{size}.eml', message(('Project notes. '*((size//15)+1))[:size]))
            add(f'text_{size}', item, allow_bounded_stop=True)
        many = message()
        for index in range(300):
            many.add_attachment(b'data', maintype='application', subtype='octet-stream', filename=f'item_{index}.bin')
        add('attachments_300', save(root/'fixtures'/'attachments_300.eml', many), expected_attachments=300)
        large = message()
        large.add_attachment(b'x'*(12*1024*1024), maintype='application', subtype='octet-stream', filename='large.bin')
        add('attachment_12MiB', save(root/'fixtures'/'attachment_12MiB.eml', large), expected_attachments=1)
        add('input_over_25MiB', save(root/'fixtures'/'oversize.eml', b'x'*(25*1024*1024+1)), 0, expected_failure=True)
        overparts = message()
        for index in range(500):
            overparts.add_attachment(b'x', maintype='application', subtype='octet-stream', filename=str(index))
        add('mime_over_500parts', save(root/'fixtures'/'overparts.eml', overparts), 0, expected_failure=True)
        add('empty_file', save(root/'fixtures'/'empty.eml', b''), 0, expected_failure=True)
    return result


def run(spec, root):
    directory = root/'runs'/spec['name']
    directory.mkdir(parents=True)
    wall = spec.get('wall', 60)
    command = [sys.executable, '-X', 'utf8', '-m', 'paw', spec['command']]
    command += ['--src', str(spec['input'])] if spec['command']=='trace' else [str(spec['input'])]
    if spec['command']!='quick': command += ['--no-egress']
    command += ['--deadline', str(wall), '--stage-timeout', '30', '--memory-mib', '512']
    environment = dict(os.environ, PYTHONPATH=str(REPO), PYTHONIOENCODING='utf-8')
    started = time.perf_counter()
    peak_rss = 0
    known = {}
    with (directory/'cli.log').open('wb') as stream:
        process = subprocess.Popen(command, cwd=directory, env=environment, stdout=stream, stderr=subprocess.STDOUT)
        parent = psutil.Process(process.pid)
        while process.poll() is None:
            rss = 0
            try: current = [parent]+parent.children(recursive=True)
            except psutil.Error: current=[]
            for child in current:
                try:
                    identity=(child.pid, child.create_time())
                    times=child.cpu_times()
                    known[identity]=max(known.get(identity,0),times.user+times.system)
                    rss += child.memory_info().rss
                except psutil.Error: pass
            peak_rss=max(peak_rss,rss)
            if time.perf_counter()-started > wall+20:
                process.kill()
                process.wait()
                raise RuntimeError('Outer harness deadline exceeded; inspect owned process tree before continuing')
            time.sleep(.05)
    cli_elapsed=time.perf_counter()-started
    controls=[path for path in (directory/'jobs').glob('analysis_*') if path.is_dir()]
    control=controls[0] if len(controls)==1 else directory/'absent'
    supervisor=read(control/'supervisor.json')
    result=read(control/'result.json')
    progress=read(control/'progress.json')
    cases=list((directory/'cases').glob('case-*'))
    from paw.core.verify import verify_case
    completed=[]
    for case in cases:
        execution=read(case/'execution.json')
        try: verified=verify_case(case)
        except Exception: verified=False
        completed.append(dict(case_id=case.name, status=execution.get('status'), integrity=verified,
            score=read(case/'report'/'score.json'), source_name=read(case/'manifest.json').get('source_name'),
            blocked_operations=execution.get('blocked_operations',[]),
            stage_timings=execution.get('observed_stage_timings',[]),
            input_sha256=hashlib.sha256((case/'input.eml').read_bytes()).hexdigest() if (case/'input.eml').exists() else None,
            url_count=len(read(case/'headers.json').get('urls',[])),
            attachment_count=len(read(case/'attachments.json')) if (case/'attachments.json').exists() else 0))
    residual=[]
    for pid, created in known:
        if pid==process.pid: continue
        try:
            if psutil.Process(pid).create_time()==created: residual.append(pid)
        except psutil.Error: pass
    observed=sum(item['status']=='completed' and item['integrity'] for item in completed)
    expected_failure=spec.get('expected_failure',False)
    checks=dict(tree_stopped=supervisor.get('tree_stopped') is True and not residual,
        completed_count=observed==spec['expected_count'],
        exit_semantics=process.returncode!=0 if expected_failure else process.returncode==0,
        integrity=all(item['integrity'] for item in completed),
        no_blocked_operations=all(not item['blocked_operations'] for item in completed))
    if observed:
        checks['input_provenance']=len(result.get('successful_inputs',[]))==observed and all(
            item['input'] and item['case_id'] in {case['case_id'] for case in completed if case['status']=='completed'}
            for item in result.get('successful_inputs',[]))
    if expected_failure and observed:
        checks['partial_batch']=result.get('status')=='partial' and bool(result.get('failed_inputs'))
    if not expected_failure and observed:
        checks['correlation_gap_visible']=all('campaign_correlation' in item['score'].get('coverage',{}).get('not_evaluated',[]) for item in completed)
    if spec['command'] in {'full','forensic'} and observed:
        checks['stix_gap_visible']=all(read(directory/'cases'/item['case_id']/'report'/'stix.json').get('status')=='unavailable' for item in completed)
    if spec.get('allow_bounded_stop') and supervisor.get('status') in {'timed_out','resource_limited'}:
        checks['completed_count']=observed in (0,1)
        checks['exit_semantics']=process.returncode!=0
    if 'expected_urls' in spec: checks['url_count']=len(completed)==1 and completed[0]['url_count']==spec['expected_urls']
    if 'expected_attachments' in spec: checks['attachment_count']=len(completed)==1 and completed[0]['attachment_count']==spec['expected_attachments']
    return dict(name=spec['name'], command=command, provenance=spec.get('provenance','constructed regression/load fixture; no corpus accuracy claim'),
        status='passed' if all(checks.values()) else 'failed', checks=checks,
        elapsed_seconds=round(time.perf_counter()-started,3), cli_elapsed_seconds=round(cli_elapsed,3), sampled_peak_tree_rss_bytes=peak_rss,
        sampled_tree_cpu_seconds=round(sum(known.values()),3), observer_interval_seconds=.05,
        exit_code=process.returncode, residual_pids=residual, supervisor=supervisor,
        worker_result=result, progress=progress, cases=completed,
        input_files=[dict(name=path.name,bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            for path in ([spec['input']] if spec['input'].is_file() else sorted(spec['input'].iterdir())) if path.is_file()],
        output_bytes=sum(path.stat().st_size for path in directory.rglob('*') if path.is_file()))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--suite',choices=['all','batch','loads'],default='all')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    root=REPO.parent/'paw-validation'/'engine_stress'/uuid.uuid4().hex
    root.mkdir(parents=True)
    output=args.output or root/'results.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    report=dict(suite=args.suite, data_directory=str(root), python=sys.version,
        network_scope='All real CLI analyses use no-egress; OS network containment not claimed',
        sampling_limit='CPU/RSS sampled at 50ms across CLI and descendants; short-lived processes may be missed; RSS sums shared pages',
        thresholds='wall 60s (batch 120s), stage 30s, worker tree memory 512MiB; outer harness wall+20s',runs=[])
    for spec in scenarios(root,args.suite):
        print('START '+spec['name'],flush=True)
        item=run(spec,root)
        report['runs'].append(item)
        output.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({key:item[key] for key in ('name','status','elapsed_seconds','sampled_peak_tree_rss_bytes','checks')}),flush=True)
    print('RESULTS '+str(output),flush=True)
    return 0 if all(item['status']=='passed' for item in report['runs']) else 1


if __name__=='__main__':
    sys.exit(main())
