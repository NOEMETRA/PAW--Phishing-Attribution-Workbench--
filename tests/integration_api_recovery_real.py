"""Real API readers on deliberately interrupted local artifacts; no fake engine."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(repo))
from paw.web import api
from paw.core.runtime import atomic_json, preserve_interrupted
from paw.core.verify import verify_case

async def main():
    with tempfile.TemporaryDirectory(dir=repo.parent) as temp:
        root = Path(temp)
        api.CASES_DIR, api.JOBS_DIR = root/'cases', root/'jobs'
        api.JOBS_DIR.mkdir()
        case = api.CASES_DIR/'case-recovery'
        (case/'evidence').mkdir(parents=True)
        (case/'report').mkdir()
        job_id = 'analysis_recovery'
        atomic_json(case/'manifest.json',{'analysis_job':job_id})
        (case/'input.eml').write_bytes(next((repo/'inbox').glob('*.eml')).read_bytes())
        atomic_json(case/'execution.json',{'status':'completed'})
        (case/'evidence/merkle_index.json').write_text('{')
        (case/'evidence/merkle_root.bin').write_text('truncated')
        (case/'report/score.json').write_text('{')
        atomic_json(api.JOBS_DIR/(job_id+'.json'),{'status':'running'})
        control = api.JOBS_DIR/job_id
        control.mkdir()
        # These deliberately truncated files have no live worker. Declare the
        # fixture's stopped state; real crash/kill recovery has its own contracts.
        atomic_json(control/'supervisor.json',{'tree_stopped':True})
        atomic_json(control/'progress.json',{'case_ids':[case.name]})
        job = await api.get_analysis_status(job_id)
        assert job['status'] == 'interrupted'
        listing = await api.list_cases()
        assert listing['cases'][0]['status'] == 'interrupted'
        detail = await api.get_case_detail(case.name)
        assert detail['status'] == 'interrupted'
        assert detail['execution']['status'] == 'interrupted'
        assert detail['score'] is None and 'score.json' in detail['artifact_errors']
        assert (case/'report/score.json').read_bytes() == b'{'
        # Recover a stopped worker: damaged artifacts remain original bytes in the partial seal.
        atomic_json(control/'progress.json',{'case_ids':[case.name]})
        recovered = preserve_interrupted(root,control,'interrupted','Stopped while sealing')
        assert recovered[0]['integrity'] == 'sealed_partial'
        assert verify_case(case)
        assert (case/'report/score.json').read_bytes() == b'{'
        # Damage to a manifest must not make the entire case list inaccessible.
        (case/'manifest.json').write_text('{')
        listing = await api.list_cases()
        assert listing['cases'][0]['status'] == 'interrupted'
        assert 'manifest.json' in listing['cases'][0]['artifact_errors']
        report = {'status':'passed', 'scope':'Actual API functions on interrupted local artifact bytes',
            'restart_does_not_publish_preseal_completion':True,
            'truncated_json_does_not_block_case_list_or_detail':True,
            'partial_evidence_resealed_without_rewriting_damaged_artifacts':True}
        output = repo.parent/'paw-validation/real_api_recovery_results.json'
        output.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2))

asyncio.run(main())
