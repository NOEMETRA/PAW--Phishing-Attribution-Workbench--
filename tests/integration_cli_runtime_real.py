"""Actual CLI processes: offline success and an enforced short deadline."""
import json
import os
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[1]
root = repo.parent/'paw-validation'
data = root/'real_cli_runtime_run'
data.mkdir(parents=True, exist_ok=True)
source = next((repo/'inbox').glob('*.eml'))
env = dict(os.environ, PYTHONPATH=str(repo), PYTHONIOENCODING='utf-8', PYTHONPYCACHEPREFIX=str(root/'pycache'))
checks = []
for deadline, expected in ((30,'exited'),(.05,'timed_out')):
    before = set((data/'jobs').glob('analysis_*'))
    command = [sys.executable,'-X','utf8','-m','paw','full',str(source),'--no-egress',
        '--deadline',str(deadline),'--stage-timeout','10']
    process = subprocess.run(command,cwd=data,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45)
    control, = {path for path in (data/'jobs').glob('analysis_*') if path.is_dir()} - before
    (control/'cli.log').write_bytes(process.stdout)
    outcome = json.loads((control/'supervisor.json').read_text())
    assert outcome['status'] == expected and outcome['tree_stopped'], outcome
    assert process.returncode == (0 if expected == 'exited' else 1)
    if expected == 'exited':
        result = json.loads((control/'result.json').read_text())
        assert result['status'] == 'completed'
        execution = json.loads((data/'cases'/result['case_ids'][0]/'execution.json').read_text())
        assert execution['no_egress'] and not execution['blocked_operations']
    checks.append({'flow':'Actual full CLI with no-egress','deadline':deadline,'status':'passed','supervisor':outcome})
(root/'real_cli_runtime_results.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
print(json.dumps(checks,indent=2))
