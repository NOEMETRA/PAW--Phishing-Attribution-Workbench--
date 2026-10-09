"""Real Chromium under the same process/memory supervisor as analysis jobs."""
import asyncio
import json
from pathlib import Path
import sys
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(repo))
from paw.core.runtime import RunLimits, supervise
root = repo.parent/'paw-validation'
data = root/'real_browser_run'
data.mkdir(parents=True, exist_ok=True)
result = asyncio.run(supervise([sys.executable,'-X','utf8',str(repo/'tests/integration_browser_real.py')],
    cwd=data, control=root/'browser_supervisor', limits=RunLimits(wall_seconds=60,stage_seconds=45),
    env={'PYTHONPATH':str(repo),'PAW_VERIFICATION_DIR':str(root)}))
assert result['status'] == 'exited' and result['returncode'] == 0 and result['tree_stopped'], result
result['browser_results'] = json.loads((root/'real_browser_results.json').read_text())
(root/'real_supervised_browser_results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
