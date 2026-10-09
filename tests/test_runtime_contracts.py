"""Real process/resource failures; no mocked workers or network targets."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from paw.core.runtime import RunLimits, supervise, preserve_interrupted, atomic_json
from paw.core.verify import verify_case

REPO = Path(__file__).resolve().parents[1]
BOOT = 'from paw.core.runtime import wait_for_gate, mark_stage\nwait_for_gate()\n'

class RuntimeContracts(unittest.IsolatedAsyncioTestCase):
    async def run_process(self, source, root, limits, cancel=None):
        return await supervise([sys.executable,'-c',BOOT+source], cwd=root,
            control=root/'control', limits=limits, cancel=cancel, env={'PYTHONPATH':str(REPO)})

    async def test_overall_deadline_kills_actual_process_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = "import time; from pathlib import Path; p=Path('heartbeat');\nwhile True: p.write_text(str(time.time())); time.sleep(.03)"
            code = 'import subprocess, sys, time\nsubprocess.Popen([sys.executable,"-c",'+repr(child)+'])\nmark_stage("blocked")\ntime.sleep(30)'
            outcome = await self.run_process(code, root, RunLimits(wall_seconds=1, stage_seconds=10))
            self.assertEqual(outcome['status'],'timed_out')
            self.assertLess(outcome['elapsed_seconds'],5)
            before = (root/'heartbeat').read_bytes()
            await asyncio.sleep(.2)
            self.assertEqual((root/'heartbeat').read_bytes(), before)

    async def test_stage_deadline_interrupts_blocking_operation(self):
        with tempfile.TemporaryDirectory() as temp:
            outcome = await self.run_process('import time\nmark_stage("blocked_io")\ntime.sleep(30)', Path(temp), RunLimits(wall_seconds=10,stage_seconds=.2))
            self.assertEqual(outcome['status'],'timed_out')
            self.assertIn('blocked_io',outcome['error'])

    async def test_operator_cancellation_stops_running_process(self):
        with tempfile.TemporaryDirectory() as temp:
            root, cancel = Path(temp), asyncio.Event()
            task = asyncio.create_task(self.run_process('import time\nfrom pathlib import Path\nPath("ready").touch()\ntime.sleep(30)', root, RunLimits(), cancel))
            for _ in range(100):
                if (root/'ready').exists(): break
                await asyncio.sleep(.02)
            self.assertTrue((root/'ready').exists())
            cancel.set()
            self.assertEqual((await task)['status'],'cancelled')

    async def test_real_log_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            outcome = await self.run_process('import time\nprint("x"*4096, flush=True)\ntime.sleep(30)',Path(temp),RunLimits(log_bytes=1024))
            self.assertEqual(outcome['status'],'resource_limited')

    async def test_artifact_budget_preserves_real_partial_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = 'import time\nfrom pathlib import Path\np=Path("cases/case-budget"); p.mkdir(parents=True)\nmark_stage("writes","case-budget")\n(p/"input.eml").write_bytes(b"x"*4096)\ntime.sleep(30)'
            outcome = await self.run_process(source,root,RunLimits(artifact_bytes=1024))
            self.assertEqual(outcome['status'],'resource_limited')
            cases = preserve_interrupted(root,root/'control',outcome['status'],outcome['error'])
            self.assertEqual(cases[0]['integrity'],'sealed_partial')
            self.assertEqual((root/'cases/case-budget/input.eml').read_bytes(),b'x'*4096)
            self.assertTrue(verify_case(root/'cases/case-budget'))

    async def test_memory_limit_rejects_actual_large_allocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code = 'from pathlib import Path\ntry: data=bytearray(128*1024**2)\nexcept MemoryError: Path("memory_blocked").touch()'
            outcome = await self.run_process(code,root,RunLimits(memory_bytes=64*1024**2))
            self.assertEqual(outcome['status'],'exited')
            self.assertTrue((root/'memory_blocked').exists())

    async def test_truncated_index_is_resealed_as_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, control = root/'cases/case-partial', root/'control'
            (case/'evidence').mkdir(parents=True)
            control.mkdir()
            (case/'input.eml').write_bytes(b'Original preserved')
            atomic_json(case/'execution.json',{'status':'completed'})
            (case/'evidence/merkle_index.json').write_text('{')
            (case/'evidence/merkle_root.bin').write_text('incomplete')
            atomic_json(control/'progress.json',{'case_ids':['case-partial']})
            result = preserve_interrupted(root,control,'timed_out','Interrupted while sealing')
            self.assertEqual(result[0]['status'],'timed_out')
            self.assertTrue(verify_case(case))

    async def test_invalid_nonfinite_limits_rejected(self):
        for value in (0,-1,float('nan'),float('inf'),True):
            with self.assertRaises(ValueError): RunLimits(wall_seconds=value)

if __name__ == '__main__': unittest.main()
