"""Bounded fork-budget probe; run in an explicitly limited transient unit."""
import json
from pathlib import Path
import subprocess

cg = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
limit = (Path('/sys/fs/cgroup') / cg.lstrip('/') / 'pids.max').read_text().strip()
if limit != '16':
    raise RuntimeError('Refusing fork test without the expected kernel task limit')
children = []
blocked = False
try:
    for _ in range(24):
        try:
            children.append(subprocess.Popen(['/bin/sleep', '5']))
        except BlockingIOError:
            blocked = True
            break
finally:
    for child in children:
        child.terminate()
    for child in children:
        child.wait(timeout=3)
assert blocked and len(children) < 24
assert all(child.returncode is not None for child in children)
print(json.dumps({'result': 'PASS', 'pids_max': limit, 'children_created': len(children),
                  'next_fork_blocked': blocked, 'children_stopped': True}))
