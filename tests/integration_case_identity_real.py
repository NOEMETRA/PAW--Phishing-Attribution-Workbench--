"""Real supervised offline worker with controlled identity collisions, not fake analyses."""
import asyncio
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.runtime import RunLimits, supervise
from paw.core.verify import verify_case


def read(path): return json.loads(path.read_text(encoding='utf-8'))


async def run(root, identifiers, partial=False):
    inputs=root/'inputs'; inputs.mkdir(parents=True)
    samples={'a.eml':b'From: a@example.com\r\nSubject: First original\r\n\r\nfirst bytes',
             'b.eml':b'From: b@example.com\r\nSubject: Second original\r\n\r\nsecond bytes'}
    for name,raw in samples.items(): (inputs/name).write_bytes(raw)
    request,result=root/'request.json',root/'result.json'
    request.write_text(json.dumps({'file_path':str(inputs),'no_egress':True,
        'lang':'en','stix':False,'abuse':False,'anchor':False,'profile':'default'}),encoding='utf-8')
    # Control only the two identity inputs. Parsing, analysis, policy, indexing,
    # process supervision and sealing all execute their real production code.
    source="""import sys
from types import SimpleNamespace
from uuid import UUID
from paw.core.runtime import wait_for_gate
wait_for_gate()
from paw.core import trace
identifiers=iter(%r)
trace.uuid=SimpleNamespace(uuid4=lambda:UUID(next(identifiers)))
trace.utc_now_iso=lambda:'2026-10-10T00:00:00Z'
from paw.web.worker import main
sys.argv=['worker',%r,%r]
sys.exit(main())
""" % (identifiers,str(request),str(result))
    outcome=await supervise([sys.executable,'-X','utf8','-c',source],cwd=root,
        control=root/'control',limits=RunLimits(wall_seconds=120,stage_seconds=60,memory_bytes=1024**3),
        env={'PYTHONPATH':str(REPO),'PYTHONDONTWRITEBYTECODE':'1','PYTHONUTF8':'1'})
    assert outcome['status']=='exited',outcome
    value=read(result)
    cases=list((root/'cases').glob('case-*'))
    if partial:
        assert outcome['returncode']==1 and value['status']=='partial',value
        assert len(cases)==1 and len(value['case_ids'])==1,value
        assert value['successful_inputs']==[{'input':'a.eml','case_id':cases[0].name}],value
        assert value['failed_inputs'][0]['input']=='b.eml',value
        assert 'FileExistsError' in value['failed_inputs'][0]['error'],value
        names={'a.eml'}
    else:
        assert outcome['returncode']==0 and value['status']=='completed',value
        assert len(cases)==len(set(value['case_ids']))==len(samples),value
        names=set(samples)
    observed=set()
    for case in cases:
        manifest=read(case/'manifest.json'); name=manifest['source_name']; observed.add(name)
        assert (case/'input.eml').read_bytes()==samples[name]
        assert verify_case(str(case)) and read(case/'execution.json')['no_egress'] is True
        assert len(manifest['case_id'].rsplit('Z-',1)[1])==32
    assert observed==names
    with closing(sqlite3.connect(root/'cases/index.db')) as conn:
        rows=conn.execute('SELECT id FROM cases').fetchall()
    assert len(rows)==len(cases) and len(set(rows))==len(cases)


def main():
    first='abcd0000000000000000000000000001'
    second='abcd0000000000000000000000000002'
    with tempfile.TemporaryDirectory(prefix='paw-case-identity-',dir=REPO.parent) as temporary:
        root=Path(temporary)
        asyncio.run(run(root/'shared-prefix',[first,second]))
        asyncio.run(run(root/'exact-collision',[first,first],partial=True))
    print('PASS: actual supervised offline workers preserve both same-second/shared-prefix inputs; exact collision fails partially before overwriting the first sealed case, with honest accounting and unique index rows. Only identity generation is controlled.')


if __name__=='__main__': main()
