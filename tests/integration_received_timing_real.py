"""Full offline CLI verifies temporal descriptions, numeric parity and seals."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
DAY = 'Wed, 8 Oct 2025 '


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    cases = {
        'single':([DAY+'10:00:00 +0000'],[None]),
        'equal':([DAY+'10:00:00 +0000']*2,[None,0]),
        'forward':([DAY+'10:00:00 +0000',DAY+'10:00:03 +0000'],[None,3]),
        'long-delay':([DAY+'10:00:00 +0000',DAY+'14:00:00 +0000'],[None,14400]),
        'backward':([DAY+'10:00:00 +0000',DAY+'09:00:00 +0000'],[None,-3600]),
        'missing-middle':([DAY+'10:00:00 +0000',None,DAY+'12:00:00 +0000'],[None,None,None]),
        'backward-across-gap':([DAY+'10:00:00 +0000',None,DAY+'09:00:00 +0000'],[None,None,None]),
        'recovered-adjacency':([DAY+'10:00:00 +0000',None,DAY+'12:00:00 +0000',DAY+'12:00:01 +0000'],[None,None,None,1]),
        'offsets':([DAY+'08:00:00 +0000',DAY+'10:00:00 +0200'],[None,0]),
        'naive':([DAY+'10:00:00 +0000',DAY+'12:00:00'],[None,None]),
        'unknown-zone':([DAY+'10:00:00 +0000',DAY+'12:00:00 -0000'],[None,None]),
        'invalid':([DAY+'10:00:00 +0000','not a date'],[None,None]),
        'future':(['Wed, 8 Oct 2099 10:00:00 +0000'],[None]),
        'absent':([] ,[]),
    }
    samples = {}
    for name,(dates,_) in cases.items():
        headers = []
        for position,date in enumerate(dates):
            by = 'mx.protection.outlook.com' if position==len(dates)-1 else 'relay.example'
            headers.append('Received: from sender.example (8.8.8.8) by '+by+('; '+date if date else ''))
        samples[name+'.eml'] = ('From: a@example.invalid\r\nSubject: Constructed timing contract\r\n'+
                               ''.join(line+'\r\n' for line in reversed(headers))+'\r\nhello').encode()
    with tempfile.TemporaryDirectory(prefix='paw-timing-',dir=REPO.parent) as temporary:
        root = Path(temporary)
        inputs = root/'inputs'
        inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        execution = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        assert execution.returncode==0,(execution.stdout+execution.stderr).decode(errors='replace')
        assert b'Suspicious relay chain detected' not in execution.stdout
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        from paw.core.header_forgery import analyze_received_anomalies
        seen = set()
        for case in (root/'cases').glob('case-*'):
            filename = read(case/'manifest.json')['source_name']
            name = Path(filename).stem
            dates,deltas = cases[name]
            assert (case/'input.eml').read_bytes()==samples[filename]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            path,origin,anomalies,score,coverage = [read(case/file) for file in (
                'received_path.json','origin.json','received_anomalies.json','report/score.json','analysis_coverage.json')]
            hops = path['ordered_hops']
            assert path['received_schema_version']==3
            assert [hop['skew_s'] for hop in hops]==deltas,(name,hops)
            assert [hop['header_index'] for hop in hops]==list(reversed(range(len(dates))))
            timing = anomalies['timing_observations']
            assert analyze_received_anomalies(hops,reference_time=timing['reference_time'])==anomalies
            assert timing['verified'] is False and timing['interpretation_status']=='not_evaluated'
            assert anomalies['suspicious_relay_chain'] is None
            assert anomalies['timestamp_manipulation'] is None
            assert anomalies['impossible_negative_skew'] is None
            assert not {'suspicious_relay_chain','timestamp_manipulation'} & set(anomalies['spoofing_patterns'])
            assert len(timing['adjacent_pairs'])==max(0,len(dates)-1)
            assert coverage['stages']['received_timing']['status']==timing['status']
            assert coverage['stages']['received_timing']['interpretation_status']=='not_evaluated'
            assert score['score_components']['received_non_monotonic_dates']==0
            assert score['score_components']['header_observations']==0
            assert score['raw_score']==.05,(name,score)
            if dates:
                assert origin['received_header_index']==0
                assert origin['skew_s']==deltas[-1]
                assert origin['timing_observation']==hops[-1]['timing_observation']
                assert origin['verified'] is False
            else:
                assert origin['skew_s'] is None
            if name=='backward': assert anomalies['non_monotonic_dates'] is True
            if name=='backward-across-gap': assert anomalies['non_monotonic_dates'] is None
            if name=='recovered-adjacency': assert timing['comparison_status']=='partial'
            if name=='future': assert timing['timestamps'][0]['after_reference'] is True
            seen.add(name)
        assert seen==set(cases)
        print('PASS: 14 real full --no-egress timing cases; adjacent claims, missing/naive gaps, neutral relay observations, zero timestamp risk, valid bytes/seals')


if __name__ == '__main__':
    main()
