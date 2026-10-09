"""Real supervised offline Received evidence; constructed messages are not labels."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
DATE = '; Wed, 8 Oct 2025 10:00:00 +0000'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    lines = {'ipv6':('from sender.example (IPv6:2001:4860:4860::8888) by mx.example (192.0.2.10) with ESMTP id 203.0.113.17','2001:4860:4860::8888'),
             'receiver-only':('from sender.example by mx.example (8.8.8.8)',None),
             'queue-only':('from sender.example by mx.example id 8.8.8.8',None),
             'ambiguous':('from sender.example (8.8.8.8 [9.9.9.9]) by mx.example',None),
             'mapped':('from [IPv6:::ffff:192.0.2.5] by mx.example','::ffff:192.0.2.5'),
             'loopback':('from relay.outlook.com (127.0.0.1) by mx.outlook.com','127.0.0.1'),
             'private':('from sender.example (10.0.0.1) by mx.example','10.0.0.1'),
             'link-local':('from sender.example ([IPv6:fe80::1]) by mx.example','fe80::1'),
             'single-label':('from sender.example by MAILBOX01',None),
             'literal-by':('from sender.example by [IPv6:2001:db8::1]',None),
             'missing-from':('by mx.example (8.8.8.8)',None),
             'comment-keywords':('(by fake.example) from sender.example (comment; by fake.example [8.8.8.8]) by mx.example','8.8.8.8')}
    base = b'From: a@example.invalid\r\nSubject: Constructed Received contract\r\n'
    samples = {name+'.eml':base+b'Received: '+(line+DATE).encode()+b'\r\n\r\nhello'
               for name,(line,_) in lines.items()}
    with tempfile.TemporaryDirectory(prefix='paw-received-',dir=REPO.parent) as temporary:
        root = Path(temporary)
        inputs = root/'inputs'
        inputs.mkdir()
        for name,raw in samples.items():
            (inputs/name).write_bytes(raw)
        env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        result = subprocess.run([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=150)
        if result.returncode:
            diagnostics = {str(file.relative_to(root)):read(file) for file in root.rglob('result.json')}
            raise AssertionError((result.stdout+result.stderr).decode(errors='replace')+'\n'+json.dumps(diagnostics))
        sys.path.insert(0,str(REPO))
        from paw.core.verify import verify_case
        seen = set()
        for case in (root/'cases').glob('case-*'):
            filename = read(case/'manifest.json')['source_name']
            name = Path(filename).stem
            expected = lines[name][1]
            assert (case/'input.eml').read_bytes() == samples[filename]
            assert verify_case(str(case))
            assert read(case/'execution.json')['no_egress'] is True
            path,origin,anomalies,score,coverage = [read(case/file) for file in (
                'received_path.json','origin.json','received_anomalies.json','report/score.json','analysis_coverage.json')]
            assert path['received_schema_version'] == 2
            value, = path['ordered_hops']
            assert value['raw'] == lines[name][0]+DATE
            assert value['ip_observation']['verified'] is False
            assert anomalies['private_ip_before_boundary'] is None
            assert anomalies['receiver_boundary']['status'] == 'not_evaluated'
            assert origin['verified'] is False
            assert coverage['stages']['received_path']['receiver_boundary'] == anomalies['receiver_boundary']
            assert score['score_components']['received_private_ip_before_boundary'] == 0
            assert score['score_components']['received_invalid_fqdn'] == 0
            assert score['score_components']['verified_authentication_failures'] == 0
            assert score['profile'] == 'strict'
            assert score['raw_score'] == .05,(name,score['score_components'])
            if expected:
                assert ipaddress.ip_address(value['ip']) == ipaddress.ip_address(expected)
                assert ipaddress.ip_address(origin['ip']) == ipaddress.ip_address(expected)
                assert origin['ip_observation'] == value['ip_observation']
                assert origin['received_header_index'] == value['header_index']
            else:
                assert value['ip'] is None
                assert not origin['ip']
            for candidate in value['ip_candidates']:
                assert value['raw'][slice(*candidate['source_span'])] == candidate['text']
                assert candidate['verified'] is False
            seen.add(name)
        assert seen == set(lines)
        print('PASS: 12 real full --no-egress Received cases; scoped IPs, raw strings, partial coverage, unverified boundary, zero category penalties and valid seals')


if __name__ == '__main__':
    main()
