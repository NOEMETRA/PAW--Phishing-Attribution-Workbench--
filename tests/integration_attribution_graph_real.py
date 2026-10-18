"""Actual offline graph publication: original EML and explicit contract fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case

DATE = '; Wed, 8 Oct 2025 10:00:00 +0000'
BADGE = 'UNVERIFIED TRANSMITTING CANDIDATE'


def message(received):
    fields = ''.join('Received: '+line+DATE+'\r\n' for line in received)
    return ('From: sender@example.invalid\r\nSubject: Constructed graph contract\r\n'
            + fields+'\r\nLiteral regression fixture; no classification label.').encode()


def main():
    samples = {
        'original.eml': next((REPO/'inbox').glob('*.eml')).read_bytes(),
        # The selected external-ingress hop is SECOND in oldest-first order,
        # despite sharing its IP with the earlier internet-origin candidate.
        'repeated-ip.eml': message([
            'from gateway.example ([8.8.8.8]) by mx.protection.outlook.com',
            'from relay.example ([8.8.8.8]) by archive.example']),
        'no-address.eml': message(['from relay.example by mx.example']),
        'no-received.eml': message([]),
        'ipv6-receiver.eml': message([
            'from relay.example ([IPv6:2001:4860:4860::8888]) by [IPv6:2001:db8::1]']),
        'single-label-domain.eml': b'From: sender@end\r\nSubject: Constructed diagram contract\r\n\r\nLiteral fixture.',
        'missing-from.eml': b'Subject: Constructed missing From contract\r\n\r\nLiteral fixture.',
    }
    with tempfile.TemporaryDirectory(prefix='paw-graph-') as temporary:
        # An optional private root retains actual sealed artifacts for external
        # Mermaid parser checks; the default leaves no persistent sample copies.
        root = Path(os.environ.get('PAW_VERIFICATION_DIR', temporary)).resolve()
        root.mkdir(parents=True, exist_ok=True)
        inputs = root/'inputs'
        inputs.mkdir()
        for name, raw in samples.items():
            (inputs/name).write_bytes(raw)
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'full', str(inputs),
            '--no-egress', '--lang', 'en', '--deadline', '120', '--stage-timeout', '60'],
            cwd=root, env=env, capture_output=True, timeout=150)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode == 0, (result.stdout+result.stderr).decode(errors='replace')
        controls = [p for p in (root/'jobs').glob('analysis_*') if p.is_dir()]
        control, = controls
        outcome = json.loads((control/'supervisor.json').read_text(encoding='utf-8'))
        assert outcome['tree_stopped'] and outcome['returncode'] == 0, outcome
        seen = set()
        for case in (root/'cases').glob('case-*'):
            if not case.is_dir():
                continue
            require_stopped_case(case)
            assert verify_case(str(case))
            read = lambda name: json.loads((case/name).read_text(encoding='utf-8'))
            name = read('manifest.json')['source_name']
            seen.add(name)
            assert (case/'input.eml').read_bytes() == samples[name]
            execution = read('execution.json')
            assert execution['no_egress'] and not execution['blocked_operations'], execution
            origin, path = read('origin.json'), read('received_path.json')
            graph_bytes = (case/'graphs'/'attribution.mmd').read_bytes()
            graph = graph_bytes.decode('utf-8')
            assert origin['verified'] is False and path['verified'] is False
            assert 'unverified Received header observations' in graph
            assert 'roles are hostname heuristics' in graph
            assert '<<ORIGIN>>' not in graph
            assert graph.count(BADGE) == int(origin['status'] == 'candidate')
            if origin['status'] == 'candidate':
                index, = (i for i, hop in enumerate(path['ordered_hops'], 1)
                          if hop['header_index'] == origin['received_header_index'])
                selected, = (line for line in graph.splitlines() if BADGE in line)
                assert f'--> Hop{index}["' in selected, (name, selected, origin)
                assert f'Received header index {origin["received_header_index"]}' in selected
                if name == 'repeated-ip.eml':
                    assert index == 2 and origin['received_header_index'] == 0
                    assert path['ordered_hops'][0]['ip'] == path['ordered_hops'][1]['ip']
            if name == 'ipv6-receiver.eml':
                assert '[IPv6:2001:db8::1]' in graph
            assert 'graphs/attribution.mmd' in read('evidence/merkle_index.json')
            domain_bytes = (case/'graphs'/'domain.mmd').read_bytes()
            domain_graph = domain_bytes.decode('utf-8')
            assert domain_graph.splitlines()[1].startswith('  D["')
            assert 'graphs/domain.mmd' in read('evidence/merkle_index.json')
            if name == 'single-label-domain.eml':
                assert read('auth.json')['from_domain'] == 'end'
                assert read('domains.json')['from_domain']['domain'] == 'end'
                assert 'D["end"]' in domain_graph
            if name == 'missing-from.eml':
                assert not read('auth.json')['from_domain']
                assert read('domains.json')['from_domain']['domain'] == ''
                assert 'D["Domain unavailable"]' in domain_graph
            # Exercise the actual supported CLI export, then inspect its bytes.
            exported = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'export',
                '--case', str(case), '--format', 'zip'], cwd=root, env=env,
                capture_output=True, timeout=30)
            assert exported.returncode == 0, exported.stdout+exported.stderr
            with zipfile.ZipFile(str(case)+'.zip') as archive:
                assert archive.read(case.name+'/graphs/attribution.mmd') == graph_bytes
                assert archive.read(case.name+'/graphs/domain.mmd') == domain_bytes
                assert archive.read(case.name+'/input.eml') == samples[name]
            assert verify_case(str(case))
        assert seen == set(samples), seen
    print('PASS: original EML plus six constructed diagram contracts through actual full --no-egress, '
          'stopped owners, candidate/header binding, absent candidates, IPv6/missing/single-label domains, CLI ZIP bytes and seals. '
          'Fixtures are not classifier ground truth; no attribution or rendering claim.')


if __name__ == '__main__':
    main()
