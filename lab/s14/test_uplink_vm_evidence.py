"""Offline regressions for the full KVM evidence reconciliation entry point."""
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from verify_uplink_vm_evidence import verify


HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 256, 1)


def tcp_frame(src, dst, sport, dport):
    ethernet = bytes(12) + struct.pack('!H', 0x800)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack('!HHIIHHHH', sport, dport, 0, 0, 0x5010, 0, 0, 0)
    return ethernet + ip + tcp


REQUEST = tcp_frame('198.18.42.1', '198.18.43.10', 45000, 443)
RESPONSE = tcp_frame('198.18.43.10', '198.18.42.1', 443, 45000)
ARP = bytes(12) + struct.pack('!H', 0x806) + bytes(28)


class UplinkVmEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = self.root / 'sources' / 'fixture.txt'
        source.parent.mkdir()
        source.write_bytes(b'constructed regression fixture, not a measured VM run')
        names = ['trusted_kvm_probe_ready_with_bounded_scope', 'empty_kernel_lease_blocks_guest',
                 'kvm_through_actual_host_docker_user_nat_tls', 'kvm_existing_tls_stops_on_kernel_expiry',
                 'kvm_existing_tls_stops_on_revoke', 'owner_sigkill_autodestroys_kvm_and_tap']
        tests = [{'name': name, 'result': 'PASS'} for name in names]
        tests[2]['observation'] = {'status': 'completed', 'http_status': 200,
                                   'tls_verified': True, 'peer': '198.18.43.10'}
        for case in tests[3:5]:
            case['observed'] = {'bytes': 128, 'running': True, 'eof': False}
        tests[5]['seconds'] = 1
        report = {key: True for key in ['source_freeze_unchanged', 'host_network_restored',
                                        'writers_stopped', 'base_unchanged']}
        report.update(result='PASS', host_before={}, host_after={}, tests=tests,
                      source_hashes={'fixture.txt': hashlib.sha256(source.read_bytes()).hexdigest()},
                      domain={'apparmor': 'libvirt-fixture (enforce)', 'limits_after_parent_tightening': {
                          'memory.max': str(768 * 1024**2), 'memory.swap.max': '0',
                          'pids.max': '64', 'cpu.max': '50000 100000'}})
        (self.root / 'results.json').write_text(json.dumps(report))
        (self.root / 'actual-domain.xml').write_text(
            '<domain><memory>524288</memory><devices><interface type="bridge">'
            '<source bridge="pawbr-up"/></interface></devices>'
            '<seclabel model="dac"><label>+1000:+1000</label></seclabel></domain>')
        (self.root / 'fixture.jsonl').write_text(json.dumps({
            'event': 'request', 'peer': '198.18.42.1', 'local': '198.18.43.10', 'path': '/get'}) + '\n')

    def capture(self, *frames):
        records = [struct.pack('<4I', 1, 0, len(frame), len(frame)) + frame for frame in frames]
        (self.root / 'uplink-vm.pcap').write_bytes(HEADER + b''.join(records))

    def test_header_only_capture_refuses(self):
        self.capture()
        with self.assertRaisesRegex(ValueError, 'no_snat_request_packet'):
            verify(self.root)

    def test_arp_only_capture_refuses(self):
        self.capture(ARP)
        with self.assertRaisesRegex(ValueError, 'no_snat_request_packet'):
            verify(self.root)

    def test_request_only_capture_refuses(self):
        self.capture(REQUEST)
        with self.assertRaisesRegex(ValueError, 'no_fixture_response_packet'):
            verify(self.root)

    def test_response_only_capture_refuses(self):
        self.capture(RESPONSE)
        with self.assertRaisesRegex(ValueError, 'no_snat_request_packet'):
            verify(self.root)

    def test_expected_bidirectional_capture_passes(self):
        self.capture(ARP, REQUEST, RESPONSE)
        result = verify(self.root)
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(result['captured_packets'], 3)

    def test_wrong_service_direction_or_foreign_packet_refuses(self):
        wrong_service = tcp_frame('198.18.42.1', '198.18.43.10', 443, 45000)
        foreign = tcp_frame('198.18.42.1', '198.18.43.11', 45000, 443)
        for frames, reason in [((wrong_service, RESPONSE), 'no_snat_request_packet'),
                               ((REQUEST, RESPONSE, foreign), 'wire_address')]:
            with self.subTest(reason=reason):
                self.capture(*frames)
                with self.assertRaisesRegex(ValueError, reason):
                    verify(self.root)


if __name__ == '__main__':
    unittest.main()
