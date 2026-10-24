"""One-shot application budgets and response handling, without network access."""
import socket
import unittest
from unittest.mock import patch

from controlled_guest import OneShot, run_synthetic
from controlled_scope import PUBLIC_HOST, PUBLIC_URL, public_scope
from controlled_uplink import observe_dns
from verify_controlled_uplink import positive_packets


class Socket:
    def __init__(self, data=b'', fail=False, peer='198.18.43.10'):
        self.data = data; self.fail = fail; self.peer = peer; self.sent = []; self.connected = []
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def settimeout(self, timeout): self.timeout = timeout
    def connect(self, peer):
        self.connected.append(peer)
        if self.fail: raise TimeoutError('fixture_timeout')
    def getpeername(self): return (self.peer, 443)
    def getpeercert(self, binary_form=False): return b'fixture certificate'
    def version(self): return 'TLSv1.3'
    def sendall(self, data): self.sent.append(data)
    def recv(self, size):
        value = self.data[:size]; self.data = self.data[size:]; return value


class ControlledTransport(unittest.TestCase):
    def fetch(self, data, fail=False):
        client = Socket(data, fail)
        probe = OneShot('fixture', 'unused-fixture-ca')
        with patch('controlled_guest.socket.socket', return_value=client), \
             patch('controlled_guest.socket.getaddrinfo', side_effect=AssertionError('No DNS')), \
             patch('controlled_guest.ssl.create_default_context') as context:
            context.return_value.wrap_socket.return_value = client
            try:
                result = probe.execute({'address': '198.18.43.10', 'lease_ms': 1000})
            finally:
                self.assertTrue(probe.used)
                with self.assertRaisesRegex(ValueError, 'request_budget'):
                    probe.execute({'address': '198.18.43.10', 'lease_ms': 1000})
        self.assertEqual(client.connected, [('198.18.43.10', 443)])
        self.assertEqual(len(client.sent), 1)
        return result, client.sent[0]

    def test_single_get_no_credentials_and_no_dns(self):
        result, request = self.fetch(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}')
        self.assertEqual(result['bytes'], 2)
        self.assertEqual(result['requests'], 1)
        self.assertIn(b'GET /get HTTP/1.0\r\nHost: allow.fixture.invalid\r\n', request)
        self.assertNotIn(b'Authorization:', request)
        self.assertNotIn(b'Cookie:', request)

    def test_body_and_wire_budgets(self):
        for data, reason in [(b'HTTP/1.0 200 OK\r\n\r\n' + b'x' * 8193, 'response_budget'),
                             (b'HTTP/1.0 200 OK\r\nX-Large: ' + b'x' * 25000, 'wire_response_budget')]:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                self.fetch(data)

    def test_redirect_error_and_encoded_body_refuse(self):
        for data, reason in [(b'HTTP/1.0 302 Found\r\nLocation: https://other.invalid/\r\n\r\n', 'http_status_302'),
                             (b'HTTP/1.0 500 Error\r\n\r\n', 'http_status_500'),
                             (b'HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\n', 'content_encoding')]:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason): self.fetch(data)

    def test_connection_failure_consumes_budget(self):
        with self.assertRaises(TimeoutError): self.fetch(b'', fail=True)

    def test_truncated_declared_body_refuses(self):
        with self.assertRaisesRegex(ValueError, 'incomplete_response'):
            self.fetch(b'HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\n{}')

    def test_scope_and_deadline_refuse_before_network(self):
        for command in [{'address': '127.0.0.1', 'lease_ms': 1000},
                        {'address': '198.18.43.10', 'lease_ms': 5001},
                        {'address': '198.18.43.10', 'lease_ms': True},
                        {'address': '198.18.43.10', 'lease_ms': 1000, 'url': 'https://other.invalid/'}]:
            with self.subTest(command=command), patch('controlled_guest.socket.socket', side_effect=AssertionError('No network')):
                with self.assertRaises(ValueError): OneShot('fixture', 'unused').execute(command)

    def test_packet_reader_requires_both_service_directions(self):
        request = {'ether_type': 0x800, 'protocol': 6, 'src': '198.18.42.1', 'dst': '198.18.43.10', 'sport': 45000, 'dport': 443}
        response = {**request, 'src': request['dst'], 'dst': request['src'], 'sport': 443, 'dport': 45000}
        for packets in [[], [{'ether_type': 0x806}], [request], [response]]:
            with self.subTest(packets=packets), self.assertRaises(ValueError):
                positive_packets(packets, '198.18.42.1', '198.18.43.10', True)
        positive_packets([request, response], '198.18.42.1', '198.18.43.10', True)

    def test_owned_public_scope_is_exact_root_and_sni(self):
        client = Socket(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}', peer='8.8.8.8')
        probe = OneShot('public', 'unused-fixture-ca')
        with patch('controlled_guest.socket.socket', return_value=client), \
             patch('controlled_guest.socket.getaddrinfo', side_effect=AssertionError('No DNS')), \
             patch('controlled_guest.ssl.create_default_context') as context:
            context.return_value.wrap_socket.return_value = client
            result = probe.execute({'address': '8.8.8.8', 'lease_ms': 1000})
            context.return_value.wrap_socket.assert_called_once_with(client, server_hostname='squishylab.fun')
        self.assertEqual(PUBLIC_URL, 'https://squishylab.fun/')
        self.assertEqual(result['tls_hostname'], PUBLIC_HOST)
        self.assertIn(b'GET / HTTP/1.0\r\nHost: squishylab.fun\r\n', client.sent[0])
        self.assertNotIn(b'/get ', client.sent[0])

    def test_refusal_retains_verified_tls_and_http_metadata(self):
        client = Socket(b'HTTP/1.0 402 Refused\r\n\r\n')
        probe = OneShot('fixture', 'unused-fixture-ca')
        with patch('controlled_guest.socket.socket', return_value=client), \
             patch('controlled_guest.ssl.create_default_context') as context:
            context.return_value.wrap_socket.return_value = client
            with self.assertRaisesRegex(ValueError, 'http_status_402'):
                probe.execute({'address': '198.18.43.10', 'lease_ms': 1000})
        self.assertTrue(probe.observation['tls_verified'])
        self.assertEqual(probe.observation['http_status'], 402)
        self.assertEqual(probe.observation['requests'], 1)
        self.assertEqual(len(probe.observation['certificate_sha256']), 64)

    def test_dns_observation_queries_only_owned_name_and_refuses_foreign_or_special(self):
        from types import SimpleNamespace
        answer = 'squishylab.fun. 60 IN A 8.8.8.8\n'
        with patch('controlled_uplink.subprocess.run', return_value=SimpleNamespace(stdout=answer)) as run:
            observation = observe_dns()
            self.assertEqual(observation['answers'], ['8.8.8.8'])
            self.assertIn('squishylab.fun.', run.call_args.args[0])
            self.assertNotIn('httpbingo.org.', run.call_args.args[0])
        for answer in ['foreign.invalid. 60 IN A 8.8.8.8\n', 'squishylab.fun. 60 IN A 127.0.0.1\n']:
            with self.subTest(answer=answer), patch('controlled_uplink.subprocess.run', return_value=SimpleNamespace(stdout=answer)):
                with self.assertRaises(ValueError): observe_dns()

    def test_www_is_separate_fixed_target_with_exact_sni(self):
        client = Socket(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}', peer='8.8.8.8')
        probe = OneShot('public', 'unused-fixture-ca', 'www')
        with patch('controlled_guest.socket.socket', return_value=client), patch('controlled_guest.ssl.create_default_context') as context:
            context.return_value.wrap_socket.return_value = client
            result = probe.execute({'address': '8.8.8.8', 'lease_ms': 1000})
            context.return_value.wrap_socket.assert_called_once_with(client, server_hostname='www.squishylab.fun')
        self.assertTrue(probe.completed)
        self.assertEqual(result['tls_hostname'], 'www.squishylab.fun')
        self.assertIn(b'GET / HTTP/1.0\r\nHost: www.squishylab.fun\r\n', client.sent[0])
        for value in ['https://other.invalid/', 'other', None, True]:
            with self.subTest(value=value), self.assertRaises(ValueError): public_scope(value)

    def test_redirect_location_is_bounded_metadata_never_followed(self):
        for location, reason in [('https://www.squishylab.fun/', 'http_status_308'),
                                 ('x' * 2049, 'redirect_location_shape')]:
            client = Socket(('HTTP/1.0 308 Redirect\r\nLocation: ' + location + '\r\n\r\n').encode())
            probe = OneShot('fixture', 'unused')
            with self.subTest(location=location), patch('controlled_guest.socket.socket', return_value=client), \
                 patch('controlled_guest.ssl.create_default_context') as context:
                context.return_value.wrap_socket.return_value = client
                with self.assertRaisesRegex(ValueError, reason):
                    probe.execute({'address': '198.18.43.10', 'lease_ms': 1000})
            self.assertEqual(len(client.connected), 1)
            self.assertEqual(len(client.sent), 1)
            self.assertFalse(probe.completed)
            if len(location) <= 2048:
                self.assertEqual(probe.observation['redirect_location'], location)

    def test_synthetic_gate_refuses_before_execution(self):
        from types import SimpleNamespace
        for completed, used, names in [(False, False, ['lo']), (True, True, ['lo']),
                                       (True, False, ['lo', 'wan0'])]:
            probe = SimpleNamespace(completed=completed, synthetic_used=used)
            with self.subTest(completed=completed, used=used, names=names), \
                 patch('controlled_guest.network_names', return_value=names), \
                 patch('controlled_guest.subprocess.Popen', side_effect=AssertionError('No execution')):
                with self.assertRaisesRegex(ValueError, 'synthetic_gate'):
                    run_synthetic(probe)

    def test_synthetic_fixed_child_reaped_and_allowance_consumed(self):
        import json
        from types import SimpleNamespace
        from benign_synthetic import MARKER
        probe = SimpleNamespace(completed=True, synthetic_used=False)
        value = {'pid': 1234, 'network_interfaces': ['lo'], 'marker_hex': MARKER.hex(),
                 'fixture': 'fixed-benign-v1'}
        with patch('controlled_guest.network_names', return_value=['lo']), \
             patch('controlled_guest.subprocess.Popen') as popen:
            child = popen.return_value.__enter__.return_value
            child.pid = 1234; child.returncode = 0
            child.communicate.return_value = (json.dumps(value).encode(), b'')
            result = run_synthetic(probe)
            self.assertTrue(result['child_reaped'])
            self.assertTrue(probe.synthetic_used)
            argv = popen.call_args.args[0]
            self.assertEqual(argv[:2], ['/usr/bin/python3', '-I'])
            self.assertTrue(argv[2].endswith('/benign_synthetic.py'))
            with self.assertRaisesRegex(ValueError, 'synthetic_gate'): run_synthetic(probe)
            popen.assert_called_once()


if __name__ == '__main__':
    unittest.main()
