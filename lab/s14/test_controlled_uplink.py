"""One-shot application budgets and response handling, without network access."""
import socket
import unittest
from unittest.mock import patch

from controlled_guest import OneShot
from verify_controlled_uplink import positive_packets


class Socket:
    def __init__(self, data=b'', fail=False):
        self.data = data; self.fail = fail; self.sent = []; self.connected = []
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def settimeout(self, timeout): self.timeout = timeout
    def connect(self, peer):
        self.connected.append(peer)
        if self.fail: raise TimeoutError('fixture_timeout')
    def getpeername(self): return ('198.18.43.10', 443)
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


if __name__ == '__main__':
    unittest.main()
