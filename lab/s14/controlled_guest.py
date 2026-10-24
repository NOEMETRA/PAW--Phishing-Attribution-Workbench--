"""Trusted, one-shot HTTPS probe; no sample input, DNS, redirect or retry."""
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time
import tty

sys.path.insert(0, str(Path(__file__).resolve().parent))
from uplink_policy import address
from controlled_scope import public_scope, PUBLIC_PATH, FIXTURE_HOST, FIXTURE_PATH


class BoundedReader(io.RawIOBase):
    def __init__(self, client):
        self.client = client
        self.remaining = 24576

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.remaining <= 0:
            raise ValueError('wire_response_budget')
        data = self.client.recv(min(len(buffer), self.remaining))
        buffer[:len(data)] = data
        self.remaining -= len(data)
        return len(data)


class ResponseSocket:
    def __init__(self, client):
        self.client = client

    def makefile(self, *args, **kwargs):
        return io.BufferedReader(BoundedReader(self.client), 1024)


class OneShot:
    def __init__(self, mode, ca_file, target='apex'):
        if mode not in {'fixture', 'public'}:
            raise ValueError('mode')
        self.mode = mode
        public_host, _ = public_scope(target)
        self.host = FIXTURE_HOST if mode == 'fixture' else public_host
        self.path = FIXTURE_PATH if mode == 'fixture' else PUBLIC_PATH
        self.ca_file = ca_file
        self.used = False
        self.completed = False
        self.synthetic_used = False
        self.observation = {'requests': 0, 'redirects': 0}

    def execute(self, command):
        if self.used:
            raise ValueError('request_budget')
        if set(command) != {'address', 'lease_ms'}:
            raise ValueError('command_shape')
        peer = address(command['address'], self.mode == 'fixture')
        milliseconds = command['lease_ms']
        if type(milliseconds) is not int or not 1 <= milliseconds <= 5000:
            raise ValueError('deadline')
        # Consume before connecting: a timeout or TLS error never permits retry.
        self.used = True
        start = time.monotonic()
        def expired(*_):
            raise TimeoutError('whole_request_deadline')
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, milliseconds / 1000)
        try:
            context = ssl.create_default_context(cafile=self.ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
                raw.settimeout(milliseconds / 1000)
                raw.connect((peer, 443))
                with context.wrap_socket(raw, server_hostname=self.host) as client:
                    if client.getpeername()[0] != peer:
                        raise ValueError('peer_binding')
                    certificate = hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest()
                    self.observation.update(peer=peer, tls_hostname=self.host, tls_verified=True,
                                            certificate_sha256=certificate, tls_version=client.version())
                    client.sendall(('GET ' + self.path + ' HTTP/1.0\r\nHost: ' + self.host +
                                    '\r\nAccept: */*\r\nAccept-Encoding: identity\r\n'
                                    'Connection: close\r\n\r\n').encode('ascii'))
                    self.observation['requests'] = 1
                    response = http.client.HTTPResponse(ResponseSocket(client))
                    try:
                        response.begin()
                        self.observation['http_status'] = response.status
                        if 300 <= response.status < 400:
                            location = response.getheader('Location')
                            if location is not None:
                                if len(location) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in location):
                                    raise ValueError('redirect_location_shape')
                                self.observation['redirect_location'] = location
                        if response.status != 200:
                            raise ValueError('http_status_' + str(response.status))
                        if response.getheader('Content-Encoding', 'identity') != 'identity':
                            raise ValueError('content_encoding')
                        data = response.read(8193)
                        self.observation['body_bytes_read'] = len(data)
                        if len(data) > 8192:
                            raise ValueError('response_budget')
                        if response.length not in {None, 0}:
                            raise ValueError('incomplete_response')
                        self.completed = True
                        return {'status': 'completed', 'http_status': response.status, 'bytes': len(data),
                                'sha256': hashlib.sha256(data).hexdigest(), 'peer': peer,
                                'tls_hostname': self.host, 'tls_verified': True,
                                'certificate_sha256': certificate, 'tls_version': client.version(),
                                'elapsed_seconds': time.monotonic() - start, 'requests': 1, 'redirects': 0}
                    finally:
                        response.close()
        finally:
            self.observation['elapsed_seconds'] = time.monotonic() - start
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


def network_names():
    return sorted(p.name for p in Path('/sys/class/net').iterdir())


def run_synthetic(probe):
    if not probe.completed or probe.synthetic_used or network_names() != ['lo']:
        raise ValueError('synthetic_gate_requires_completed_get_and_networkless_once')
    probe.synthetic_used = True
    program = Path(__file__).resolve().with_name('benign_synthetic.py')
    with subprocess.Popen(['/usr/bin/python3', '-I', str(program)], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(timeout=1)
            raise ValueError('synthetic_deadline')
        if child.returncode != 0 or len(stdout) > 4096 or len(stderr) > 4096:
            raise ValueError('synthetic_result')
        value = json.loads(stdout)
        if value['pid'] != child.pid:
            raise ValueError('synthetic_child_identity')
        return {**value, 'returncode': child.returncode, 'child_reaped': True,
                'scope': 'fixed benign fixture only; no hostile-code acceptance'}


def emit(value):
    data = ('PAW14 ' + json.dumps(value) + '\n').encode()
    while data:
        data = data[os.write(1, data):]


def main():
    config = json.loads(open('/etc/paw-controlled.json').read())
    probe = OneShot(config['mode'], '/etc/paw-controlled-ca.pem', config['target'])
    tty.setraw(0)
    emit({'ready': True, 'mode': config['mode'], 'one_shot': True})
    while True:
        raw = sys.stdin.buffer.readline(4097)
        if not raw:
            return
        if len(raw) > 4096:
            raise ValueError('frame_budget')
        command = json.loads(raw)
        try:
            op = command.pop('op'); ident = command.pop('id')
            if op == 'state':
                result = {'used': probe.used, 'completed': probe.completed, 'host': probe.host,
                          'path': probe.path, 'mode': probe.mode, 'network_interfaces': network_names()}
            elif op == 'fetch':
                result = probe.execute(command)
            elif op == 'synthetic' and not command:
                result = run_synthetic(probe)
            else:
                raise ValueError('fixed_operations_only')
            emit({'id': ident, 'ok': True, 'data': result})
        except Exception as error:
            emit({'id': command.get('id', locals().get('ident')), 'ok': True,
                  'data': {'status': 'refused', 'reason': str(error), 'used': probe.used,
                           'observation': probe.observation}})


if __name__ == '__main__':
    main()
