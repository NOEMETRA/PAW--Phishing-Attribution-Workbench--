"""Fixed benign probes inside the trusted guest; no general shell/URL interface."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import tty

PREFIX = 'PAW14 '
MARKER = Path('/var/lib/paw-s14-probe/marker')
CONFIG = json.loads(Path('/etc/paw-s14-fixture.json').read_text())
TCP = {('192.0.2.10', 18080), ('198.18.0.1', 18081), ('198.18.1.2', 18082),
       ('fd42:14::10', 18080), ('fd42:14:1::1', 18081), ('fd42:14:2::2', 18082)}
UDP = {('192.0.2.10', 5353), ('198.18.0.1', 18081), ('198.18.1.2', 5353)}

def tcp(address, port):
    if (address, port) not in TCP:
        raise ValueError('Only fixed owned fixture endpoints are admitted')
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(.8)
        client.connect((address, port))
        client.sendall(b'GET /benign HTTP/1.0\r\nHost: owned.fixture.invalid\r\n\r\n')
        return {'connected': True, 'response': client.recv(256).hex()}

def dns(address, port):
    if (address, port) not in UDP:
        raise ValueError('Only fixed owned fixture endpoints are admitted')
    query = b'\x14\x14\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    query += b'\x05owned\x07fixture\x07invalid\0\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(.8)
        client.sendto(query, (address, port))
        data, peer = client.recvfrom(512)
        return {'received': True, 'response': data.hex(), 'peer': list(peer)}

def checksum(data):
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    return (~((total & 0xffff) + (total >> 16))) & 0xffff

def spoof():
    payload = b'PAW-BENIGN-SPOOF'
    src = socket.inet_aton('198.18.9.9')
    dst = socket.inet_aton('198.18.0.1')
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + 8 + len(payload), 0x1414, 0, 32, 17, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    udp = struct.pack('!HHHH', 18100, 18081, 8 + len(payload), 0) + payload
    ethernet = bytes.fromhex(CONFIG['bridge_mac'].replace(':', ''))
    ethernet += bytes.fromhex('525400abcdef') + b'\x08\x00'
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as client:
        client.bind(('lab0', 0))
        for _ in range(3):
            client.send(ethernet + header + udp)
    return {'frames_sent': 3, 'source_ip': '198.18.9.9', 'source_mac': '52:54:00:ab:cd:ef'}

def stream():
    client = socket.create_connection(('192.0.2.10', 18080), timeout=1)
    client.sendall(b'GET /stream HTTP/1.0\r\nHost: owned.fixture.invalid\r\n\r\n')
    first = client.recv(256)
    def read():
        try:
            client.settimeout(30)
            while client.recv(256):
                pass
        except OSError:
            pass
        finally:
            client.close()
    threading.Thread(target=read, daemon=True).start()
    return {'stream_started': bool(first)}

def budget():
    children = []
    blocked = False
    try:
        for _ in range(48):
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
    return {'attempt_budget': 48, 'created': len(children), 'blocked': blocked,
            'children_stopped': all(child.returncode is not None for child in children)}

def dispatch(command):
    operation = command['op']
    if operation == 'snapshot':
        cg = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
        directory = Path('/sys/fs/cgroup') / cg.lstrip('/')
        return {'kernel': os.uname().release, 'marker_exists': MARKER.exists(),
                'marker_sha256': hashlib.sha256(MARKER.read_bytes()).hexdigest() if MARKER.exists() else None,
                'pids_max': (directory / 'pids.max').read_text().strip(),
                'memory_max': (directory / 'memory.max').read_text().strip(),
                'addresses': subprocess.check_output(['/usr/sbin/ip', '-j', 'address'], timeout=3).decode()}
    if operation == 'tcp':
        return tcp(command['address'], command['port'])
    if operation == 'dns':
        return dns(command['address'], command['port'])
    if operation == 'spoof':
        return spoof()
    if operation == 'stream':
        return stream()
    if operation == 'budget':
        return budget()
    if operation == 'marker':
        MARKER.write_bytes(b'PAW S14 disposable overlay marker\n')
        subprocess.run(['/usr/bin/sync'], check=True, timeout=10)
        return {'marker_written': True}
    if operation == 'ready':
        return {'ready': True}
    raise ValueError('Unsupported fixed probe operation')

def main():
    tty.setraw(sys.stdin.fileno())
    print(PREFIX + json.dumps({'ready': True}), flush=True)
    while True:
        line = sys.stdin.buffer.readline(8193)
        if not line:
            return
        if len(line) > 8192:
            raise ValueError('Control frame exceeds budget')
        command = json.loads(line)
        try:
            result = {'id': command['id'], 'ok': True, 'data': dispatch(command)}
        except Exception as error:
            result = {'id': command.get('id'), 'ok': False, 'error': type(error).__name__ + ': ' + str(error)[:512]}
        print(PREFIX + json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
