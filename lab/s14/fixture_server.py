"""Owned synthetic HTTP/DNS canary; never forwards or resolves a destination."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import threading
import time

lock = threading.Lock()
stop = threading.Event()
workers = threading.BoundedSemaphore(8)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['peer', 'host', 'lan'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    addresses, tcp_port, udp_port = {
        'peer': (['192.0.2.10', 'fd42:14::10'], 18080, 5353),
        'host': (['198.18.0.1', 'fd42:14:1::1'], 18081, 18081),
        'lan': (['198.18.1.2', 'fd42:14:2::2'], 18082, 5353),
    }[args.role]
    def record(event, **values):
        with lock, (args.output / (args.role + '.jsonl')).open('a') as stream:
            stream.write(json.dumps({'time_monotonic': time.monotonic(), 'event': event, **values}) + '\n')
    def handle(client, peer):
        try:
            client.settimeout(2)
            data = client.recv(1024)
            record('tcp', peer=str(peer), bytes=len(data))
            client.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nPAW-OWNED-FIXTURE\n')
            if data.startswith(b'GET /stream '):
                record('stream_start')
                try:
                    for _ in range(300):
                        if stop.wait(.1): break
                        client.sendall(b'bounded heartbeat\n')
                except OSError:
                    pass
                record('stream_end')
        except OSError:
            pass
        finally:
            client.close()
            workers.release()
    sockets = []
    def tcp_loop(server):
        while not stop.is_set():
            try:
                client, peer = server.accept()
            except socket.timeout:
                continue
            if not workers.acquire(False):
                client.close()
                continue
            threading.Thread(target=handle, args=(client, peer), daemon=True).start()
    def udp_loop(server):
        while not stop.is_set():
            try:
                data, peer = server.recvfrom(512)
            except socket.timeout:
                continue
            record('udp', peer=str(peer), bytes=len(data))
            if len(data) >= 12:
                answer = data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + data[12:]
                answer += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04' + socket.inet_aton('192.0.2.10')
                server.sendto(answer, peer)
    for address in addresses:
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        for kind, port, target in [(socket.SOCK_STREAM, tcp_port, tcp_loop), (socket.SOCK_DGRAM, udp_port, udp_loop)]:
            server = socket.socket(family, kind)
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, port))
            if kind == socket.SOCK_STREAM: server.listen(8)
            server.settimeout(.2)
            sockets.append(server)
            threading.Thread(target=target, args=(server,), daemon=True).start()
    (args.output / (args.role + '-ready.json')).write_text(json.dumps({'pid': os.getpid()}))
    record('ready')
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    while not stop.wait(.2):
        pass
    record('stopped')
    for server in sockets: server.close()

if __name__ == '__main__':
    main()
