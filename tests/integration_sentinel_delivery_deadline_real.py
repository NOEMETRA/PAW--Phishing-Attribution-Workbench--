"""Foreground stop while a local receiver emits incomplete headers continuously."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time


def main():
    delivery_received = threading.Event()
    receiver_done = threading.Event()
    body = b'baseline'

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            observed = body
            self.send_response(200)
            self.send_header('Content-Length', str(len(observed)))
            self.end_headers()
            self.wfile.write(observed)

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.wfile.write(b'HTTP/1.1 202 Accepted\r\nX-Incomplete: ')
            delivery_received.set()
            try:
                for _ in range(60):
                    self.wfile.write(b'x')
                    time.sleep(.15)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                receiver_done.set()

    with tempfile.TemporaryDirectory() as temp, ThreadingHTTPServer(('127.0.0.1', 0), Fixture) as server:
        root = Path(temp)
        origin = f'http://127.0.0.1:{server.server_port}'
        (root/'sentinel_config.json').write_text(json.dumps({
            'storage':{'database_path':'sentinel.db'},
            'monitoring':{'check_interval_minutes':.02,'timeout_seconds':3}}))
        cli = [sys.executable,'-I','-B','-m','paw','monitor']
        subprocess.run(cli+['add','--case','fixture','--url',origin+'/watch'],
                       cwd=root, check=True, capture_output=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            process = subprocess.Popen(cli+['run','--origin',origin,'--webhook',origin+'/alerts'],
                                       cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                with closing(sqlite3.connect(root/'sentinel.db')) as conn:
                    deadline = time.monotonic()+10
                    while not conn.execute('SELECT 1 FROM checks LIMIT 1').fetchone():
                        assert process.poll() is None and time.monotonic() < deadline
                        time.sleep(.02)
                    body = b'changed'
                    assert delivery_received.wait(10)
                    start = time.monotonic()
                    process.send_signal(signal.SIGTERM)
                    output, _ = process.communicate(timeout=6)
                    elapsed = time.monotonic()-start
                    assert process.returncode == 0, output
                    assert elapsed < 5, elapsed
                    events = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
                    assert events[-1] == {'event':'stopped','active_operations':0}, events
                    event, = [e for e in events if e['event'] == 'webhook_delivery']
                    assert event['error'] == 'deadline_exceeded', event
                    saved, = conn.execute('SELECT metadata FROM alerts').fetchone()
                    state = json.loads(saved)['webhook_delivery']
                    assert state['status'] == 'receipt_unconfirmed' and state['error'] == 'deadline_exceeded'
                    assert state['attempts'] == 1 and state['event_id'] == event['event_id']
                    assert receiver_done.wait(2)
                    print(json.dumps({'status':'PASS','stop_seconds':round(elapsed,3),
                                      'delivery_error':state['error'],'active_operations':0}))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            server.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
