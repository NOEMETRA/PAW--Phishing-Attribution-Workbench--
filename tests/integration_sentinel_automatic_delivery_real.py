"""Exercise durable automatic webhook delivery across two foreground processes."""
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
    requests = []
    accepted = set()
    body = b'baseline'
    first_seen = threading.Event()

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            observed = body
            self.send_response(200)
            self.send_header('Content-Length', str(len(observed)))
            self.end_headers()
            self.wfile.write(observed)

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            key = self.headers['Idempotency-Key']
            assert payload['event_id'] == key
            requests.append((self.path, key))
            accepted.add(key)
            if len(requests) == 1:
                first_seen.set()
                self.connection.settimeout(7)
                self.connection.recv(1)
                return
            self.send_response(202)
            self.send_header('Sentinel-Receipt', key)
            self.end_headers()

    with tempfile.TemporaryDirectory() as temp, ThreadingHTTPServer(('127.0.0.1', 0), Receiver) as receiver:
        root = Path(temp)
        database = root/'sentinel.db'
        origin = f'http://127.0.0.1:{receiver.server_port}'
        webhook = origin+'/alerts'
        (root/'sentinel_config.json').write_text(json.dumps({
            'storage':{'database_path':'sentinel.db'},
            'monitoring':{'check_interval_minutes':.01,'timeout_seconds':3}}))
        cli = [sys.executable,'-I','-B','-m','paw','monitor']
        added = subprocess.run(cli+['add','--case','fixture','--url',origin+'/watch'],
                               cwd=root, check=True, capture_output=True, text=True)
        campaign = added.stdout.split()[-1]
        thread = threading.Thread(target=receiver.serve_forever)
        thread.start()
        processes = []
        try:
            def run(args, out):
                process = subprocess.Popen(cli+['run','--origin',origin,*args],
                                           cwd=root, stdout=out, stderr=out)
                processes.append(process)
                return process

            def wait_for(predicate, timeout=15):
                deadline = time.monotonic()+timeout
                while not predicate():
                    assert processes[-1].poll() is None and time.monotonic() < deadline
                    time.sleep(.02)

            with (root/'service.log').open('w') as output, closing(sqlite3.connect(database)) as conn:
                proc = run(['--webhook',webhook], output)
                wait_for(lambda: conn.execute('SELECT COUNT(*) FROM checks').fetchone()[0] == 1)
                body = b'changed once'
                wait_for(first_seen.is_set, timeout=10)
                proc.kill()
                assert proc.wait(timeout=5) == -signal.SIGKILL

                def delivery():
                    record = conn.execute('SELECT metadata FROM alerts').fetchall()
                    if len(record) != 1:
                        return {}
                    return json.loads(record[0][0])['webhook_delivery']

                state = delivery()
                assert state['status'] == 'pending' and state['attempts'] == 1 and state['automatic']
                event_id = state['event_id']
                assert requests == [('/alerts',event_id)]

                # A restart with another recipient must not move the queued event.
                proc = run(['--webhook',origin+'/other'], output)
                wait_for(lambda: conn.execute('SELECT COUNT(*) FROM checks').fetchone()[0] >= 3)
                time.sleep(1.15)
                proc.terminate()
                assert proc.wait(timeout=5) == 0
                assert delivery() == state and requests == [('/alerts',event_id)]

                proc = run(['--webhook',webhook], output)
                wait_for(lambda: delivery().get('status') == 'receipt_confirmed')
                assert (delivery()['attempts'], delivery()['event_id']) == (2,event_id)
                assert requests == [('/alerts',event_id)] * 2 and accepted == {event_id}
                time.sleep(1.15)
                proc.terminate()
                assert proc.wait(timeout=5) == 0
                assert len(requests) == 2
            read = subprocess.run(cli+['history','--campaign',campaign], cwd=root,
                                  check=True, capture_output=True, text=True)
            alert, = json.loads(read.stdout)['alerts']
            assert alert['webhook_delivery']['status'] == 'receipt_confirmed'
            assert alert['external_delivery_at_commit'] == 'not_attempted' and alert['acknowledged'] == 0
            print('PASS: automatic queue recovered after process death, original receiver confirmed once, clean stop.')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            receiver.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
