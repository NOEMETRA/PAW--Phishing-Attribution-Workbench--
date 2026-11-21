"""Installed CLI, HTTP receiver and SQLite delivery/retry with synthetic data."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading

from paw.sentinel.database import CampaignDatabase


def main():
    requests = []
    accepted = {}
    pending_at_receiver = threading.Event()

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            event_id = self.headers['Idempotency-Key']
            assert payload['event_id'] == event_id
            requests.append((self.path, payload))
            if len(requests) == 1:
                self.send_response(307)
                self.send_header('Location', '/must-not-follow')
                self.send_header('Content-Length', '9999')
            else:
                accepted.setdefault(event_id, payload)
                if len(requests) == 3:
                    pending_at_receiver.set()
                    self.connection.settimeout(8)
                    self.connection.recv(1)
                    return
                self.send_response(202)
                if len(requests) >= 4:
                    self.send_header('Sentinel-Receipt', event_id)
            self.end_headers()

    with tempfile.TemporaryDirectory() as temp, ThreadingHTTPServer(('127.0.0.1', 0), Receiver) as receiver:
        root = Path(temp)
        path = root/'sentinel.db'
        db = CampaignDatabase(str(path))
        campaign = db.add_campaign('fixture', 'http://127.0.0.1/never-fetched')
        db.record_alert(campaign, 'changed', 'private note excluded from payload')
        alert, = db.get_unacknowledged_alerts()
        alert_id = alert['id']
        origin = f'http://127.0.0.1:{receiver.server_port}'
        thread = threading.Thread(target=receiver.serve_forever)
        thread.start()
        try:
            def invoke(*args, expected=0):
                outcome = subprocess.run([sys.executable,'-I','-B','-m','paw','monitor',*args],
                                         cwd=root, capture_output=True, text=True, timeout=15)
                assert outcome.returncode == expected, outcome.stdout + outcome.stderr
                return outcome.stdout

            deliver = ('deliver', '--campaign', campaign, '--alert-id', str(alert_id), '--destination')
            for target in ('http://localhost/alerts', 'https://192.0.2.1/alerts', origin+'/alerts?key=private'):
                invoke(*deliver, target, expected=1)
            assert requests == []
            assert 'webhook_delivery' not in db.get_campaign_history(campaign)['alerts'][0]
            first = json.loads(invoke(*deliver, origin+'/alerts', expected=1))
            assert (first['attempts'], first['status'], first['http_status'], first['error']) == (
                1, 'receipt_unconfirmed', 307, 'http_status')
            invoke(*deliver, origin+'/wrong-receiver', expected=1)
            assert len(requests) == 1
            second = json.loads(invoke(*deliver, origin+'/alerts', expected=1))
            assert (second['attempts'], second['status'], second['http_status'], second['error']) == (
                2, 'receipt_unconfirmed', 202, 'receipt_missing')
            interrupted = subprocess.Popen([sys.executable, '-I', '-B', '-m', 'paw', 'monitor',
                                            *deliver, origin+'/alerts'], cwd=root)
            try:
                assert pending_at_receiver.wait(10)
            finally:
                interrupted.kill()
                interrupted.wait(timeout=5)
            pending = db.get_campaign_history(campaign)['alerts'][0]['webhook_delivery']
            assert pending['status'] == 'pending' and pending['attempts'] == 3
            confirmed = json.loads(invoke(*deliver, origin+'/alerts'))
            assert (confirmed['attempts'], confirmed['status'], confirmed['http_status'], confirmed['error']) == (
                4, 'receipt_confirmed', 202, None)
            assert first['event_id'] == second['event_id'] == pending['event_id'] == confirmed['event_id']
            snapshot = path.read_bytes()
            assert json.loads(invoke(*deliver, origin+'/alerts')) == confirmed
            assert path.read_bytes() == snapshot
            expected_payload = {'event_id':confirmed['event_id'], 'campaign_id':campaign,
                                'alert_id':alert_id, 'alert_type':'changed'}
            assert requests == [('/alerts', expected_payload)] * 4
            assert accepted == {confirmed['event_id']: expected_payload}
            report = json.loads(invoke('history', '--campaign', campaign))
            assert report['alerts'][0]['webhook_delivery'] == confirmed
            assert report['alerts'][0]['acknowledged'] == 0
            assert report['alerts'][0]['external_delivery_at_commit'] == 'unknown'
            with closing(sqlite3.connect(path)) as conn:
                assert conn.execute('SELECT message FROM alerts').fetchone() == ('private note excluded from payload',)
            print('PASS: redirect not followed, missing receipt persisted, retry reused key, receiver accepted once.')
        finally:
            receiver.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
