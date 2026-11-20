"""Installed Linux CLI and SQLite lifecycle with one owned loopback service."""
from contextlib import ExitStack, closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from queue import Queue
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time


def main():
    requests = Queue()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            control = Queue()
            requests.put((self.path, control, time.monotonic()))
            response = control.get(timeout=30)
            if response == 'disconnect':
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            if response == 'stream':
                self.send_response(200)
                self.end_headers()
                for _ in range(800):
                    try:
                        self.wfile.write(b'x')
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    time.sleep(.025)
                return
            status, body = response
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory() as work, ExitStack() as stack:
        root = Path(work)
        server = stack.enter_context(ThreadingHTTPServer(('127.0.0.1', 0), Handler))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        stack.callback(thread.join)
        stack.callback(server.shutdown)
        origin = f'http://127.0.0.1:{server.server_port}'
        config = {'monitoring': {'check_interval_minutes': .005, 'timeout_seconds': 20},
                  'storage': {'database_path': 'saved.db', 'retain_http_bodies': True},
                  'alerts': {'alert_on_up': True}}
        (root / 'sentinel_config.json').write_text(json.dumps(config))
        command = [sys.executable, '-I', '-B', '-m', 'paw', 'monitor']

        def invoke(*args, expected=0):
            proc = subprocess.run(command + list(args), cwd=root, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, timeout=15)
            assert proc.returncode == expected, proc.stdout
            return proc.stdout

        run = ['run', '--origin', origin]
        def launch():
            proc = subprocess.Popen(command + run, cwd=root, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            stack.callback(proc.wait, 15)
            stack.callback(proc.terminate)
            return proc

        def receive(proc):
            deadline = time.monotonic() + 10
            while requests.empty():
                assert proc.poll() is None, proc.stdout.read()
                assert time.monotonic() < deadline, 'Expected a laboratory request'
                time.sleep(.025)
            path, control, arrived = requests.get_nowait()
            assert path == '/owned', path
            return control, arrived

        def stop(proc):
            proc.send_signal(signal.SIGTERM)
            output = proc.communicate(timeout=10)[0]
            assert proc.returncode == 0, output
            events = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
            assert events[-1] == {'event': 'stopped', 'active_operations': 0}, events
            check_ids = [e['check_id'] for e in events if e['event'] == 'check_committed']
            for event in events:
                if event['event'] == 'alert_committed':
                    assert event['check_id'] in check_ids and event['external_delivery'] == 'not_attempted'
            return check_ids, [e['alert_id'] for e in events if e['event'] == 'alert_committed']

        invoke('acknowledge', '--campaign', 'absent', '--alert-id', '1', expected=1)
        assert not (root / 'saved.db').exists()
        invoke('add', '--case', 'lab', '--url', origin + '/owned')
        assert 'outside the selected' in invoke('run', '--origin', 'http://127.0.0.1:1', expected=1)
        assert requests.empty()
        with closing(sqlite3.connect(root / 'saved.db')) as conn:
            campaign, = conn.execute('SELECT id FROM campaigns').fetchone()
        first = launch()
        sequence = [(200, b'A'), (200, b'A'), (503, b'B'), (200, b'B'), 'disconnect', (200, b'B')]
        arrivals, commit_delays = [], []
        with closing(sqlite3.connect(root / 'saved.db')) as conn:
            for count, response in enumerate(sequence, 1):
                control, arrived = receive(first)
                arrivals.append(arrived)
                released = time.monotonic()
                control.put(response)
                while conn.execute('SELECT COUNT(*) FROM checks').fetchone()[0] < count:
                    assert first.poll() is None and time.monotonic() - released < 10
                    time.sleep(.01)
                commit_delays.append(round(time.monotonic() - released, 3))
        control, _ = receive(first)
        control.put('stream')
        assert 'already owns' in invoke(*run, expected=1)
        def history():
            return json.loads(invoke('history', '--campaign', campaign))
        snapshot = history()
        assert [r['status'] for r in reversed(snapshot['checks'])] == ['up','up','down','up','error','up']
        assert sorted(r['alert_type'] for r in snapshot['alerts']) == ['changed','down','up']
        selected = snapshot['alerts'][0]
        assert selected['acknowledged'] == 0
        identifier = str(selected['id'])
        invoke('acknowledge', '--campaign', campaign.swapcase(), '--alert-id', identifier, expected=1)
        assert history()['alerts'] == snapshot['alerts']
        receipt = json.loads(invoke('acknowledge', '--campaign', campaign, '--alert-id', identifier))
        assert receipt == {'campaign_id':campaign, 'alert_id':selected['id'], 'status':'acknowledged'}
        receipt = json.loads(invoke('acknowledge', '--campaign', campaign, '--alert-id', identifier))
        assert receipt['status'] == 'already_acknowledged'
        expected_alerts = [dict(selected, acknowledged=1), *snapshot['alerts'][1:]]
        assert history()['alerts'] == expected_alerts
        first_ids, emitted_alerts = stop(first)
        assert emitted_alerts == [r['id'] for r in reversed(snapshot['alerts'])]
        assert first_ids == [r['id'] for r in reversed(snapshot['checks'])]
        assert history()['checks'] == snapshot['checks']
        with closing(sqlite3.connect(root / 'saved.db')) as conn:
            conn.execute("UPDATE campaigns SET last_check='pending'")
            assert 'sidecars' in invoke('history', '--campaign', campaign, expected=1)
            conn.rollback()
        # After enabling automatic expiry, rows aged five days should expire
        # under the observation window (2 days) only, preserving the alert.
        with closing(sqlite3.connect(root / 'saved.db')) as conn, conn:
            conn.execute("UPDATE checks SET check_time=strftime('%Y-%m-%dT%H:%M:%SZ','now','-36 hours') "
                         "WHERE id=?", (first_ids[-1],))
            prior_raw, prior_digest = conn.execute(
                'SELECT metadata,content_hash FROM checks WHERE id=?', (first_ids[-1],)).fetchone()
            expected_metadata = json.loads(prior_raw)
            prior_source = expected_metadata['source_metadata']
            assert prior_source['http_observation'].pop('body_base64')
            prior_source.update(retained_body_bytes=0, body_retention_status='expired')
            expired_check = conn.execute("INSERT INTO checks(campaign_id,check_time,status) "
                         "VALUES (?,strftime('%Y-%m-%dT%H:%M:%SZ','now','-5 days'),'error')", (campaign,)).lastrowid
            conn.execute("INSERT INTO alerts(campaign_id,alert_time,alert_type,message,metadata) "
                         "VALUES (?,strftime('%Y-%m-%dT%H:%M:%SZ','now','-5 days'),'legacy','saved',?)",
                         (campaign,json.dumps({'check_id':expired_check})))
        config['storage'].update(automatic_retention=True, retention_days=2, alert_retention_days=10, body_retention_days=1)
        (root / 'sentinel_config.json').write_text(json.dumps(config))
        second = launch()
        receive(second)[0].put((200, b'C'))
        receive(second)[0].put('stream')
        second_ids, second_alerts = stop(second)
        final = history()
        assert second_alerts == [final['alerts'][0]['id']]
        assert next(alert for alert in final['alerts'] if alert['id'] == selected['id']) == expected_alerts[0]
        assert final['alerts'][0]['recorded_check_id'] == second_ids[0]
        assert final['alerts'][0]['source_check_available'] is True
        assert final['alerts'][0]['external_delivery_at_commit'] == 'not_attempted'
        legacy, = [r for r in final['alerts'] if r['alert_type'] == 'legacy']
        assert legacy['external_delivery_at_commit'] == 'unknown'
        assert legacy['recorded_check_id'] == expired_check and legacy['source_check_available'] is False
        assert len(second_ids) == 1 and second_ids[0] > first_ids[-1]
        assert [r['id'] for r in reversed(final['checks'])] == first_ids + second_ids
        assert final['alerts'][0]['alert_type'] == 'changed' and len(final['alerts']) == 5
        assert len([r for r in final['alerts'] if r['alert_type'] == 'legacy']) == 1
        with closing(sqlite3.connect(root / 'saved.db')) as conn:
            saved_raw, digest = conn.execute(
                'SELECT metadata,content_hash FROM checks WHERE id=?', (first_ids[-1],)).fetchone()
            assert json.loads(saved_raw) == expected_metadata and digest == prior_digest
            metadata, = conn.execute('SELECT metadata FROM checks WHERE id=?', second_ids).fetchone()
            assert json.loads(metadata)['monitor_comparison']['previous_check_id'] == first_ids[-1]
        assert requests.empty()
        print(json.dumps({'checks_before_restart': first_ids, 'checks_after_restart': second_ids,
                          'expected_alerts': 4, 'observed_alerts': len([r for r in final['alerts'] if r['alert_type'] != 'legacy']),
                          'fixture_release_to_visible_check_seconds': commit_delays,
                          'request_intervals_seconds': [round(b-a, 3) for a,b in zip(arrivals, arrivals[1:])]}))


if __name__ == '__main__':
    main()
