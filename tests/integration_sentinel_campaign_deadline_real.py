"""Run installed Sentinel with a healthy campaign and a stalled owned peer."""
from contextlib import ExitStack, closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from queue import Queue
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time


def main():
    stalled = Queue()
    healthy = Queue()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == "/slow":
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Stalled: ")
                disconnected = threading.Event()
                stalled.put((time.monotonic(), disconnected))
                for _ in range(100):
                    if release.wait(0.05):
                        return
                    try:
                        self.connection.sendall(b"x")
                    except (BrokenPipeError, ConnectionResetError):
                        disconnected.set()
                        return
                return
            self.send_response(200)
            self.send_header("Content-Length", "1")
            self.end_headers()
            self.wfile.write(b"A")
            healthy.put(time.monotonic())

    with tempfile.TemporaryDirectory() as raw, ExitStack() as cleanup:
        root = Path(raw)
        server = cleanup.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        cleanup.callback(thread.join, 10)
        cleanup.callback(server.shutdown)
        origin = f"http://127.0.0.1:{server.server_port}"
        settings = {
            "monitoring": {"timeout_seconds": 1, "max_concurrent_checks": 2, "check_interval_minutes": 0.002},
            "storage": {"database_path": "campaigns.db"},
        }
        (root / "sentinel_config.json").write_text(json.dumps(settings), encoding="utf-8")
        command = [sys.executable, "-I", "-B", "-m", "paw", "monitor"]
        for path in ("slow", "healthy"):
            subprocess.run(command+["add","--case",path,"--url",f"{origin}/{path}"],
                           cwd=root, check=True, capture_output=True, timeout=15)
        proc = subprocess.Popen(command+["run","--origin",origin], cwd=root, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        try:
            first_slow, deadline_disconnect = stalled.get(timeout=10)
            first_healthy = healthy.get(timeout=10)
            deadline = first_slow + 2.5
            with closing(sqlite3.connect(root / "campaigns.db", timeout=0.2)) as db:
                while True:
                    rows = db.execute(
                        "SELECT campaigns.url, checks.status, checks.http_status, checks.error_message "
                        "FROM checks JOIN campaigns ON campaigns.id = checks.campaign_id ORDER BY checks.id"
                    ).fetchall()
                    if len(rows) >= 3:
                        break
                    if time.monotonic() >= deadline:
                        raise AssertionError(f"Only {len(rows)} observations before the next-cycle deadline")
                    time.sleep(0.02)
            assert rows[0] == (origin+"/healthy","up",200,None), rows
            assert rows[1] == (origin+"/slow","error",None,"Response collection deadline exceeded"), rows
            assert rows[2] == (origin+"/healthy","up",200,None), rows
            next_slow, stop_disconnect = stalled.get(timeout=2)
            next_healthy = healthy.get(timeout=2)
            assert next_slow > first_slow and not release.is_set()
            assert deadline_disconnect.is_set()
            stop_requested = time.monotonic()
            proc.send_signal(signal.SIGTERM)
            output = proc.communicate(timeout=3)[0]
            stopped_after = time.monotonic() - stop_requested
            assert proc.returncode == 0, output
            events = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            assert events[-1] == {"event":"stopped","active_operations":0}, events
            assert stopped_after < 1.0, stopped_after
            assert stop_disconnect.wait(1.0)
            with closing(sqlite3.connect(root / "campaigns.db")) as db:
                assert db.execute("SELECT COUNT(*) FROM checks").fetchone() == (3,)
            print(json.dumps({"status":"PASS",
                              "next_healthy_check_seconds":round(next_healthy-first_healthy, 3),
                              "signal_to_exit_seconds":round(stopped_after, 3),
                              "stop_with_dripping_headers":True}), flush=True)
        finally:
            release.set()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=5)


if __name__ == "__main__":
    main()
