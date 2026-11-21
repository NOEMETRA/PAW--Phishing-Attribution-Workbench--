"""Private-link fixture for the Linux namespace integration; all endpoint addresses are fixed."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import sqlite3
from contextlib import closing
import subprocess
import sys
import threading
import time

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

PEER = os.environ["PAW_FIXTURE_PEER_IP"]
CLIENT = os.environ["PAW_FIXTURE_CLIENT_IP"]
IPV6 = ip_address(PEER).version == 6
PEER_AUTHORITY = f"[{PEER}]" if IPV6 else PEER
ADDRESS_TYPE = "AAAA" if IPV6 else "A"
ADDRESS_FAMILY = socket.AF_INET6 if IPV6 else socket.AF_INET
CAMPAIGN = "https://sentinel.test:8443/campaign"
UNTRUSTED_TLS_NAME = "wrong-name.test" if IPV6 else PEER_AUTHORITY
EVENTS = Path("events.jsonl")


def record(event):
    with EVENTS.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event) + "\n")


def events():
    return [json.loads(line) for line in EVENTS.read_text().splitlines()]


class Resolver(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        query = dns.message.from_wire(packet)
        question, = query.question
        name = question.name.to_text()
        answer = dns.message.make_response(query)
        if name != "sentinel.test." and not (IPV6 and name == "wrong-name.test."):
            answer.set_rcode(dns.rcode.NXDOMAIN)
        elif question.rdtype == dns.rdatatype.from_text(ADDRESS_TYPE):
            answer.answer.append(dns.rrset.from_text(name, 37, "IN", ADDRESS_TYPE, PEER))
        record(dict(kind="dns", peer=self.client_address[0], name=name,
                    type=dns.rdatatype.to_text(question.rdtype), rcode=answer.rcode()))
        sock.sendto(answer.to_wire(), self.client_address)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        record(dict(kind="http", peer=self.client_address[0], path=self.path, host=self.headers["Host"],
                    tls=self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://sentinel.test:8443/unvisited")
            body = b"redirect"
        else:
            code, content = Path("state").read_text().split()
            self.send_response(int(code))
            body = content.encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FixtureUDPServer(socketserver.UDPServer):
    address_family = ADDRESS_FAMILY


class FixtureHTTPServer(ThreadingHTTPServer):
    address_family = ADDRESS_FAMILY


def serve():
    EVENTS.touch()
    with FixtureUDPServer((PEER, 53), Resolver) as resolver, \
         FixtureHTTPServer((PEER, 8080), Handler) as http, \
         FixtureHTTPServer((PEER, 8443), Handler) as https:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain("fixture.pem", "fixture.key")
        https.socket = tls.wrap_socket(https.socket, server_side=True)
        for service in (resolver, http):
            threading.Thread(target=service.serve_forever, daemon=True).start()
        Path("ready").touch()
        https.serve_forever()


def cli(*args):
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "paw", *args],
                            capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stdout} {result.stderr}")
    return result.stdout.strip()


def register(name, url):
    return cli("monitor", "add", "--case", name, "--url", url).split()[-1]


def check(identifier):
    cli("monitor", "check", "--campaign", identifier)
    return json.loads(cli("monitor", "history", "--campaign", identifier))


def http_events():
    return [entry for entry in events() if entry["kind"] == "http"]


def observe():
    from paw.core.dns_enrichment import DNSEnrichmentAnalyzer

    enrichment = DNSEnrichmentAnalyzer(timeout=2).analyze_domain_dns("sentinel.test")
    Path("paw-dns.json").write_text(json.dumps(enrichment, indent=2))
    assert not enrichment["errors"], enrichment["errors"]
    assert enrichment["records"][ADDRESS_TYPE] == [{"value": PEER, "ttl": 37}], enrichment["records"]
    identifier = register("private-https", CAMPAIGN)
    Path("campaign-id").write_text(identifier)
    for code, body in [(200, "first"), (503, "second"), (200, "second")]:
        Path("state").write_text(f"{code} {body}")
        history = check(identifier)
        row = history["checks"][0]
        assert row["http_status"] == code
        assert row["content_hash"] == hashlib.sha256(body.encode()).hexdigest()
    assert [r["http_status"] for r in history["checks"]] == [200, 503, 200]
    assert sorted(a["alert_type"] for a in history["alerts"]) == ["changed", "down"]
    redirect = register("private-redirect", "http://sentinel.test:8080/redirect")
    assert check(redirect)["checks"][0]["http_status"] == 302
    before = http_events()
    for name, url in [("wrong-name", f"https://{UNTRUSTED_TLS_NAME}:8443/campaign"),
                      ("missing-dns", "https://absent.test:8443/campaign")]:
        ident = register(name, url)
        result = check(ident)
        with closing(sqlite3.connect("file:sentinel.db?mode=ro", uri=True)) as db:
            error, = db.execute("SELECT error_message FROM checks WHERE campaign_id = ?", (ident,)).fetchone()
        assert error == ("SSLError" if name == "wrong-name" else "ConnectionError"), error
        assert result["checks"][0]["status"] == "error" and not result["alerts"]
    assert http_events() == before
    assert [r["path"] for r in before] == ["/campaign"] * 3 + ["/redirect"]
    assert any(e.get("name") == "absent.test." and e["rcode"] == dns.rcode.NXDOMAIN for e in events())
    assert all(e["peer"] == CLIENT for e in events())
    assert all(e["tls"] for e in before[:3]) and before[-1]["tls"] is None

    # A message carries the reachable fixture URL; the default CLI must stay offline.
    prior = list(events())
    Path("sample.eml").write_bytes(
        b"From: sender@example.invalid\r\nTo: lab@example.invalid\r\nSubject: fixture\r\n"
        b"X-PAW-Fixture: 1\r\n\r\nhttps://sentinel.test:8443/campaign\r\n")
    cli("full", "sample.eml")
    case, = Path("cases").glob("case-*")
    execution = json.loads((case / "execution.json").read_text())
    assert execution["no_egress"] and not execution["blocked_operations"]
    assert execution["status"] == "completed" and "detonation" in execution["skipped_stages"]
    assert (case / "input.eml").read_bytes() == Path("sample.eml").read_bytes()
    cli("verify", "--case", str(case))
    assert events() == prior
    Path("baseline-history.json").write_text(json.dumps(history, indent=2))


def denied():
    before = http_events()
    history = check(Path("campaign-id").read_text())
    row = history["checks"][0]
    assert row["status"] == "error" and row["http_status"] is None and row["content_hash"] is None
    assert http_events() == before
    assert history["alerts"] == json.loads(Path("baseline-history.json").read_text())["alerts"]
    Path("denied-history.json").write_text(json.dumps(history, indent=2))


def restored():
    history = check(Path("campaign-id").read_text())
    assert [r["http_status"] for r in history["checks"]] == [200, None, 200, 503, 200]
    assert len(http_events()) == 5
    assert all(e["peer"] == CLIENT for e in events())
    assert history["alerts"] == json.loads(Path("baseline-history.json").read_text())["alerts"]
    Path("restored-history.json").write_text(json.dumps(history, indent=2))
    print("PASS: private DNS, TLS, HTTP, redirect, two failure modes, kernel denial, recovery and offline CLI.")


def foreground(phase):
    directory = Path('foreground')
    directory.mkdir(exist_ok=True)
    scheme, port = ('https', 8443) if IPV6 else ('http', 8080)
    authority = f'{PEER_AUTHORITY}:{port}'
    origin = f'{scheme}://{authority}'
    if phase == 'initial':
        config = {'storage': {'database_path': 'saved.db'}, 'monitoring': {'check_interval_minutes': 60}}
        (directory / 'sentinel_config.json').write_text(json.dumps(config))
        subprocess.run([sys.executable, '-I', '-m', 'paw', 'monitor', 'add', '--case', 'lab',
                        '--url', origin + '/foreground'], cwd=directory, check=True, timeout=15)
    if phase == 'restored':
        Path('state').write_text('200 replacement')
    path = directory / 'saved.db'
    before = len(http_events())
    trust = ['--ca-file', str(Path('fixture.pem').absolute())] if IPV6 else []
    with closing(sqlite3.connect(path)) as db:
        initial, = db.execute('SELECT COUNT(*) FROM checks').fetchone()
        with (directory / f'{phase}.log').open('w') as log:
            process = subprocess.Popen([sys.executable, '-I', '-m', 'paw', 'monitor', 'run',
                                        '--origin', origin, *trust], cwd=directory, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while db.execute('SELECT COUNT(*) FROM checks').fetchone()[0] == initial:
                    assert process.poll() is None and time.monotonic() < deadline, phase
                    time.sleep(.05)
                process.terminate()
                assert process.wait(timeout=10) == 0
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        rows = db.execute('SELECT status, http_status, metadata FROM checks ORDER BY id').fetchall()
        assert len(rows) == initial + 1
        status, code, metadata = rows[-1]
        assert (status, code) == (('error', None) if phase == 'blocked' else ('up', 200))
        assert json.loads(metadata)['monitor_comparison']['previous_check_id'] == (initial or None)
        saved_alerts = db.execute('SELECT alert_type,metadata FROM alerts ORDER BY id').fetchall()
        if phase in ('restored','unchanged'):
            alert, = saved_alerts
            assert alert[0] == 'changed'
            receipt = json.loads(alert[1])
            assert (receipt['previous_check_id'], receipt['digest_reference_check_id'], receipt['check_id']) == (2,1,3)
        else:
            assert not saved_alerts
    extra = http_events()[before:]
    if phase == 'blocked':
        assert not extra
    else:
        event, = extra
        assert (event['peer'], event['path']) == (CLIENT, '/foreground')
        assert event['host'] == authority
        assert bool(event['tls']) == IPV6
    print(f'PASS foreground {phase} on {origin}: {status}, HTTP {code}, {len(extra)} peer requests')


if __name__ == "__main__":
    {"serve": serve, "observe": observe, "denied": denied, "restored": restored,
     "foreground": foreground}[sys.argv[1]](*sys.argv[2:])
