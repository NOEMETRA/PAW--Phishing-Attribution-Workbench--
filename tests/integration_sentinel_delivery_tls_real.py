"""Actual HTTPS handshake and receipt with synthetic loopback certificates."""
import asyncio
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
import ssl
import tempfile
import threading
from unittest.mock import patch

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from paw.sentinel.delivery import _request_receipt


def fixture_certificate(root, address):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, address)])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(address))]), False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                   .sign(key, hashes.SHA256()))
    cert_file = root/f'{address}.pem'
    key_file = root/f'{address}.key'
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_file, key_file


def main():
    accepted = []
    payload = {'event_id':'a'*32, 'campaign_id':'fixture', 'alert_id':1, 'alert_type':'changed'}

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            accepted.append(self.path)
            key = self.headers['Idempotency-Key']
            self.send_response(202)
            self.send_header('Sentinel-Receipt', key)
            if self.path == '/duplicate':
                self.send_header('Sentinel-Receipt', key)
            self.end_headers()

    with tempfile.TemporaryDirectory() as work:
        for address in ('127.0.0.1','127.0.0.2'):
            cert, key = fixture_certificate(Path(work), address)
            with ThreadingHTTPServer(('127.0.0.1',0),Receiver) as server:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert,key)
                server.socket = context.wrap_socket(server.socket,server_side=True)
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                origin = f'https://127.0.0.1:{server.server_port}'
                try:
                    assert asyncio.run(_request_receipt(origin+'/notify',payload)) == (None,'transport_error')
                    expected = (202,'receipt_confirmed') if address == '127.0.0.1' else (None,'transport_error')
                    with patch.object(certifi,'where',return_value=str(cert)):
                        assert asyncio.run(_request_receipt(origin+'/notify',payload)) == expected
                        if address == '127.0.0.1':
                            assert asyncio.run(_request_receipt(origin+'/duplicate',payload)) == (202,'receipt_missing')
                finally:
                    server.shutdown()
                    thread.join()
    assert accepted == ['/notify','/duplicate']
    print('PASS: correct HTTPS identity accepted, unknown CA and wrong IP refused, duplicate receipt unconfirmed.')


if __name__ == '__main__':
    main()
