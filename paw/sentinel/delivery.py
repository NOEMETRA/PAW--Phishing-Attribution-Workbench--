"""Receipt-based delivery of saved alerts to an owned laboratory receiver."""
import asyncio
import hashlib
import ipaddress
import json
from urllib.parse import urlsplit, urlunsplit

from .config import SentinelConfig
from .contracts import _require_active
from .database import CampaignDatabase
from .lab_transport import lab_tls_context, load_lab_ca


def _destination(value):
    if not value or len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('A literal loopback webhook destination is required')
    parsed = urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or parsed.username is not None or
            '@' in parsed.netloc or '?' in value or '#' in value or
            '%' in parsed.netloc or '\\' in value):
        raise ValueError('Use a loopback HTTP(S) URL without credentials, query or fragment')
    address = ipaddress.ip_address(parsed.hostname)
    if not address.is_loopback:
        raise ValueError('Webhook delivery requires a literal loopback receiver')
    host = f'[{address}]' if address.version == 6 else str(address)
    default_port = 443 if parsed.scheme == 'https' else 80
    if parsed.port is not None and parsed.port != default_port:
        host += f':{parsed.port}'
    return urlunsplit((parsed.scheme, host, parsed.path or '/', '', ''))


def webhook_destination(value):
    _require_active()
    import requests

    # Bind retries to the normalized wire URL.
    endpoint = requests.Request('POST', _destination(value)).prepare().url
    return endpoint, hashlib.sha256(endpoint.encode('utf-8')).hexdigest()


def deliver_saved_alert(campaign_id, alert_id, destination, *, ca_file=None):
    target = webhook_destination(destination)
    tls_context = load_lab_ca(ca_file) if ca_file is not None else None
    database = CampaignDatabase(**SentinelConfig().get_database_options(), initialize=False)
    return send_saved_alert(database, campaign_id, alert_id, target, tls_context=tls_context)


def send_saved_alert(database, campaign_id, alert_id, target, *, tls_context=None, automatic=False):
    _require_active()

    endpoint, fingerprint = webhook_destination(target[0])
    if fingerprint != target[1]:
        raise ValueError('Webhook destination fingerprint changed')
    attempt = database.start_alert_delivery(campaign_id, alert_id, fingerprint, automatic=automatic)
    if attempt is None:
        return None
    state, alert_type = attempt
    if state['status'] == 'receipt_confirmed':
        return state
    event_id = state['event_id']
    payload = {'event_id':event_id, 'campaign_id':campaign_id, 'alert_id':alert_id, 'alert_type':alert_type}
    code, outcome = asyncio.run(_request_receipt(endpoint, payload, tls_context=tls_context))
    return database.finish_alert_delivery(campaign_id, alert_id, state, outcome, code)


async def _request_receipt(endpoint, payload, *, tls_context=None):
    """Use one wall-clock deadline for connect, TLS, write and response headers."""
    import h11

    parsed = urlsplit(endpoint)
    secure = parsed.scheme == 'https'
    context = lab_tls_context(tls_context) if secure else None
    port = parsed.port if parsed.port is not None else (443 if secure else 80)
    key = payload['event_id'].encode('ascii')
    body = json.dumps(payload, separators=(',', ':')).encode('ascii')
    connection = h11.Connection(h11.CLIENT)
    packet = connection.send(h11.Request(method=b'POST', target=parsed.path.encode('ascii'), headers=[
        (b'host', parsed.netloc.encode('ascii')), (b'content-type', b'application/json'),
        (b'content-length', str(len(body)).encode('ascii')), (b'idempotency-key', key),
        (b'connection', b'close'),
    ]))
    packet += connection.send(h11.Data(data=body)) + connection.send(h11.EndOfMessage())
    try:
        async with asyncio.timeout(3):
            reader, writer = await asyncio.open_connection(parsed.hostname, port, ssl=context)
            try:
                writer.write(packet)
                await writer.drain()
                remaining = 16 * 1024
                while True:
                    event = connection.next_event()
                    if isinstance(event, h11.Response):
                        code = event.status_code
                        if not 200 <= code < 300:
                            return code, 'http_status'
                        receipts = [value for name, value in event.headers if name == b'sentinel-receipt']
                        return code, 'receipt_confirmed' if receipts == [key] else 'receipt_missing'
                    if isinstance(event, h11.InformationalResponse) and event.status_code != 101:
                        continue
                    if event is not h11.NEED_DATA or remaining == 0:
                        return None, 'transport_error'
                    data = await reader.read(min(4096, remaining))
                    remaining -= len(data)
                    connection.receive_data(data)
            finally:
                # A receipt is only a header. Abort the transport without
                # consuming an arbitrary body or waiting for a TLS close reply.
                writer.transport.abort()
    except TimeoutError:
        return None, 'deadline_exceeded'
    except (OSError, h11.ProtocolError):
        return None, 'transport_error'
