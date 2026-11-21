"""Deadline-bound HTTP/1 observations for explicitly admitted laboratory origins."""
import asyncio
import ipaddress
import ssl
import time
from urllib.parse import urlsplit

from .contracts import _require_active
from .transport import _finish_observation, _new_observation, _source_url
from ..core.network_policy import EgressDenied


_LAB_RANGES = tuple(ipaddress.ip_network(network) for network in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7',
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32',
))
_HEADER_BYTES = 64 * 1024


def _lab_address(hostname):
    if not hostname or '%' in hostname:
        raise ValueError('Specify an HTTP(S) origin with a literal laboratory address')
    address = ipaddress.ip_address(hostname)
    if not (address.is_loopback or any(address in network for network in _LAB_RANGES)):
        raise ValueError('Foreground monitoring requires a loopback, private or documentation-prefix address')
    return address


def lab_origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Specify an HTTP(S) origin with a literal laboratory address')
    address = _lab_address(parsed.hostname)
    host = f'[{address}]' if address.version == 6 else str(address)
    port = parsed.port
    origin = f'{parsed.scheme}://{host}' + (f':{port}' if port is not None else '')
    if value != origin:
        raise ValueError('Specify the canonical origin without credentials, path, query or fragment')
    return origin


def load_lab_ca(path):
    from ..core.source_inspection import SourceLimits, acquire_source

    source = acquire_source(path, SourceLimits(input_bytes=1024**2))
    try:
        return ssl.create_default_context(cadata=source.raw.decode('ascii'))
    except (UnicodeDecodeError, ssl.SSLError):
        raise ValueError('Laboratory CA file must contain PEM certificates') from None


def lab_tls_context(context):
    if context is not None:
        return context
    import certifi

    return ssl.create_default_context(cafile=certifi.where())


class _Canceled(Exception):
    pass


async def _collect(request, address, result, body, max_bytes, tls_context):
    import h11

    parsed = urlsplit(request.url)
    secure = parsed.scheme == 'https'
    context = lab_tls_context(tls_context) if secure else None
    port = parsed.port if parsed.port is not None else (443 if secure else 80)
    conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=_HEADER_BYTES)
    packet = conn.send(h11.Request(method=b'GET', target=request.path_url.encode('ascii'), headers=[
        (b'host', parsed.netloc.encode('ascii')), (b'connection', b'close'),
        (b'user-agent', b'PAW-Sentinel/1.0'), (b'accept-encoding', b'identity'),
    ]))
    packet += conn.send(h11.EndOfMessage())
    reader, writer = await asyncio.open_connection(str(address), port, ssl=context)
    try:
        writer.write(packet)
        await writer.drain()
        header_budget = _HEADER_BYTES
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                awaiting_headers = result['http_status'] is None
                capacity = min(8192, header_budget) if awaiting_headers else 8192
                if not capacity:
                    raise h11.RemoteProtocolError('Response headers exceed the byte limit')
                data = await reader.read(capacity)
                if awaiting_headers:
                    header_budget -= len(data)
                conn.receive_data(data)
            elif isinstance(event, h11.Response):
                encodings = [value for name, value in event.headers if name == b'content-encoding']
                result.update(status='observed', http_status=event.status_code, body_status='partial',
                              response_url=_source_url(request.url, {'apikey'}),
                              content_encoding=b', '.join(encodings or [b'identity']).decode('latin-1')[:4096])
                headers = result['response_headers']
                headers['status'] = 'completed'
                remaining = headers['max_characters']
                for raw_name, raw_value in event.headers.raw_items():
                    remaining -= len(raw_name) + len(raw_value)
                    if remaining < 0:
                        headers['status'] = 'partial'
                        break
                    headers['entries'].append([raw_name.decode('ascii'), raw_value.decode('latin-1')])
            elif isinstance(event, h11.Data):
                body.extend(event.data[:max_bytes-len(body)+1])
                if len(body) > max_bytes:
                    result['error'] = 'Response byte limit exceeded'
                    return
            elif isinstance(event, h11.EndOfMessage):
                result['body_status'] = 'completed'
                return
            elif not isinstance(event, h11.InformationalResponse) or event.status_code == 101:
                raise h11.RemoteProtocolError('Expected one HTTP response')
    finally:
        writer.transport.abort()


async def _bounded_collect(args, stop_event, timeout):
    async with asyncio.timeout(timeout):
        task = asyncio.create_task(_collect(*args))
        try:
            while True:
                finished, _ = await asyncio.wait((task,), timeout=.05)
                if finished:
                    return task.result()
                if stop_event.is_set():
                    raise _Canceled
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def fetch_lab_http(url, *, timeout, max_bytes, stop_event, tls_context=None):
    _require_active()
    started = time.monotonic()
    result = _new_observation(url)
    body = bytearray()
    try:
        if stop_event.is_set():
            raise _Canceled
        import requests

        request = requests.Request('GET', url).prepare()
        parsed = urlsplit(request.url)
        address = _lab_address(parsed.hostname)
        if parsed.scheme not in ('http', 'https') or parsed.username is not None:
            raise ValueError('A laboratory HTTP(S) URL without credentials is required')
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError
        asyncio.run(_bounded_collect((request, address, result, body, max_bytes, tls_context), stop_event, remaining))
    except EgressDenied:
        raise
    except _Canceled:
        result['error'] = 'Collection canceled'
    except TimeoutError:
        result['error'] = 'Response collection deadline exceeded'
    except ImportError:
        result.update(status='unavailable', error='Optional HTTP dependency unavailable')
    except Exception as error:
        result.update(status='error', error=type(error).__name__)
    _finish_observation(result, bytes(body), started)
    if result['body_status'] == 'completed':
        result['content_sha256'] = result['retained_sha256']
    return result
