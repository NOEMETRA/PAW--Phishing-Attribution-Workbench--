"""Receipt-based delivery of saved alerts to an owned laboratory receiver."""
import hashlib
import ipaddress
from urllib.parse import urlsplit, urlunsplit

from .config import SentinelConfig
from .contracts import _require_active
from .database import CampaignDatabase


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


def deliver_saved_alert(campaign_id, alert_id, destination):
    target = webhook_destination(destination)
    database = CampaignDatabase(**SentinelConfig().get_database_options(), initialize=False)
    return send_saved_alert(database, campaign_id, alert_id, target)


def send_saved_alert(database, campaign_id, alert_id, target):
    _require_active()
    import requests

    endpoint, fingerprint = webhook_destination(target[0])
    if fingerprint != target[1]:
        raise ValueError('Webhook destination fingerprint changed')
    state, alert_type = database.start_alert_delivery(campaign_id, alert_id, fingerprint)
    if state['status'] == 'receipt_confirmed':
        return state
    event_id = state['event_id']
    payload = {'event_id':event_id, 'campaign_id':campaign_id, 'alert_id':alert_id, 'alert_type':alert_type}
    code = None
    try:
        with requests.Session() as session:
            request = requests.Request('POST', endpoint, json=payload,
                                       headers={'Idempotency-Key':event_id}).prepare()
            # The adapter performs a single request. It doesn't resolve redirects
            # or consume the redirect body while preparing a potential next hop.
            adapter = session.get_adapter(endpoint)
            with adapter.send(request, timeout=3, stream=True, verify=True, proxies={}) as response:
                code = response.status_code
                if not 200 <= code < 300:
                    outcome = 'http_status'
                elif response.headers.get('Sentinel-Receipt') == event_id:
                    outcome = 'receipt_confirmed'
                else:
                    outcome = 'receipt_missing'
    except requests.RequestException:
        outcome = 'transport_error'
    return database.finish_alert_delivery(campaign_id, alert_id, state, outcome, code)
