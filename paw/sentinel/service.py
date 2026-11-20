"""Foreground HTTP monitoring of explicitly selected laboratory origins on Linux."""
import ipaddress
import json
import os
import signal
import sys
import time
from urllib.parse import urlsplit

from .config import SentinelConfig
from .contracts import (_admit_storage_path, _require_active, _storage_identity,
                        _storage_opener, _storage_path)
from .database import CampaignDatabase
from .monitor import SentinelMonitor


def _lab_origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or '%' in parsed.hostname:
        raise ValueError('Specify an HTTP(S) origin with a literal laboratory address')
    address = ipaddress.ip_address(parsed.hostname)
    lab_ranges = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7',
                  '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')
    if not (address.is_loopback or any(address in ipaddress.ip_network(net) for net in lab_ranges)):
        raise ValueError('Foreground monitoring requires a loopback, private or documentation-prefix address')
    host = f'[{address}]' if address.version == 6 else str(address)
    port = parsed.port
    origin = f'{parsed.scheme}://{host}' + (f':{port}' if port is not None else '')
    if value != origin:
        raise ValueError('Specify the canonical origin without credentials, path, query or fragment')
    return origin


class _LabMonitor(SentinelMonitor):
    def __init__(self, config, database, origins):
        super().__init__(config, database)
        self.origins = origins
        self.next_cleanup = 0

    def _perform_checks(self):
        if self.config.get('storage.automatic_retention', False) and time.monotonic() >= self.next_cleanup:
            result = self.db.cleanup_old_data(
                self.config.get('storage.retention_days', 90),
                alert_retention_days=self.config.get('storage.alert_retention_days'),
                body_retention_days=self.config.get('storage.body_retention_days'))
            _event('retention', cutoffs_utc=result['cutoffs_utc'], deleted=result['deleted'],
                   expired_bodies=result['expired_bodies'],
                   uninterpretable_bodies=len(result['uninterpretable_body_ids']),
                   uninterpretable={table: len(ids) for table, ids in result['retained_uninterpretable'].items()})
            self.next_cleanup = time.monotonic() + 86400
        super()._perform_checks()

    def _admit_campaign(self, campaign):
        admitted = super()._admit_campaign(campaign)
        url = admitted['url']
        if not any(url == origin or url.startswith(origin + '/') for origin in self.origins):
            raise ValueError('Active campaign outside the selected laboratory origins')
        return admitted


def _event(name, **fields):
    sys.stdout.write(json.dumps({'event': name, **fields}) + '\n')
    sys.stdout.flush()


def run_foreground(origins):
    _require_active()
    if not sys.platform.startswith('linux'):
        raise RuntimeError('Foreground Sentinel supervision currently requires Linux')
    import fcntl
    if not origins:
        raise ValueError('monitor run requires --origin for an owned laboratory HTTP service')
    origins = frozenset(_lab_origin(value) for value in origins)
    config = SentinelConfig()
    options = config.get_database_options()
    path = _storage_path(options['db_path'])
    before = _admit_storage_path(path, must_exist=True)
    with open(path, 'rb', opener=_storage_opener) as lock:
        identity = _storage_identity(os.fstat(lock.fileno()))
        if identity != _storage_identity(before):
            raise ValueError('Sentinel database replaced before service admission')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('A foreground monitor already owns this database') from None
        database = CampaignDatabase(**options)
        if database._source_identity != identity:
            raise ValueError('Sentinel database replaced during service admission')
        monitor = _LabMonitor(config, database, origins)
        for campaign in database.get_active_campaigns():
            monitor._admit_campaign(campaign)
        monitor.on_check_complete(lambda row: _event('check_committed', campaign_id=row['campaign_id'],
                                                     check_id=row['check_id'], status=row['status']))
        monitor.on_alert(lambda row: _event('alert_committed', campaign_id=row['campaign_id'],
                                            alert_id=row['id'], check_id=row['check_id'],
                                            alert_type=row['type'], external_delivery='not_attempted'))
        stopping = False

        def request_stop(signum, frame):
            nonlocal stopping
            stopping = True

        previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            monitor.start()
            try:
                _event('started', pid=os.getpid())
                while not stopping:
                    state = monitor.get_runtime_state()
                    if state['last_error'] or state['callback_errors'] or state['state'] != 'running':
                        raise RuntimeError(f"Sentinel cycle failed: {state['last_error'] or state['callback_errors'] or state['state']}")
                    time.sleep(.1)
            finally:
                while not monitor.stop(timeout=1):
                    pass
                _event('stopped', active_operations=monitor.get_runtime_state()['active_operations'])
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
