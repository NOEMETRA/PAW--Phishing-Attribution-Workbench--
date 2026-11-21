"""Foreground HTTP monitoring of explicitly selected laboratory origins on Linux."""
import json
import os
import signal
import sys
import time

from .config import SentinelConfig
from .contracts import (_admit_storage_path, _require_active, _storage_identity,
                        _storage_opener, _storage_path)
from .database import AlertDeliveryMissing, CampaignDatabase
from .delivery import send_saved_alert, webhook_destination
from .lab_transport import fetch_lab_http, lab_origin as _lab_origin, load_lab_ca
from .monitor import SentinelMonitor


class _LabMonitor(SentinelMonitor):
    def __init__(self, config, database, origins, *, webhook_fingerprint=None, tls_context=None):
        super().__init__(config, database, webhook_fingerprint=webhook_fingerprint)
        self.origins = origins
        self.tls_context = tls_context
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

    def _collect_http(self, url, *, timeout, max_bytes):
        return fetch_lab_http(url, timeout=timeout, max_bytes=max_bytes,
                              stop_event=self._stop_event, tls_context=self.tls_context)


def _event(name, **fields):
    sys.stdout.write(json.dumps({'event': name, **fields}) + '\n')
    sys.stdout.flush()


def run_foreground(origins, webhook=None, *, ca_file=None):
    _require_active()
    if not sys.platform.startswith('linux'):
        raise RuntimeError('Foreground Sentinel supervision currently requires Linux')
    import fcntl
    if not origins:
        raise ValueError('monitor run requires --origin for an owned laboratory HTTP service')
    origins = frozenset(_lab_origin(value) for value in origins)
    target = webhook_destination(webhook) if webhook is not None else None
    tls_context = load_lab_ca(ca_file) if ca_file is not None else None
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
        monitor = _LabMonitor(config, database, origins, webhook_fingerprint=target[1] if target else None,
                              tls_context=tls_context)
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
            if not stopping:
                stopping = True
                monitor._stop_event.set()

        previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            monitor.start()
            try:
                _event('started', pid=os.getpid())
                next_delivery = time.monotonic()
                while not stopping:
                    state = monitor.get_runtime_state()
                    if stopping:
                        break
                    if state['last_error'] or state['callback_errors'] or state['state'] != 'running':
                        raise RuntimeError(f"Sentinel cycle failed: {state['last_error'] or state['callback_errors'] or state['state']}")
                    if target and time.monotonic() >= next_delivery:
                        next_delivery = time.monotonic() + 1
                        candidate = database.next_automatic_alert(target[1])
                        if candidate and not stopping:
                            campaign_id, alert_id = candidate
                            try:
                                receipt = send_saved_alert(database, campaign_id, alert_id, target,
                                                           tls_context=tls_context)
                            except AlertDeliveryMissing:
                                _event('webhook_alert_missing', campaign_id=campaign_id, alert_id=alert_id)
                            else:
                                _event('webhook_delivery', campaign_id=campaign_id, alert_id=alert_id,
                                       event_id=receipt['event_id'], status=receipt['status'],
                                       attempts=receipt['attempts'], error=receipt['error'])
                    time.sleep(.1)
            finally:
                while not monitor.stop(timeout=1):
                    pass
                _event('stopped', active_operations=monitor.get_runtime_state()['active_operations'])
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
