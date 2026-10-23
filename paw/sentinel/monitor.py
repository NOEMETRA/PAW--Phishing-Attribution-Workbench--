"""In-process Sentinel HTTP observations; service deployment and rendering are separate."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import contextmanager
import copy
import base64
import threading
import time

from .config import SentinelConfig, _require_active
from .contracts import _json_tree, _json_chunks
from .database import CampaignDatabase
from .transport import fetch_http, positive_number, native_integer
from ..deobfuscate.url import http_url_status


class SentinelMonitor:
    def __init__(self, config=None, database=None):
        self.config = SentinelConfig() if config is None else config
        self.db = CampaignDatabase(**self.config.get_database_options()) if database is None else database
        self._running = False; self._thread = None; self._executor = None
        self._state = threading.Condition(threading.RLock())
        self._stop_event = threading.Event(); self._operation_lock = threading.RLock()
        self._operations = set(); self._last_error = None; self._callback_errors = []
        self._callbacks = {name:[] for name in ('on_check_complete','on_alert','on_campaign_down',
                                               'on_campaign_up','on_content_changed')}

    def _settings(self):
        interval = positive_number(self.config.get('monitoring.check_interval_minutes',30),'interval',525600)*60
        workers = native_integer(self.config.get('monitoring.max_concurrent_checks',5),'workers',64)
        timeout = positive_number(self.config.get('monitoring.timeout_seconds',30),'timeout',300)
        return interval,workers,timeout

    def start(self):
        self._require_collector(); self._settings()
        with self._state:
            if self._thread is not None and self._thread.is_alive():
                if self._stop_event.is_set(): raise RuntimeError('Sentinel is still stopping')
                return
            if self._operations: raise RuntimeError('An immediate Sentinel check is still active')
            if self.config.get('monitoring.enabled',True) is not True:
                raise ValueError('Sentinel monitoring is disabled')
            self._stop_event.clear(); self._running = True
            self._thread = threading.Thread(target=self._monitor_loop,name='paw-sentinel-monitor',daemon=True)
            try: self._thread.start()
            except BaseException:
                self._running = False; self._thread = None; raise

    def stop(self, timeout=5):
        if type(timeout) not in (int,float) or not 0 <= timeout <= 300:
            raise ValueError('Stop timeout must be a finite native number in 0..300')
        deadline = time.monotonic()+timeout
        with self._state:
            self._stop_event.set(); thread = self._thread
            if threading.get_ident() in self._operations or thread is threading.current_thread(): return False
        if thread is not None: thread.join(max(0,deadline-time.monotonic()))
        with self._state:
            while self._operations and time.monotonic() < deadline:
                self._state.wait(max(0,deadline-time.monotonic()))
            stopped = not self._operations and (self._thread is None or not self._thread.is_alive())
            if stopped: self._running = False
            return stopped

    def is_running(self):
        with self._state:
            return self._running or bool(self._operations) or bool(self._thread and self._thread.is_alive())

    def add_campaign(self, case_id, url, metadata=None): return self.db.add_campaign(case_id,url,metadata)
    def remove_campaign(self, campaign_id): return self.db.remove_campaign(campaign_id)
    def get_campaign_status(self, campaign_id): return self.db.get_campaign(campaign_id)
    def get_all_campaigns(self): return self.db.get_active_campaigns()

    def _register(self, name, callback):
        if not callable(callback): raise ValueError('A callable Sentinel callback is required')
        with self._state:
            if len(self._callbacks[name]) >= 128: raise ValueError('Sentinel callback limit exceeded')
            self._callbacks[name].append(callback)

    def on_check_complete(self, callback): self._register('on_check_complete',callback)
    def on_alert(self, callback): self._register('on_alert',callback)
    def on_campaign_down(self, callback): self._register('on_campaign_down',callback)
    def on_campaign_up(self, callback): self._register('on_campaign_up',callback)
    def on_content_changed(self, callback): self._register('on_content_changed',callback)

    def get_stats(self):
        return {**self.db.get_monitor_statistics(),'is_running':self.is_running(),
                'is_running_scope':'this_instance_flag'}

    def get_runtime_state(self):
        with self._state:
            return {'state':('stopping' if self._stop_event.is_set() else 'running') if self.is_running() else 'stopped',
                'active_operations':len(self._operations),'last_error':self._last_error,
                'callback_errors':copy.deepcopy(self._callback_errors),'scope':'this_instance',
                'persistent_service':'unavailable','isolation':'not_established',
                'unavailable_capabilities':['browser_capture','fingerprinting','webhook_notifications',
                    'email_notifications','automatic_retries','automatic_retention','identity_and_risk'],
                'http_body_limit_bytes':128*1024}

    def _require_collector(self):
        _require_active()
        if self.db.read_only: raise RuntimeError('Read-only saved Sentinel storage cannot collect or publish observations')

    def _monitor_loop(self):
        try:
            self._require_collector()
            interval,_,_ = self._settings()
            while not self._stop_event.is_set():
                try: self._perform_checks()
                except Exception as error: self._last_error = type(error).__name__
                deadline = time.monotonic()+interval
                while not self._stop_event.is_set():
                    remaining = deadline-time.monotonic()
                    if remaining <= 0: break
                    self._stop_event.wait(min(remaining,60,threading.TIMEOUT_MAX))
        finally:
            with self._state:
                self._running = False; self._state.notify_all()

    @contextmanager
    def _operation(self):
        with self._operation_lock:
            identifier = threading.get_ident()
            with self._state:
                if self._stop_event.is_set(): raise RuntimeError('Sentinel stopping; no new check admitted')
                if identifier in self._operations: raise RuntimeError('Nested Sentinel collection is unavailable')
                self._operations.add(identifier)
            try: yield
            finally:
                with self._state:
                    self._operations.discard(identifier); self._state.notify_all()

    @staticmethod
    def _admit_campaign(campaign):
        if (type(campaign) is not dict or type(campaign.get('id')) is not str or not campaign['id'].strip()
                or type(campaign.get('url')) is not str or http_url_status(campaign['url'])[0] != 'completed'):
            raise ValueError('A named campaign with a complete HTTP(S) URL is required')
        return {'id':campaign['id'],'url':campaign['url']}

    def _perform_checks(self):
        self._require_collector()
        with self._operation():
            campaigns = [self._admit_campaign(value) for value in self.db.get_active_campaigns()]
            _,workers,_ = self._settings()
            with ThreadPoolExecutor(max_workers=workers,thread_name_prefix='paw-sentinel-http') as executor:
                self._executor = executor
                try:
                    pending = set(); source = iter(campaigns)
                    while True:
                        while not self._stop_event.is_set() and len(pending) < workers:
                            campaign = next(source,None)
                            if campaign is None: break
                            pending.add(executor.submit(self._check_campaign,campaign))
                        if not pending: break
                        completed,pending = wait(pending,timeout=.05,return_when=FIRST_COMPLETED)
                        for future in completed:
                            result = future.result()
                            if not self._stop_event.is_set(): self._handle_check_result(result)
                        if self._stop_event.is_set():
                            for future in pending: future.cancel()
                            break
                finally: self._executor = None

    def _check_campaign(self, campaign):
        self._require_collector(); campaign = self._admit_campaign(campaign)
        _,_,timeout = self._settings()
        observed = fetch_http(campaign['url'],timeout=timeout,max_bytes=128*1024,stop_event=self._stop_event)
        body = observed.pop('body'); code = observed['http_status']
        observed['body_base64'] = base64.b64encode(body).decode('ascii')
        status = ('up' if code < 400 else 'down') if observed['status']=='observed' else 'error'
        digest = observed['content_sha256'] if self.config.get('analysis.enable_content_diff',True) is True else None
        return {'campaign_id':campaign['id'],'url':campaign['url'],'status':status,
            'http_status':code,'response_time':observed['elapsed_seconds'],'content_hash':digest,
            'screenshot_path':None,'error_message':observed['error'],
            'metadata':{'http_observation':observed,'retained_body_bytes':len(body),
                'screenshot':{'status':'unavailable' if self.config.get('analysis.enable_screenshots',True) is True else 'not_requested',
                              'reason':'Browser capture requires the isolated collector validation'},
                'assessment':{'status':'unavailable','reason':'HTTP observations do not establish campaign liveness or identity'}}}

    def _take_screenshot(self, url, campaign_id):
        _require_active()
        raise NotImplementedError('Sentinel browser capture is unavailable until isolated collector validation')

    def _emit(self, name, payload):
        with self._state: callbacks = tuple(self._callbacks[name])
        for callback in callbacks:
            try: callback(copy.deepcopy(payload))
            except Exception as error:
                with self._state:
                    self._callback_errors.append({'event':name,'error':type(error).__name__})
                    self._callback_errors[:] = self._callback_errors[-100:]

    def _handle_check_result(self, result):
        self._require_collector()
        if self._stop_event.is_set(): return None
        result = _json_tree(result)
        flags = {key:self.config.get('alerts.'+key,default) for key,default in
                 (('enabled',True),('alert_on_down',True),('alert_on_up',False),('alert_on_changes',True))}
        receipt = self.db._record_monitor_result(result,flags)
        published = {**result,**{key:receipt[key] for key in ('check_id','previous_check_id','content_changed')}}
        self._emit('on_check_complete',published)
        for event in receipt['events']:
            self._emit({'up':'on_campaign_up','down':'on_campaign_down','changed':'on_content_changed'}[event],published)
        for alert in receipt['alerts']: self._emit('on_alert',alert)
        return published

    def _check_for_alerts(self, result):
        _require_active()
        raise NotImplementedError('Use atomic monitor result publication; standalone alert inference is unavailable')

    def _trigger_alert(self, campaign_id, alert_type, message, severity='info'):
        _require_active()
        raise NotImplementedError('Monitor alerts must be committed with their source observation')

    def check_now(self, campaign_id=None):
        self._require_collector()
        if campaign_id is not None and (type(campaign_id) is not str or not campaign_id.strip()):
            raise ValueError('campaign_id requires a nonblank string or None')
        with self._state:
            if self._stop_event.is_set():
                if self.is_running(): raise RuntimeError('Sentinel is still stopping')
                self._stop_event.clear()
        with self._operation():
            selected = ([self.db.get_campaign(campaign_id)] if campaign_id is not None else self.db.get_active_campaigns())
            campaigns = [self._admit_campaign(value) for value in selected if value is not None]
            results = []; size = 2
            for campaign in campaigns:
                if self._stop_event.is_set(): break
                result = self._check_campaign(campaign)
                published = self._handle_check_result(result)
                if published is None: continue
                size += sum(len(chunk) for chunk in _json_chunks(published,self.db.limits['max_result_bytes']))+1
                if size > self.db.limits['max_result_bytes']:
                    raise ValueError('Immediate check result byte limit exceeded; earlier per-check commits remain, no complete batch result')
                results.append(published)
            return results
