# paw/sentinel/monitor.py
"""
Core monitoring engine for Sentinel.
"""
import time
import threading
import hashlib
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import SentinelConfig, _require_active
from .database import CampaignDatabase
from ..util.fsutil import ensure_dir
from ..util.timeutil import utc_now_iso


class SentinelMonitor:
    """Core monitoring engine for phishing campaigns."""

    def __init__(self, config: SentinelConfig = None, database: CampaignDatabase = None):
        self.config = SentinelConfig() if config is None else config
        self.db = CampaignDatabase(**self.config.get_database_options()) if database is None else database
        self._running = False
        self._thread = None
        self._executor = None
        self._callbacks = {
            'on_check_complete': [],
            'on_alert': [],
            'on_campaign_down': [],
            'on_campaign_up': [],
            'on_content_changed': []
        }

    def start(self) -> None:
        """Start the monitoring service."""
        _require_active()
        if self._running:
            return

        self._running = True
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.get("monitoring.max_concurrent_checks", 5)
        )

        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

        print(f"[sentinel] Monitoring started - checking every "
              f"{self.config.get('monitoring.check_interval_minutes')} minutes")

    def stop(self) -> None:
        """Stop the monitoring service."""
        self._running = False
        if self._executor:
            self._executor.shutdown(wait=True)
        if self._thread:
            self._thread.join(timeout=5)
        print("[sentinel] Monitoring stopped")

    def is_running(self) -> bool:
        """Check if monitoring is running."""
        return self._running

    def add_campaign(self, case_id: str, url: str, metadata: Dict[str, Any] = None) -> str:
        """Add a campaign to monitoring."""
        return self.db.add_campaign(case_id, url, metadata)

    def remove_campaign(self, campaign_id: str) -> bool:
        """Remove a campaign from monitoring."""
        return self.db.remove_campaign(campaign_id)

    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a campaign."""
        return self.db.get_campaign(campaign_id)

    def get_all_campaigns(self) -> List[Dict[str, Any]]:
        """Get all monitored campaigns."""
        return self.db.get_active_campaigns()

    def on_check_complete(self, callback: Callable) -> None:
        """Register callback for check completion."""
        self._callbacks['on_check_complete'].append(callback)

    def on_alert(self, callback: Callable) -> None:
        """Register callback for alerts."""
        self._callbacks['on_alert'].append(callback)

    def on_campaign_down(self, callback: Callable) -> None:
        """Register callback for campaign going down."""
        self._callbacks['on_campaign_down'].append(callback)

    def on_campaign_up(self, callback: Callable) -> None:
        """Register callback for campaign coming back up."""
        self._callbacks['on_campaign_up'].append(callback)

    def on_content_changed(self, callback: Callable) -> None:
        """Register callback for content changes."""
        self._callbacks['on_content_changed'].append(callback)

    def get_stats(self) -> Dict[str, Any]:
        """Stored row counts and this instance's flag, not global service status."""
        return {**self.db.get_monitor_statistics(),
                'is_running': self.is_running(), 'is_running_scope': 'this_instance_flag'}

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        interval_seconds = self.config.get("monitoring.check_interval_minutes", 30) * 60

        while self._running:
            try:
                self._perform_checks()
                time.sleep(interval_seconds)
            except Exception as e:
                print(f"[sentinel] Error in monitor loop: {e}")
                time.sleep(60)  # Wait a minute before retrying

    def _perform_checks(self) -> None:
        """Perform monitoring checks for all active campaigns."""
        _require_active()
        campaigns = self.db.get_active_campaigns()
        if not campaigns:
            return

        print(f"[sentinel] Checking {len(campaigns)} campaigns...")

        # Submit checks to thread pool
        futures = []
        for campaign in campaigns:
            future = self._executor.submit(self._check_campaign, campaign)
            futures.append(future)

        # Wait for completion
        for future in as_completed(futures):
            try:
                result = future.result()
                self._handle_check_result(result)
            except Exception as e:
                print(f"[sentinel] Check failed: {e}")

    def _check_campaign(self, campaign: Dict[str, Any]) -> Dict[str, Any]:
        """Check a single campaign."""
        _require_active()
        campaign_id = campaign['id']
        url = campaign['url']

        result = {
            'campaign_id': campaign_id,
            'url': url,
            'status': 'error',
            'response_time': None,
            'http_status': None,
            'content_hash': None,
            'screenshot_path': None,
            'error_message': None,
            'metadata': {}
        }

        try:
            import requests
            from urllib.parse import urlparse

            # Make HTTP request
            start_time = time.time()
            response = requests.get(
                url,
                timeout=self.config.get("monitoring.timeout_seconds", 30),
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time

            result.update({
                'status': 'up' if response.status_code < 400 else 'down',
                'response_time': response_time,
                'http_status': response.status_code,
            })

            # Get content hash if enabled
            if self.config.get("analysis.enable_content_diff", True):
                content_hash = hashlib.sha256(response.content).hexdigest()
                result['content_hash'] = content_hash

                # Check for content changes
                previous_checks = self.db.get_recent_checks(campaign_id, limit=1)
                if previous_checks:
                    prev_hash = previous_checks[0].get('content_hash')
                    if prev_hash and prev_hash != content_hash:
                        result['content_changed'] = True
                        result['previous_hash'] = prev_hash

            # Take screenshot if enabled
            if self.config.get("analysis.enable_screenshots", True):
                screenshot_path = self._take_screenshot(url, campaign_id)
                if screenshot_path:
                    result['screenshot_path'] = screenshot_path

        except requests.exceptions.RequestException as e:
            result.update({
                'status': 'down',
                'error_message': str(e)
            })
        except Exception as e:
            result.update({
                'status': 'error',
                'error_message': str(e)
            })

        return result

    def _take_screenshot(self, url: str, campaign_id: str) -> Optional[str]:
        """Take a screenshot of the URL."""
        _require_active()
        try:
            from playwright.sync_api import sync_playwright

            screenshots_dir = self.config.get("storage.screenshots_dir", "screenshots")
            ensure_dir(screenshots_dir)

            timestamp = int(datetime.now().timestamp())
            filename = f"{campaign_id}_{timestamp}.png"
            filepath = os.path.join(screenshots_dir, filename)

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_viewport_size({"width": 1280, "height": 720})

                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle')

                page.screenshot(path=filepath, full_page=True)
                browser.close()

            return filepath

        except Exception as e:
            print(f"[sentinel] Screenshot failed for {url}: {e}")
            return None

    def _handle_check_result(self, result: Dict[str, Any]) -> None:
        """Handle the result of a campaign check."""
        campaign_id = result['campaign_id']

        # Record the check in database
        self.db.record_check(
            campaign_id=campaign_id,
            status=result['status'],
            response_time=result.get('response_time'),
            http_status=result.get('http_status'),
            content_hash=result.get('content_hash'),
            screenshot_path=result.get('screenshot_path'),
            error_message=result.get('error_message'),
            metadata=result.get('metadata', {})
        )

        # Trigger callbacks
        for callback in self._callbacks['on_check_complete']:
            try:
                callback(result)
            except Exception as e:
                print(f"[sentinel] Callback error: {e}")

        # Handle alerts
        self._check_for_alerts(result)

    def _check_for_alerts(self, result: Dict[str, Any]) -> None:
        """Check if alerts should be triggered."""
        campaign_id = result['campaign_id']
        status = result['status']

        # Get previous status
        previous_checks = self.db.get_recent_checks(campaign_id, limit=1)
        previous_status = previous_checks[0]['status'] if previous_checks else None

        # Campaign went down
        if status in ['down', 'error'] and previous_status == 'up':
            if self.config.get("alerts.alert_on_down", True):
                self._trigger_alert(campaign_id, 'down',
                                  f"Campaign {campaign_id} went down", 'warning')

        # Campaign came back up
        elif status == 'up' and previous_status in ['down', 'error']:
            if self.config.get("alerts.alert_on_up", False):
                self._trigger_alert(campaign_id, 'up',
                                  f"Campaign {campaign_id} came back up", 'info')

        # Content changed
        if result.get('content_changed') and self.config.get("alerts.alert_on_changes", True):
            self._trigger_alert(campaign_id, 'changed',
                              f"Campaign {campaign_id} content changed", 'info')

    def _trigger_alert(self, campaign_id: str, alert_type: str, message: str,
                      severity: str = 'info') -> None:
        """Trigger an alert."""
        self.db.record_alert(campaign_id, alert_type, message, severity)

        # Trigger callbacks
        for callback in self._callbacks['on_alert']:
            try:
                callback({
                    'campaign_id': campaign_id,
                    'type': alert_type,
                    'message': message,
                    'severity': severity,
                    'timestamp': utc_now_iso()
                })
            except Exception as e:
                print(f"[sentinel] Alert callback error: {e}")

        print(f"[sentinel] ALERT: {message}")

    def check_now(self, campaign_id: str = None) -> List[Dict[str, Any]]:
        """Perform immediate checks for campaigns."""
        _require_active()
        if campaign_id:
            campaign = self.db.get_campaign(campaign_id)
            campaigns = [campaign] if campaign else []
        else:
            campaigns = self.db.get_active_campaigns()

        if not campaigns:
            return []

        results = []
        print(f"[sentinel] Checking {len(campaigns)} campaigns...")

        for campaign in campaigns:
            result = self._check_campaign(campaign)
            self._handle_check_result(result)
            results.append(result)

        print(f"[sentinel] Check complete - {len(results)} campaigns processed")
        return results
