# paw/sentinel/config.py
"""
Configuration management for Sentinel monitoring module.
"""
import os
import json
import copy
import math
import stat
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Dict, Any, Optional


from .contracts import (_resource_limits, _json_tree, _json_chunks, _bounded_report,
    _require_active, _encode_writer_json, _storage_directory, _storage_path,
    _admit_storage_path, _storage_identity, _storage_stamp, _storage_opener)


class SentinelConfig:
    """Configuration manager for Sentinel monitoring."""

    def __init__(self, config_file: str = None):
        self._base_dir = Path.cwd()
        self.config_file = str(_storage_path('sentinel_config.json' if config_file is None else config_file))
        self._source_stamp = None
        self._explicit_database = False
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create defaults."""
        path = Path(self.config_file)
        metadata = _admit_storage_path(path)
        if metadata is None:
            return self._get_defaults()
        if metadata.st_size > 1024**2:
            raise ValueError('Sentinel configuration byte limit exceeded')
        with open(path, 'rb', opener=_storage_opener) as source:
            if _storage_stamp(os.fstat(source.fileno())) != _storage_stamp(metadata):
                raise OSError('Configuration changed before reading')
            raw = source.read(1024**2 + 1)
            if len(raw) > 1024**2:
                raise ValueError('Sentinel configuration byte limit exceeded')
            if (_storage_stamp(os.fstat(source.fileno())) != _storage_stamp(metadata) or
                    _storage_stamp(_admit_storage_path(path, must_exist=True)) != _storage_stamp(metadata)):
                raise OSError('Configuration changed during reading')
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError('Duplicate Sentinel configuration key')
                result[key] = value
            return result
        def finite_number(value):
            number = float(value)
            if not math.isfinite(number): raise ValueError('Non-finite Sentinel configuration number')
            return number
        config = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                            parse_constant=finite_number, parse_float=finite_number)
        self._validate_config(config)
        _json_tree(config)
        self._explicit_database = isinstance(config.get('storage'), dict) and 'database_path' in config['storage']
        self._source_stamp = _storage_stamp(metadata)
        return config or self._get_defaults()

    def _validate_config(self, config):
        if not isinstance(config, dict):
            raise ValueError('Sentinel configuration must be an object')
        for section in ('monitoring', 'alerts', 'analysis', 'storage'):
            if section in config and type(config[section]) is not dict:
                raise ValueError(f'Sentinel {section} configuration must be an object')
        if 'storage' in config:
            if not isinstance(config['storage'], dict):
                raise ValueError('Sentinel storage configuration must be an object')
            if 'database_path' in config['storage']:
                _storage_path(config['storage']['database_path'], base=self._base_dir)
            if 'limits' in config['storage']: _resource_limits(config['storage']['limits'])

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "monitoring": {
                "enabled": True,
                "check_interval_minutes": 30,  # Check campaigns every 30 minutes
                "max_concurrent_checks": 5,    # Max parallel checks
                "timeout_seconds": 30,         # Timeout for each check
                "max_retries": 3,             # Retry failed checks
            },
            "alerts": {
                "enabled": True,
                "webhook_url": None,          # Optional webhook for alerts
                "email_alerts": False,        # Email notifications
                "alert_on_changes": True,     # Alert when content changes
                "alert_on_down": True,        # Alert when site goes down
                "alert_on_up": False,         # Alert when site comes back up
            },
            "storage": {
                "database_path": "sentinel.db",
                "screenshots_dir": "screenshots",
                "max_screenshots_per_campaign": 50,
                "retention_days": 90,         # Keep data for 90 days
            },
            "analysis": {
                "enable_screenshots": True,
                "enable_content_diff": True,
                "enable_fingerprinting": True,
                "screenshot_resolution": "1280x720",
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key."""
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            if key == 'storage.database_path' and value is not None:
                return str(_storage_path(value, base=self._base_dir))
            return copy.deepcopy(value)
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot-notation key."""
        keys = key.split('.')
        candidate = copy.deepcopy(self._config)
        config = candidate
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self._save_config(candidate)
        self._config = candidate

    def _save_config(self, candidate) -> None:
        """Save configuration to file."""
        self._validate_config(candidate)
        candidate = _json_tree(candidate)
        encoded = ''.join(_json_chunks(candidate, 1024**2, indent=2)).encode('ascii')
        if len(encoded) > 1024**2:
            raise ValueError('Sentinel configuration byte limit exceeded')
        path = Path(self.config_file)
        def unchanged():
            metadata = _admit_storage_path(path)
            if (None if metadata is None else _storage_stamp(metadata)) != self._source_stamp:
                raise ValueError('Sentinel configuration source changed; reload before saving')
        unchanged()
        path.parent.mkdir(parents=True, exist_ok=True)
        _admit_storage_path(path)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.sentinel-config-', delete=False) as output:
                temporary = Path(output.name)
                output.write(encoded)
            published_stamp = _storage_stamp(_admit_storage_path(temporary, must_exist=True))
            unchanged()
            os.replace(temporary, path)
            temporary = None
            self._source_stamp = published_stamp
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)

    def reset_to_defaults(self) -> None:
        """Reset configuration to default values."""
        candidate = self._get_defaults()
        self._save_config(candidate)
        self._config = candidate

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring-specific configuration."""
        return copy.deepcopy(self._config.get("monitoring", {}))

    def get_alert_config(self) -> Dict[str, Any]:
        """Get alert-specific configuration."""
        return copy.deepcopy(self._config.get("alerts", {}))

    def get_storage_config(self) -> Dict[str, Any]:
        """Get storage-specific configuration."""
        values = copy.deepcopy(self._config.get("storage", {}))
        if 'database_path' in values: values['database_path'] = self.get('storage.database_path')
        return values

    def get_database_options(self):
        return {'db_path': self.get('storage.database_path'), 'limits': self.get('storage.limits')}

    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis-specific configuration."""
        return copy.deepcopy(self._config.get("analysis", {}))


def configured_database_options(config_file='sentinel_config.json', *, require_explicit=False):
    config = SentinelConfig(config_file)
    if require_explicit and config._source_stamp is not None and not config._explicit_database:
        raise ValueError('Sentinel configuration requires a nonblank storage.database_path')
    return config.get_database_options()
