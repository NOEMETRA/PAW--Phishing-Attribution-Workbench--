# paw/sentinel/__init__.py
"""
Sentinel: local campaign records, saved-data reports and file observations.

Stored claims remain unverified. Active collectors and service lifecycle require
the separate controlled-egress validation; offline policy rejects those paths.
"""

__version__ = "1.0.0"
__author__ = "PAW Team"

__all__ = ['SentinelConfig', 'SentinelMonitor', 'CampaignDatabase', 'FileMonitor', 'IPAnalyzer', 'IntelligenceAnalyzer']


def __getattr__(name):
    # Local integrity monitoring must not import optional geographic plotting.
    from importlib import import_module
    modules = {'SentinelConfig':'config', 'SentinelMonitor':'monitor',
               'CampaignDatabase':'database', 'FileMonitor':'file_monitor',
               'IPAnalyzer':'ip_analyzer', 'IntelligenceAnalyzer':'intelligence_analyzer'}
    if name not in modules: raise AttributeError(name)
    value = getattr(import_module('.'+modules[name], __name__), name)
    globals()[name] = value
    return value
