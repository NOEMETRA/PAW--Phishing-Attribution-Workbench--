"""Fixed local-file Chrome command; no user arguments, URL mode or sandbox bypass."""
from pathlib import Path

JOB_MEMORY = 512 * 1024**2
JOB_TASKS = 128
MAX_HTML = 512 * 1024
MAX_DOM = 256 * 1024
MAX_NETLOG = 1024**2
JOB_SECONDS = 15


def chrome_arguments(source, profile, netlog=None):
    for value in [source, profile, *([] if netlog is None else [netlog])]:
        if not isinstance(value, Path) or not value.is_absolute() or '..' in value.parts:
            raise ValueError('browser_fixed_local_paths_required')
    values = ['/opt/google/chrome/chrome', '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
              '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions',
              '--disable-dev-shm-usage', '--password-store=basic', '--user-data-dir=' + str(profile),
              '--virtual-time-budget=2000', '--timeout=5000', '--dump-dom']
    if netlog is not None: values += ['--log-net-log=' + str(netlog), '--net-log-capture-mode=Default']
    return values + [source.as_uri()]
