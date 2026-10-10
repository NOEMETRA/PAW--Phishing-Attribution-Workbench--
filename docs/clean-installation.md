# Clean Windows installation validation

The wheel built from merged PR22 declared `Requires-Python: >=3.8`, despite
`pyproject.toml` requiring `>=3.11`. The legacy `setup.py` value still supplied
the wheel metadata. It now matches the project's Python requirement. This change
does not alter the engine, dependency ranges or analysis profiles.

`python tests/integration_wheel_metadata_real.py` builds an actual wheel outside
the checkout using the current tracked sources. It checks the distributed Python
requirement against `pyproject.toml`, the console entry point and the exact Python
source bytes. CI runs this check before the engine checks. Building the wheel is
not a dependency-install or analysis test.

On 2026-10-10, the corrected wheel was also installed on Windows in a new Python
3.13.5 virtual environment with `include-system-site-packages = false`, no
`PYTHONPATH` and user site packages disabled. All runtime dependencies were
installed through pip into that environment; host-installed dependencies were
not reused. `pip check` passed. The installed console command and API were run
from data directories outside the repository; installed Python sources matched
the wheel's archived sources.

Validation used 20 protected original EMLs with `full --no-egress`. The installed
worker completed all 20, stopped its process tree and preserved original bytes
and valid evidence seals. Numeric scores and attribution decisions matched the
prior CLI replay; all 20 remained Inconclusive. Descriptive metadata differed in
the recorded `tldextract` version on 14 cases, reflecting the fresh dependency
installation. This difference was checked against the installed distribution
version, rather than treated as a scoring change. The 180 compared evidence JSONs
matched apart from the separately reproduced per-run domain-age reference.

A real loopback HTTP API check uploaded one original EML, completed its offline
worker, read the completed case and exported the original bytes in a ZIP. Evidence
verification and process-tree stop checks passed. Packaged local static files
were served as an installation check; no UI functionality was added.

The first virtualenv attempt failed with Windows error 112 because the host's
`C:` volume had no free space. Validation and temporary files were placed on
another local volume. That failure occurred before installing PAW and is not
evidence of a package failure. Private messages and detailed logs remain outside
Git under restricted ACLs.

This validates the measured Windows installation and original-MIME offline
paths. It does not validate every supported Python/OS combination, MSG ingestion,
optional ML dependencies, browser binaries, online enrichment or the separate
Linux detonation lab. It does not establish classifier accuracy or reproduce
the historical four-hour online analysis. Dependency ranges remain ranges, not
a reproducible lockfile; the measured environment's freeze was retained locally.
