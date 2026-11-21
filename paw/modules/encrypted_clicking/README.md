# Encrypted Clicking prototype

The privileged bootstrap, module Compose services and Python image builder
are retired. The historical implementation is preserved in Git history.
The bootstrap entry point exits with a diagnostic. The archived Compose
file defines zero services.

The package reader still authenticates and decrypts previously saved
evidence with the supplied session password. The local cryptographic
round-trip is exercised by `tests/integration_crypto_real.py`.

Use the [PAW Quick Start](../../../QUICKSTART.md) for offline EML analysis.
The [S14 isolation protocol](../../../docs/s14-controlled-uplink.md) tracks
the acceptance criteria for controlled network and browser collection.
