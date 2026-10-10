# Canary automatic alerts are unavailable

The legacy canary collector and its automatic SMTP alert sender have been
removed from the deployment path. Canary entry points deliberately exit nonzero
before starting a listener, accessing cases or delivering mail.

The previous instructions for SMTP variables and provider app passwords are
retired. Configuring credentials does not enable the removed workflow; this
feature does not require new SMTP credentials.

See [canary status](docs/canary-status.md). Future collection is deferred to the
isolated lab with separate observation storage that preserves sealed cases.
An observed request alone cannot identify a phishing operator or establish that
the requester is a victim. No automatic victim-notification workflow is provided.
