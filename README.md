# PAW — Phishing Attribution Workbench

**Email-forensics and infrastructure-correlation research workbench.**

PAW is a Python research project for turning suspicious email files into structured forensic cases.

Its strongest and most coherent workflow is:

```text
email file
  -> parse headers and message metadata
  -> normalize Received hops
  -> identify a likely transmitting boundary
  -> interpret authentication results
  -> extract and deobfuscate indicators
  -> enrich selected infrastructure
  -> score the case with explicit heuristics
  -> preserve evidence and generate reports
```

PAW also contains experimental browser detonation, canary, infrastructure-mapping, threat-intelligence, campaign-correlation, and attribution-matrix modules.

Those experimental layers should not be interpreted as an automated identity-attribution system. PAW can correlate infrastructure and generate hypotheses; it does not prove who operated a phishing campaign.

## Project status

PAW is a **research workbench**, not a production incident-response platform or an attribution oracle.

| Area | Current status |
|---|---|
| `.eml` parsing | Implemented |
| `.msg` parsing | Implemented through `extract-msg`, with format-specific limitations |
| Case creation and input hashing | Implemented |
| Received-path normalization | Implemented heuristically |
| MX/trust-boundary classification | Implemented heuristically |
| SPF/DKIM/DMARC result interpretation | Implemented from message headers |
| ARC and Received-SPF parsing | Implemented |
| DMARC policy DNS lookup | Implemented |
| Independent end-to-end DKIM verification in the main trace path | Not established |
| URL extraction | Implemented |
| Content deobfuscation | Implemented experimentally |
| Attachment inspection | Implemented for selected formats |
| RDAP / infrastructure enrichment | Implemented where network access is available |
| Case scoring | Implemented as hand-authored heuristics |
| Local case index and indicator query | Implemented |
| Evidence manifest / Merkle utilities | Implemented |
| Optional PGP manifest signing | Implemented when a key is configured |
| STIX export | Implemented |
| Abuse-package generation | Implemented as report/package generation |
| Playwright detonation | Implemented experimentally |
| Network request logging | Implemented during detonation |
| Resource collection / static kit analysis | Implemented experimentally |
| Canary logging | Implemented experimentally |
| Infrastructure correlation | Implemented |
| Operator identity attribution | Not established |
| Automated legal attribution | Not claimed |
| Production readiness | Not claimed |

## Repository philosophy

The useful distinction in PAW is between three kinds of output.

### Observation

Data directly present in an email or collected during a controlled measurement.

Examples:

- a `Received` header contains a particular IP;
- an `Authentication-Results` header reports `spf=fail`;
- a detonation browser requested a particular hostname;
- a certificate contains a particular public-key fingerprint.

### Inference

A conclusion derived from one or more observations.

Examples:

- a public hop is the likely external ingress point;
- two domains may share infrastructure;
- a domain resembles a protected brand;
- two campaigns may be related because they share a tracker or TLS key.

### Attribution hypothesis

A claim about a person, group, operator, geography, or criminal organization.

This is the weakest category unless supported by evidence independent of PAW's own heuristics.

PAW should preserve the observations and correlations even when the attribution hypothesis remains unknown.

## Core workflow

### 1. Email ingestion

The main CLI accepts a single email or a directory of email files.

The current parser extracts fields including:

- `From`;
- `Reply-To`;
- `Return-Path`;
- `Message-ID`;
- `Date`;
- `Subject`;
- `Received` headers;
- `Authentication-Results`;
- ARC headers;
- `Received-SPF`.

`.eml` files use Python's standard email parser. `.msg` support uses `extract-msg` and depends on which transport headers are available in the original Outlook message.

### 2. Case preservation

Each analysis creates a case directory under:

```text
cases/
```

The original input is copied into the case and its BLAKE3 hash is stored in `manifest.json`.

When `PAW_PGP_PRIV` is configured, the manifest can also be signed.

This provides useful evidence-integrity metadata, but PAW does not by itself establish a legal chain of custody. Collection procedure, analyst identity, system time, acquisition method, storage controls, and external documentation still matter.

### 3. Received-path reconstruction

`paw/core/received.py` parses `Received` lines into a normalized hop representation.

It attempts to extract:

- `from` host;
- `by` host;
- IP address;
- protocol;
- HELO value;
- timestamp;
- PTR result;
- basic timestamp skew;
- a trust-boundary role.

The trace pipeline then chooses a likely origin candidate using a sequence of fallbacks, preferring public hops classified as external ingress.

This is a **transmitting-path hypothesis**, not proof of the original human sender.

Email paths can contain:

- compromised mail servers;
- forwarding systems;
- SaaS relays;
- mailing infrastructure;
- NAT;
- spoofed or malformed headers before the first trusted boundary;
- legitimate cloud providers used by an attacker.

A hosting IP should therefore be reported as infrastructure evidence, not automatically as attacker identity.

## Email authentication

PAW parses authentication information already present in the message and derives alignment information.

The main path currently uses:

- `Authentication-Results` for SPF, DKIM, and DMARC result strings;
- `Received-SPF`;
- ARC headers;
- `From` and `Return-Path` domains;
- DNS lookup of the sender domain's DMARC policy.

This is not equivalent to independently reproducing the receiver's complete authentication process.

In particular:

- a parsed `dkim=pass` value means a receiving system reported that result;
- the core trace path does not establish that PAW independently revalidated the DKIM signature against the exact raw message bytes;
- SPF depends on the connecting IP and receiver context, which may not be reconstructable from a forwarded message;
- DMARC alignment in PAW is simplified compared with a complete standards implementation;
- ARC interpretation is heuristic and should not be treated as independent cryptographic validation of the entire chain.

Authentication results are strong evidence when their provenance is trusted, but they are not absolute attribution evidence.

## Deobfuscation

The trace pipeline inspects body text, HTML, JavaScript, and URL-like strings for transformations such as:

- ordinary HTTP/HTTPS URLs;
- `hxxp` / `hxxps` forms;
- percent encoding;
- domain-like strings;
- selected character and encoding transformations.

Newly recovered URLs are added to the case as candidate indicators.

Deobfuscation can create false positives. A recovered string should be treated as a candidate IOC until its syntax, context, and provenance are verified.

## Heuristic scoring

`paw/core/scoring.py` calculates a case score from explicit rules.

Signals currently include combinations of:

- SPF/DKIM/DMARC and ARC results;
- header inconsistencies;
- newly registered domains;
- display-name and reply-to mismatches;
- selected TLDs;
- mixed-script domains;
- brand-string similarity;
- deobfuscation score;
- detonation artifacts;
- canary observations;
- enrichment artifacts;
- recurrence across indexed cases.

The result is a **heuristic score**, not a calibrated probability that an email is malicious.

For example, a value such as `0.85` should not be interpreted as "85% probability of phishing."

Weights and thresholds were chosen by the project and have not been demonstrated here against a large independently labeled corpus with measured precision, recall, false-positive rate, or calibration error.

The three profiles (`default`, `strict`, and `conservative`) change thresholds; they do not represent statistically validated operating points.

## Local case index

PAW can index completed cases and search recent records by indicators such as:

- IP;
- domain;
- ASN;
- organization.

Repeated infrastructure can be useful campaign evidence. Reuse does not prove common human ownership: hosting platforms, reverse proxies, registrars, analytics identifiers, and shared services can create legitimate overlap.

## Experimental detonation

PAW includes a Playwright-based detonation runner.

The current implementation can:

- launch Chromium;
- visit extracted URLs;
- record requests and responses;
- block `POST`, `PUT`, `PATCH`, and `DELETE` when observe-only mode is enabled;
- record downloads;
- optionally start `tcpdump`;
- save page HTML;
- download selected external JavaScript, CSS, and image resources;
- calculate hashes;
- perform static string analysis;
- generate enrichment files for trackers, TLS, DNS, redirects, forms, and other pivots.

### Important detonation boundary

"Observe only" does **not** mean side-effect free.

A browser `GET` can still:

- notify a remote server that the URL was visited;
- activate tracking pixels;
- consume single-use tokens;
- cause redirects;
- trigger server-side state changes in badly designed applications;
- execute JavaScript in the browser;
- initiate additional requests;
- download content.

The runner also performs additional HTTP requests when collecting resources.

Use detonation only from an isolated research environment with an appropriate outbound-network policy.

## Critical current issue: `--no-egress`

The CLI exposes `--no-egress`, and the selected value is stored in the case manifest.

**In the current code, that flag must not be treated as a reliable network kill switch.**

The trace pipeline contains network-dependent operations and automatic detonation paths that are not consistently gated by `no_egress`. For example, after URL discovery the current `trace_one()` path can invoke the detonation runner automatically, and later stages can perform RDAP, DNS, reverse-DNS, certificate, banner, and threat-intelligence enrichment.

Until this is corrected in code:

- do not rely on `--no-egress` for isolation;
- use an OS firewall, VM network policy, container/network namespace, or physically isolated environment when offline analysis is required;
- inspect the trace path before processing untrusted evidence;
- treat the manifest value as analyst intent, not enforcement evidence.

This is one of the highest-priority code fixes for PAW.

## Phishing-kit collection

During detonation, PAW can save page HTML and selected external resources and calculate a combined kit hash.

Static analysis currently searches for simple indicators such as:

- Telegram-style identifiers;
- email addresses;
- source-code comments;
- login/password/form strings;
- selected JavaScript network patterns.

These findings are useful pivots, not proof of authorship.

A username found in a copied script, for example, may belong to:

- the kit author;
- a reseller;
- a victim;
- a copied dependency;
- an analyst;
- an unrelated commenter.

## Infrastructure enrichment

PAW includes modules for several infrastructure observations, including combinations of:

- RDAP;
- DNS records;
- reverse DNS;
- server banners;
- TLS certificates;
- tracker identifiers;
- redirects;
- form structure;
- hosting and registrar metadata;
- optional external threat-intelligence sources.

Availability and accuracy vary by source.

Network metadata is especially time dependent. A domain, IP, certificate, ASN, or hosting account can change ownership or configuration after collection.

Every externally collected datum should therefore retain a timestamp and original source when used as evidence.

## Attribution Matrix

`paw/core/attribution_matrix.py` combines enrichment-derived correlation keys and produces hypotheses.

This module is experimental.

The current implementation includes a small hard-coded set of example operator profiles and performs substring matching against infrastructure and indicator strings.

Those profiles are not a validated threat-actor knowledge base.

The resulting names and regional labels **must not be treated as real criminal attribution**. They are demonstrations of how a correlation matrix might be structured.

A high score from this module means that several strings matched one of the built-in profiles under the current weighting rules. It does not establish nationality, organization, geography, criminal group, or individual identity.

For serious use, this layer should be replaced by evidence-based cluster identifiers and analyst-authored hypotheses without demographic or national shortcuts.

## Canary module

The canary server records requests made to generated tracking paths and can preserve values such as:

- timestamp;
- source IP as seen by the server;
- user agent;
- requested path.

A canary hit proves that something requested the URL from an observed network path.

It does not prove that the requester was:

- the phishing operator;
- a particular person;
- located at the apparent IP address;
- manually using a browser.

Security scanners, mail gateways, link-expansion services, crawlers, sandboxes, VPNs, proxies, NAT, and automated preview systems can all trigger links.

Canary data should therefore be correlated with other evidence rather than promoted directly to identity attribution.

## Reports and exports

PAW can generate multiple artifacts under each case, depending on the enabled workflow.

Typical outputs can include:

```text
cases/case-.../
├── input.eml
├── manifest.json
├── headers.json
├── received_path.json
├── auth.json
├── transmitting_server.json
├── domains.json
├── deobfuscation_results.json
├── campaign_origin.json
├── attribution_matrix.json
├── report/
├── graphs/
├── detonation/
├── evidence/
└── canary/
```

Additional modules may produce files such as:

- STIX bundles;
- abuse packages;
- enrichment reports;
- infrastructure maps;
- threat-intelligence snapshots;
- kit-analysis files;
- PCAPs;
- exported ZIP archives.

Not every artifact is generated in every run.

## Installation

The dependency set is pinned in `requirements.txt`.

Create an isolated environment:

```bash
python -m venv .venv
```

Activate it, then install dependencies:

```bash
python -m pip install -r requirements.txt
```

Browser detonation additionally requires the Playwright browser runtime:

```bash
python -m playwright install chromium
```

Some optional functions also depend on platform tools such as `tcpdump`, system MIME libraries, or network access.

## CLI

The current CLI is available through:

```bash
python -m paw --help
```

### Email analysis

```bash
python -m paw analyze sample.eml
```

A directory can be analyzed through the legacy `trace` interface:

```bash
python -m paw trace --src samples/
```

### Verify a case

```bash
python -m paw verify --case cases/<case-directory>
```

### Query recent cases

```bash
python -m paw query --by domain --value example.test
```

### Export a case

```bash
python -m paw export --case cases/<case-directory> --format zip
```

### Detonation

PAW exposes a dedicated detonation command. Use it only in an isolated environment and only for URLs you are authorized to investigate.

```bash
python -m paw detonate --url http://127.0.0.1:8000/example --observe
```

The loopback example is intentional. Do not use the command as a general-purpose URL scanner.

## Presets

The CLI currently contains `quick`, `full`, and `forensic` shortcuts.

These names describe requested workflow depth, not validation levels.

Because network gating is currently incomplete, inspect the code before assuming that a preset is offline or passive.

## Known limitations

- `--no-egress` is not consistently enforced.
- The main trace path automatically detonates discovered URLs in the current implementation.
- Several network enrichments run from the same process as forensic parsing.
- Authentication handling primarily interprets reported results rather than independently reproducing every authentication protocol.
- Received-path origin selection is heuristic.
- Reverse DNS can be missing, stale, or misleading.
- The case score is not statistically calibrated.
- Hard-coded cloud and reputation ranges are incomplete and can become stale.
- Selected geography/risk heuristics can introduce bias and should be removed from evidentiary scoring.
- The attribution matrix contains demo operator profiles and must not be used for real identity attribution.
- Infrastructure overlap does not prove common ownership.
- A canary IP does not identify a person.
- Browser observation can cause real network side effects.
- Resource collection disables TLS verification in selected code paths.
- Some static phishing-kit analysis is keyword-based and can over-classify ordinary code.
- Threat-intelligence integrations depend on external services, API availability, credentials, quotas, and their own data quality.
- Errors are often caught and converted to partial output, so the existence of a report file does not imply that every upstream stage succeeded.
- Multiple generations of features coexist in the repository, including legacy and experimental interfaces.

## Evidence discipline

For every important conclusion, retain the smallest evidence chain that supports it.

A useful reporting format is:

```text
OBSERVATION
Received hop contains public IP X.

SOURCE
Original email, Received header #N.

MEASUREMENT TIME
<UTC timestamp>

INFERENCE
X is the first public hop outside the classified recipient boundary.

ALTERNATIVE EXPLANATIONS
Forwarder, compromised mail server, cloud relay, forged pre-boundary header.

CONFIDENCE
Medium.
```

For infrastructure correlation:

```text
OBSERVATION
Two cases share the same certificate SPKI hash.

INFERENCE
The hosts may share key material or deployment infrastructure.

NOT PROVEN
Same operator, same organization, same person, or same geography.
```

This distinction is more valuable than increasing a numeric confidence score.

## Intended use

PAW is intended for:

- analysis of phishing email samples you are authorized to inspect;
- email-header forensics;
- defensive threat-intelligence research;
- controlled infrastructure correlation;
- offline and isolated-lab experimentation;
- generation of structured evidence packages for analyst review.

It is not intended for unauthorized scanning, interaction with third-party infrastructure outside an approved investigation, automated accusation of individuals or groups, or unsupervised takedown decisions.

## Recommended next development steps

The highest-value improvements are architectural rather than additional enrichment modules.

1. **Enforce network policy centrally.** Every network-capable module should receive one explicit policy object. `no_egress=True` must make outbound access technically impossible from PAW code paths.
2. **Separate parse from enrich.** A forensic parse should be deterministic and offline. Network enrichment should be a second explicit command.
3. **Remove automatic detonation from `trace`.** Detonation should require a deliberate operator action.
4. **Add provenance to every enrichment field.** Store source, timestamp, request type, and failure state.
5. **Replace the current attribution profiles.** Use neutral cluster IDs and evidence-driven analyst hypotheses.
6. **Calibrate scoring.** Build a labeled corpus and measure precision, recall, false positives, and score calibration.
7. **Independently validate authentication where possible.** Separate "receiver reported pass" from "PAW reproduced pass."
8. **Test case determinism.** The same offline input should produce the same forensic artifacts when network enrichment is disabled.
9. **Create explicit module status metadata.** Mark each subsystem as stable, experimental, external-data-dependent, or deprecated.
10. **Treat negative results as first-class output.** Failed RDAP, DNS, TLS, or TI lookups should remain visible rather than disappearing behind broad exception handling.

## Development context

PAW contains several generations of experimentation. Some modules are considerably more mature than others.

The core value of the repository is not the number of enrichment modules. It is the attempt to preserve a traceable chain from an email artifact to infrastructure observations and then to clearly qualified hypotheses.

The project should be judged by whether each conclusion can be traced back to evidence, not by how aggressive the attribution language sounds.

## License

See the repository's current license and notices for the applicable terms.
