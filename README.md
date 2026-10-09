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

Authentication output now separates header claims from independent verification.
No receiver is trusted merely because its name appears in Authentication-Results;
multiple receiver headers are preserved individually. Reported alignment requires
a passing SPF or DKIM result and a matching identifier; it is never a reproduced
DMARC verdict. ARC structure checks do not verify ARC signatures or sealer trust.
These boundaries follow [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html),
[RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html), and
[RFC 8617](https://www.rfc-editor.org/rfc/rfc8617.html).

`paw.core.dkim_offline.verify_dkim_offline` verifies message signatures using
explicitly supplied local public-key TXT records, without external DNS. The normal
CLI has no local key input yet and marks DKIM verification as not evaluated.
SPF, DMARC and ARC independent verification are also not evaluated; missing checks
are listed in `analysis_coverage.json`, the API and the reports. Untrusted claims
and missing keys do not add authentication risk points or establish safety.
The evidence score remains heuristic, and partial coverage is separate from
successful completion of the analysis process.

PAW is a **research workbench**, not a production incident-response platform or an attribution oracle.

| Area | Current status |
|---|---|
| `.eml` parsing | Implemented |
| `.msg` parsing | Unavailable pending validated conversion and original-header preservation |
| Case creation and input hashing | Implemented |
| Received-path normalization | Implemented heuristically |
| MX/trust-boundary classification | Implemented heuristically |
| SPF/DKIM/DMARC result interpretation | Implemented from message headers |
| ARC and Received-SPF parsing | Implemented |
| DMARC policy DNS lookup | Implemented |
| Independent end-to-end DKIM verification in the main trace path | Not established |
| URL extraction | Implemented |
| Content deobfuscation | Implemented experimentally |
| Attachment inspection | Hashes, metadata and bounded ZIP inventory; malware/macros not evaluated |
| RDAP / infrastructure enrichment | Implemented where network access is available |
| Case scoring | Implemented as hand-authored heuristics |
| Local case index and indicator query | Implemented |
| Evidence manifest / Merkle utilities | Implemented |
| Optional PGP manifest signing | Implemented when a key is configured |
| STIX export | Unavailable pending schema-conformance validation; status file only |
| Abuse-package generation | Qualified local review drafts; ARF/X-ARF conformance not validated |
| Playwright detonation | Implemented experimentally |
| Network request logging | Implemented during detonation |
| Resource collection / static kit analysis | Implemented experimentally |
| Canary logging | Implemented experimentally |
| Cross-case campaign correlation | Unavailable pending validated current-case schema and corpus |
| Operator identity attribution | Not established |
| Automated legal attribution | Not claimed |
| Production readiness | Not claimed |

## Local graphical workbench

GUI development is paused while the engine undergoes wider correctness and load
validation. The current UI covers an offline workflow, not all CLI capabilities.

## Offline CLI validation and batch behavior

`quick` uses the common pipeline offline, with default scoring and no STIX/abuse
exports. `full --no-egress` uses strict scoring and both exports; external stages
are skipped. `forensic --no-egress` has the same local scope: its optional anchoring
is excluded offline. `analyze --forensic` requests anchoring only; it does not
implicitly enable strict scoring or exports. Main reports are English; `--lang`
currently selects Italian abuse-package text or the English fallback.

Directory analyses select EML/MSG extensions without case sensitivity. A bad email
or unsupported MSG is recorded as an individual failure while remaining emails
are attempted within the common runtime budgets. Partial batches exit nonzero;
worker results include successful input-to-case mappings and individual failures.
Original basenames are preserved in case manifests. Empty directories fail.
`trace --deob-weight` accepts finite values from 0 to 1 only.

STIX requests currently write an explicit unavailable status in `report/stix.json`,
not a STIX bundle. Abuse files are local review drafts with no automatic sender
or recipient, separate authentication claims/verification and a byte-preserving
original attachment. Compatibility filenames `arf_report.eml` and `xarf_report.json`
do not establish ARF/X-ARF conformance. No messages are sent. The evidence root
is stored outside the drafts to avoid embedding the later seal in its own input.

`tests/integration_engine_stress_real.py` runs real supervised offline CLI processes
on original repository EML and explicitly constructed load/regression inputs.
CPU/RSS are sampled externally using psutil; it is an observer dependency, not
a production PAW dependency. These loads do not establish accuracy on a labelled
legitimate/phishing corpus or explain historic online four-hour analyses.

## Local graphical workbench usage

Run `paw gui` (or `python -m paw gui`) to open the replacement interface at `http://127.0.0.1:8765`. The launcher owns its socket and refuses occupied ports. Use `--port`, `--data-dir` and `--no-browser` to choose the port, analysis storage and automatic browser opening. Stop the server with Ctrl+C; closing its browser tab does not stop it.

The old Tkinter workflow has been replaced. The new interface uploads original EML files, starts actual offline workers, displays observed stages and total elapsed time, cancels jobs, reopens persisted history/cases, verifies evidence and exports real ZIP packages. It separates execution status, assessment coverage, heuristic score and local file integrity. Attachments are metadata only; reports and captured content are inert text, with no clickable email URLs. Desktop/mobile layouts and keyboard-operated tabs are included. All assets are packaged locally, without a CDN or a frontend build step.

The UI always requests `no_egress=true` and excludes detonation, network enrichment and anchoring. It does not offer MSG conversion, active investigation controls or local DKIM-key ingestion. Local resource controls do not establish an OS network sandbox. The local API enforces loopback Host and same-origin requests, plus CSP and non-sniffing headers; it is intended for a single local user. `tests/integration_gui_real.py` exercises actual Chromium, API, worker and ZIP export, including hostile email bytes, timeout and cancellation. Its separate authentication-rendering contract uses real RSA DKIM results without replacing API responses.

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

`.eml` files use Python's bounded standard email parser. `.msg` conversion is unavailable until transport headers, attachments and original evidence preservation have been validated.

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

- independently verified SPF/DKIM/DMARC and ARC failures;
- header inconsistencies;
- newly registered domains;
- display-name and reply-to mismatches;
- selected TLDs;
- non-ASCII domain spelling;
- brand-string similarity;
- deobfuscation score;
- detonation artifacts;
- canary observations.

Availability of enrichment carries no score bonus. The main CLI leaves ASN and
recurrence flags disabled, and campaign correlation remains unavailable.

Version-2 score artifacts record additive components, provenance, thresholds and
the unrounded decision value. Display rounding cannot change a verdict. See
[score explanations](docs/score-explanations.md) for the contract, numeric
regressions and the provisional private original-EML triage.

The text path preserves decoded MIME text. Visual comparisons are descriptive
metadata and do not add risk points; actual URL recovery remains separate.
See [text preservation](docs/text-deobfuscation.md) for the audited rewriting
defect and remaining HTML/JavaScript validation.

The [HTML evidence contract](docs/html-evidence.md) also preserves original markup
and separates bounded decoded attribute candidates. Routine entity handling adds
no points; text/HTML risk detection remains explicitly not evaluated.

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

## Offline analysis: `--no-egress`

`analyze`, `trace`, `full`, `forensic`, and `quick` apply the offline policy.
Offline runs skip detonation, RDAP/DNS enrichment, canary deployment and remote anchoring.
A process-wide Python audit guard blocks socket operations and subprocess launches,
including worker threads. API jobs run in separate processes and default to offline.
`execution.json` records skipped stages and policy violations; skipped is not a successful measurement.

This is application enforcement, not an OS sandbox for native extensions or hostile code.
For containment of untrusted active code, use an OS firewall or isolated VM as well.

## Real results and unavailable capabilities

Web jobs execute the real engine and verify the evidence index before completion.
No database means no geographic report; absent provider adapters are explicitly unavailable.
Unverified operator profiles and built-in JA3 labels have been removed.
JA3 requires captured handshake fields, preserves wire order and excludes GREASE as defined by
[the original JA3 specification](https://github.com/salesforce/ja3#how-it-works).
HTTP request logs alone do not supply these fields. Scores are heuristic, not calibrated probabilities;
merely creating enrichment files no longer raises the score.

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

- STIX capability status (bundle generation unavailable pending validation);
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

- `--no-egress` uses application enforcement; native-code containment needs OS isolation.
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

## Current forensic validation limits

Offline EML ingestion now preserves the original bytes and decodes MIME text with its declared charset. HTML links, inline attachments, empty attachments and embedded messages are retained, with explicit decoding defects and resource limits. Embedded-message representations are derived artifacts; the original EML remains primary evidence.

Attachment output is metadata and hashes only. Malware, macros and independent MIME-type detection remain `not_evaluated`; absence of a finding does not establish safety. ZIP members are inventoried without extraction or execution. MSG conversion is unavailable pending validation of original headers and attachment preservation.

New cases inventory all case files for integrity verification, except the fixed index/root and post-seal Rekor artifacts. Unsigned local hashes establish consistency, not independent authenticity. Rekor inclusion proofs remain unverified; the legacy presence-of-fields check has been removed. Updating an existing report is unavailable until a versioned workflow can preserve sealed evidence and assessment coverage; create a new case instead.

Independent review regression coverage includes same-name browser downloads, complete evidence inventories and organizational-domain boundaries in scoring. Brand similarity remains a structural heuristic, not an ownership check or calibrated probability. Run `python -m unittest discover -s tests -p "test_*contracts.py"` for offline contracts. The real API, MIME-engine and controlled-loopback Chromium integrations are separate scripts under `tests/integration_*_real.py`.

## Supervised analysis jobs

CLI analysis commands (`analyze`, `quick`, `full`, `forensic`, `trace`) and API analysis jobs now use the same real process supervisor. Defaults are 900 seconds overall, 120 seconds per observed stage, 2 GiB memory, 512 MiB case artifacts, 10,000 artifact files and 8 MiB logs. API queue waiting consumes the overall deadline; at most 32 pending jobs are admitted. Progress reports actual stages and measured elapsed times.

Use `paw full sample.eml --no-egress --deadline 300 --stage-timeout 60 --memory-mib 2048`. API `/api/analyze` accepts a `limits` object with `wall_seconds`, `stage_seconds`, `memory_bytes`, `artifact_bytes`, `artifact_files` and `log_bytes`. `POST /api/analysis/{analysis_id}/cancel` cancels queued or running jobs. Completed jobs stay completed. Terminal failures distinguish `timed_out`, `cancelled`, `resource_limited`, `failed` and `interrupted`.

On Windows, analysis starts only after assignment to a Job Object, with tree-wide memory and process-count limits; the supervisor confirms that no job processes remain before sealing partial evidence. POSIX uses a process group and an inherited per-process address-space limit; equivalent full-browser behavior has not been verified on this Windows host. Disk/log budgets are sampled and can temporarily overshoot between checks. These resource controls are not an OS network sandbox: offline workers retain the application-level `no-egress` policy.

Interrupted evidence is retained. Partial seals establish byte consistency, not completed analysis. After an API restart, lost jobs are marked interrupted; a preliminary `execution.json` alone cannot publish an API job case as completed. Damaged JSON artifacts are exposed as `artifact_errors` without rewriting their bytes. Jobs are not automatically resumed. Direct library calls and standalone legacy commands outside the listed analysis commands are not covered by this supervisor.

## License

See the repository's current license and notices for the applicable terms.
