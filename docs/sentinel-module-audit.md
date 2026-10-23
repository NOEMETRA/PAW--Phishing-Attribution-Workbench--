# Sentinel module audit and capability disposition

Baseline: merged PR91, `801c268387347cc4793ce274a52561d4c4ec6ffc`, 23 October 2026.
This family completes the source disposition of the current Sentinel package.
Review/CI acceptance of this change remains a separate gate. Completion here
means bounded supported contracts plus explicit unsupported paths; it does not
mean every branch is covered, every deployment is qualified, or active egress
and attribution are validated.

## Whole-package register

The register covers all ten Sentinel Python files and 171 module/class-level
function definitions (property getter/setter counted separately; nested closures
excluded). The inventory is an accounting aid, not execution coverage.

| Source | Disposition and exercised contracts | Boundary |
| --- | --- | --- |
| `__init__.py` (1) | Lazy public imports; cold offline consumers exercise the package without geographic plotting or HTTP imports. | No service or isolation established by import. |
| `contracts.py` (12) | Shared native JSON, row/output/SQL budgets, active-policy refusal and local path/source identity helpers. Exercised by offline completion, admission, writer and report suites. | Bounds selected work/payloads; no hostile-filesystem atomic snapshot or OS resource/isolation guarantee. |
| `config.py` (14) | Literal configuration/source binding, strict finite JSON, copy-on-read/write, optimistic source stamp and atomic publication. Monitoring numbers and native booleans now validated before saving. | Retained options are not proof their corresponding capabilities exist; see options below. |
| `database.py` (45) | Named stored readers, typed JSON provenance, literal writers, row/parent checks, explicit retention, and atomic monitor check/comparison/alerts. Full saved readers remain distinct from capped interactive listings. | Historical scores, timestamps and labels remain unverified; risk calculation and attacker-correlation inference unavailable. Known row effects are checked, not arbitrary-trigger/schema certification. |
| `file_monitor.py` (19) | Admitted stable roots and regular files, stopped case ownership, complete bounded inventories, failure-aware hashing/verification, per-instance baseline serialization and rollback. Existing original-EML integrations exercise verify/export preservation. | First scan is a new instance baseline, not prior history. No atomic filesystem snapshot or identity/authenticity claim. |
| `geographic_reports.py` (15) | Complete selected stored sources, omissions, literal numeric filters, escaped inert HTML/JSON and bounded exclusive outputs. | Locations/labels are claims; maps, attacker identity and calibrated risk unavailable. An output pair is not an atomic multi-file commit. |
| `intelligence_analyzer.py` (18) | Saved-source reports, strict integrity serialization, descriptive counts, source-backed candidate-label selection and geographic wrappers. Existing writer-mode `ip_analyzer` attribute retained; read-only construction stays cold. | Automatic in-place enrichment/relabeling and attacker publication unavailable; classification helpers report unknown/null confidence, not invented victim/attacker probabilities. |
| `ip_analyzer.py` (14) | Native literal admission, descriptive address flags, bounded provider/PTR observations, IP echo binding, strict source JSON, cache isolation, bounded batches and unique-address prefix membership. Real loopback HTTP/PTR protocols exercised. | No IP domain-WHOIS substitution, RDAP allocation, calibrated risk, operator identity or attacker attribution. External providers and DNS/proxy deployment remain unqualified. |
| `monitor.py` (29) | In-process controller, bounded submitted workers, interruptible interval, truthful stop acknowledgement, local wrappers/state, deep-copied callbacks and atomic result publication. Real owned HTTP workers, callbacks and SQLite exercised. | CLI persistent service remains unavailable. Browser capture and standalone alert inference refuse explicitly. No automatic retention/retries/remote alert delivery. |
| `transport.py` (4) | Native bounds, credential-safe source URI projection and one bounded raw-entity HTTP response without redirects or content decoding. Local oversized, compressed, broken and slow-drip responses exercised. | Library-decoded headers are not raw wire bytes; HTTP status is not campaign liveness. Cooperative I/O bounds are not hard DNS/native/process deadlines. |

Earlier detailed passive contracts remain in [offline completion](sentinel-offline-completion.md),
[local storage](sentinel-local-storage-family.md), [configured storage](sentinel-configured-storage.md)
and their linked writer, report, JSON and history families. Their historical
test counts are evidence for those revisions, not current global totals.

## Corrected observation and publication contracts

`SentinelMonitor.stop(timeout)` signals the controller and owned HTTP work.
It returns true only after the instance controller and admitted operations have
actually ended. A callback can signal stop, but cannot join itself: it returns
false until an external caller confirms completion. Restart during shutdown
refuses. Interval waits are interruptible, including large admitted intervals.
Results finishing after cancellation are not published. A true stop is required
before treating this instance as quiescent; it does not stop other instances or
processes writing the same database. Callback/native/DNS code can delay it.

The collector admits every selected campaign URI before issuing its requests.
Read-only saved storage refuses collection before transport. At most the
configured worker count is submitted at once. A check, parent timestamp and its
derived alerts commit in one `BEGIN IMMEDIATE` transaction; removed/changed
campaigns and failed known row effects roll back together. Callbacks run after
commit, each with a separate copy; bounded error diagnostics do not undo source
rows. Alert flags control stored/local alert delivery.

The comparison source is the greatest prior stored check id, not an arbitrary
claimed timestamp. Only matching source URI contracts admit status comparison;
content digests also require matching representation contracts. Legacy rows
without that contract stay readable but do not become evidence of a transition.
Stored timestamps are not silently reinterpreted as collection chronology.
Concurrent instances serialize publication, not remote observation time.

Legacy `up`/`down` values mean an observed HTTP status class: below 400 versus
400 or above. A transport/dependency error remains `error`, never a down event.
A redirect is one observed response; its destination is not followed. A changed
digest means literal comparable entity bytes, not a changed phishing kit, DOM,
operator or intent. Error/partial captures have no complete-content digest.

Monitor observations retain at most 128 KiB plus one overflow-detection byte,
base64 body bytes, retained-byte SHA256, complete-body SHA256 only when complete,
requested/response URI, timestamp, elapsed time, status, content encoding and
bounded library-decoded response fields. Header capture has a separate
16,384-character ceiling and explicit partial status. Content encoding is not
decompressed; a compressed bomb cannot inflate into an unbounded decoded body.
Environment proxies are ignored; an explicit HTTP proxy is a route, not isolation.

`check_now` has the database selected-result byte budget (32 MiB by default).
Publication is atomic per check, not per batch: a later exception/limit can leave
earlier checks committed and must not be interpreted as a complete batch result.
Background cycles do not accumulate all response bodies in a returned list.

## IP observations and unsupported interpretation

Inputs are native unscoped textual IP literals; integer/bool/CIDR/path values
are refused before providers or worker submission. Address flags and assumed
IPv4 /24 or IPv6 /64 groups are syntax/grouping observations, not allocated
subnets, ASNs, people or operators. Invalid admitted observations retain source
indices. Supplied range membership remains an unverified supplied claim;
`potential_attacker_ranges` is not fabricated from repeated addresses.

Provider attempts retain bounded original response bytes and parsed native
payloads, source/time/status/limits and omissions. Success requires a complete
200 response, strict unambiguous finite JSON and the requested IP echoed back.
Zero coordinates are valid. A successful first provider does not call the paid
fallback. Missing credentials, mismatched IPs, invalid/duplicate JSON and limited
responses remain unavailable/invalid observations, without invented geography.
API credentials are redacted from recorded request/response URI projections.

The per-instance cache copies values, expires after 300 seconds and is bounded
to 256 entries and 16 MiB encoded payload. Batches admit at most 1,000 input
literals, 64 in-flight workers and 32 MiB serialized results; lexical duplicate
inputs share an output entry and input order is retained. Prefix correlation
admits at most 1,000 strings of 128 characters and 256 supplied ranges of 64
characters, with a 32 MiB output ceiling. These are payload/work bounds, not RSS.

PTR collection returns the first bounded DNS PTR text observation. Its absence
is unavailable, not suspiciousness or proof that no PTR exists; complete DNS
answer/negative-response provenance is not claimed. HTTP proxy selection does
not proxy PTR/system DNS. No system DNS or public provider was queried during
this acceptance: the DNS responder and HTTP endpoints were explicitly owned
loopback fixtures, and public-looking IP strings were only protocol payloads.

`whois_lookup` reports unavailable because domain WHOIS does not establish IP
allocation; validated IP RDAP is future work. `analyze_risk_indicators`,
`calculate_risk_score`, automatic victim enrichment and attacker-publication
methods refuse unsupported inference/publication. Interaction/country/UA/IP
classifiers report unavailable/unknown with null confidence. Existing raw rows,
stored historical scores and supplied labels are preserved and remain readable.

## Option and entry-point reconciliation

| Option/path | Current behavior |
| --- | --- |
| Monitoring enabled/interval/concurrency/timeout | Used by the in-process controller; native finite numbers/booleans validated. Interval changes require restart. Manual immediate checks are explicit operations. |
| Content diff | Controls complete comparable entity-byte digest comparison; bounded raw observations are retained independently. |
| Alert enabled/down/up/changes | Used by atomic local check/alert publication. Registered domain events remain separate from enabled alert delivery. |
| Screenshots/resolution/directory/count | Capture unavailable before browser/argument/filesystem use; disabled requests are labelled not requested. Existing screenshot files are not deleted or rewritten. |
| Fingerprinting, retries, webhook/email delivery | Unavailable; retained configuration does not activate a hidden worker or external publisher. Listed in `get_runtime_state()`. |
| Retention days | No automatic cleanup scheduler. Existing explicit bounded database retention remains a separate local mutation. |
| Database path/limits; local/file/report/diagnostic CLI | Existing configured passive contracts and no-egress admission preserved. |
| CLI monitor start/stop; geographic map; legacy active publishers | Existing explicit unavailability retained. In-process API tests do not establish a persistent service. |

## Acceptance and remaining project gates

Final Windows/Python 3.13 general suite: **954 tests, 940 passed and 14 expected
platform/optional skips**. This family adds 25 focused contracts and 17 actual
loopback HTTP/PTR integration cases, including worker-stop acknowledgement,
atomic rollback/callback publication, source/digest compatibility, raw-body
limits, broken/slow/compressed responses, redirect refusal, provider binding,
credential projection, cache copies and no-egress refusal.

The general suite and **25 Sentinel/legacy/wheel integration scripts** passed
serially on frozen sources. After final monitor-transaction literal-identity,
comparison-source and version checks, the full suite, loopback protocols, cold
offline completion/two-process SQLite, writers and wheel were repeated. Other
passive method bodies were unchanged by that final refinement. The built wheel
matches all 94 current Python sources, metadata and console entry points. After
the final suite, only the screenshot regression test was strengthened to reject
process/socket/write attempts independently of implementation; all 25 focused
contracts passed again with runtime unchanged. The final manifest covers 248
runtime/test/workflow files. GitHub review and CI must accept the published head.

Runtime/tests/workflows are frozen during validation; documentation follows
stopped validators. Originals, private logs and audit manifests stay outside Git.
Constructed protocol responses and declared fault injection are regression
evidence, not classifier labels, real-provider validation or accuracy estimates.

This closes the named source/contract audit of the current Sentinel module when
the PR review and CI gates pass. It does not close S14, the whole engine audit or
production acceptance: controlled Windows/Linux isolation, real provider/DNS/
proxy/browser collection, process deadlines/containment, source sealing for
future versioned enrichment, persistent deployment and final platform/install
acceptance remain separate. UI remains after engine stabilization. No email URL
or domain was visited/resolved, no attachment executed and no Docker started.
