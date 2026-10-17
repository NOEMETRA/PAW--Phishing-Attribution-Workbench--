# Engine stabilization checkpoint

Baseline: merged PR38, `92c4c7a9601babd4b2826e557e9c17cf99afd1db`, 11 October 2026.
This is a finite audit register for the existing repository. It assigns work and
closure criteria; a family with passing tests is not an attestation that every
function in its modules has been validated. Adding a new capability requires a
demonstrated investigative need and its own explicit contract.

The current objective is stabilization and depth of forensic evidence extraction.
Historical four-hour runtime reproduction and speed optimization are not current
completion criteria. Analysis on the development host stays `--no-egress`.
Controlled egress and the proposed Windows solution remain later project stages;
the application guard is not an OS sandbox. UI work follows the engine.

Sentinel interaction diagnostics remain an optional saved-data inspection path.
The current work repairs existing contracts; future behavioral or cross-case
extensions are deferred to a separately justified plan after engine stabilization.

## Evidence levels and closure

**Bounded verification** means the linked contract has actual tests or worker
evidence, within its documented scope. **Open audit** means implementation exists
without a complete assessment of that family. **Explicitly unavailable** means
the current path must report unavailability, not generate a success substitute.
**Deferred** means later isolation, independent labels or UI work is needed.
Static inventory and test-file presence alone are not verification.

Each family closes only when its supported inputs, outputs, source provenance,
limits, omissions and failure behavior have named expectations; applicable actual
CLI/API/export tests pass on an identified version; and unavailable paths are
honest. A reproduced failure is corrected in a focused PR and the whole affected
family is checked, including previous review findings. An extension or algorithm
change is not justified solely by the absence of a test. Review findings are
checked against both the baseline and the proposed fix before changing code.

## Finite family register

| ID | Existing capability and current evidence | Remaining work and closure criterion |
| --- | --- | --- |
| S00 | Filesystem/hash/time helpers occur in tested flows; this does not validate every helper or initializer. **Open audit:** `paw/util/validators.py` has no identified consumer or test reference in the tracked Python source search. The similarly named external `util/validators.py` is a separate file. | Keep the package validator explicitly unvalidated pending an exercised consumer/contract or an archival disposition; do not treat its declarations as the current admission framework. Check indirect helper assumptions in consuming families and the package/import surface in S13. Close only with an explicit disposition for unused helpers and source-bound supported flows. |
| S01 | Five analysis CLI presets and HTTP worker: [import boundary](offline-validation.md#analysis-worker-import-boundary), batch contracts. [Standalone input](standalone-deobfuscation-input.md) and supervision checked. MSG deliberately unavailable; EML is the supported original format. | Final admission matrix: valid/empty/malformed/oversized EML, mixed batches, source kinds and numeric options, local-key inputs, unavailable MSG with partial accounting. Correct completion/failure and input preservation must agree across CLI/API. This does not require enabling MSG. |
| S02 | Runtime/process recovery/job ownership/no-egress contracts; actual cancellation, supervisor crash, stopped-tree acknowledgment and read admission. Python guard is application policy only. | Consolidated final Windows end-to-end shutdown, interruption, recovery and reader/export checks. Record which POSIX checks run in CI and which platform behaviors remain untested. No sealing or stable-reader success while writers are alive or stop is unknown. |
| S03 | [Header inventory](header-inventory.md), [MIME headers](mime-header-inventory.md), [identity](header-identity.md), [Received](received-evidence.md)/[timing](received-timing.md), supplied [DKIM keys](local-dkim-keys.md). Claims and independent checks separated. | Final combined duplicate/malformed/inner-message boundary and unavailable-authentication tests. Independently verified SPF/DMARC/ARC and key authenticity remain separate unavailable/unverified capabilities; they cannot be inferred from sender claims. |
| S04 | [MIME body evidence](mime-body-evidence.md), original embedded-message spans, [CID candidates](mime-cid-evidence.md): per-part provenance, duplicates/scopes and omissions checked. | Audit whether attached/embedded HTML, Content-Location and CSS/srcset interpretation are required evidence gaps. Preserve unavailable/uninterpreted observations now; add support only with a demonstrated need. Candidate equality must not imply MIME resource selection or rendering. |
| S05 | [URL records](url-evidence.md), [text](text-deobfuscation.md), [HTML](html-evidence.md), [JavaScript](javascript-evidence.md), source catalogs. Original and derived observations remain distinct; JS is not executed. | Reconcile all advertised extraction contexts with supported sources and transforms. Final originals/derived-value/budget/failed-candidate tests; ignored contexts explicit. No inferred visit, execution, decryption or recovered semantics from string resemblance. |
| S06 | [Attachment ZIP inventories](attachment-archive-inventory.md), attachment payload hashes and separate original embedded spans tested. ZIP membership inventory does not unpack contents. | Required local attachment coverage must be explicit for opaque/encrypted/non-ZIP formats, executable/macro/AV claims and nested archives. Preserve originals and omissions; no execution. Actual attachment corpus is absent from the private 20-email pilot, so fixture checks do not establish real-world coverage. |
| S07 | [Content assessment](content-assessment.md), [score explanations](score-explanations.md), domain Unicode/brand/TLD/age and RDAP binding contracts. Numerical contributions and unrounded decisions checked; classifier is uncalibrated. | Combined evidence-to-contribution audit, missing-input behavior and explanation parity. Independent labeled evaluation in S10; matching a rule or passing arithmetic tests cannot validate a risk threshold. Live domain/provider checks remain S14. |
| S08 | Integrity, stopped-case query admission, legacy index observation, ZIP/API/report exposure and [SimHash](header-simhash.md) contracts. STIX unavailable; abuse outputs are unsent local drafts. | Audit every final report/diagram/export for traceable sources, unsupported origin/risk claims and malformed-input readability. PGP signing verification and Rekor inclusion authenticity are not established by existing seal checks. Schema-conformant STIX/ARF/X-ARF requires an independent contract; unavailable status can close the present boundary. |
| S09 | Trace orchestration has actual worker evidence. [Static captured-kit observations](kit-static-evidence.md), [supplied HTML form observations](form-static-evidence.md) and [supplied tracker-pattern observations](tracker-static-evidence.md) have bounded source/interpretation contracts. Version-2 matrix consumers retain unverified provenance/counts rather than unsupported payment/operator confidence. [Header-forgery disposition](header-forgery-observations.md) preserves passive Received descriptions and makes unvalidated aggregate/DNS/authentication interpretations unavailable. | Consolidate the supported trace/helper boundaries with the remaining register; do not declare all trace collection validated. Static kit/form/tracker ingestion is tested separately from active collection (S14), including later DOM-snapshot retention and publisher behavior. Do not infer dynamic kit behavior, tracking/pixels, payments, merchant/operator identity, C2/exfiltration, forgery or low risk from static strings or absence. |
| S10 | Operator attribution has no sourced dataset; cross-case campaign correlation explicitly unavailable. SimHash algorithm is versioned, without calibrated similarity thresholds. Private pilot: 20 originals, 10 owner-confirmed legitimate, spam not independently adjudicated. | Independently label representative evidence and preserve a separate holdout; evaluate coverage and false positives/negatives for a defined task. Calibrate thresholds and correlation before enabling claims. All pilot decisions being Inconclusive proves neither accuracy nor coverage. No arbitrary project completion percentage. |
| S11 | Local file-integrity monitoring has earlier actual tests. [Interaction-row readers](sentinel-database-rows.md) use named columns across migrations. [Passive opening and `monitor list`](sentinel-passive-opening.md) have actual SQLite/CLI checks without initialization/migration; WAL/pending journals are explicitly unsupported. [Stored JSON evidence](sentinel-json-evidence.md) retains typed source and decoding/default status in campaign/check/alert/interaction records, with ambiguity/non-finite rejection. [Passive status](sentinel-status.md) uses actual stored counts and explicitly unknown runtime state; instance statistics label their local flag scope. [Stored forensic export](sentinel-forensic-export.md) retains full reader records and JSON sources with an independently recomputable returned-list digest and unverified timestamp aliases. [Stored intelligence report](sentinel-intelligence-report.md) retains complete selected sources and traceable descriptive counts, with risk/recency/attribution/actions explicitly unavailable. [Stored geographic observations](sentinel-geographic-report.md) retain complete selected sources, coordinates including zero, traceable filters/omissions and passive escaped JSON/HTML output; identity/risk/maps explicitly unavailable. [Stored interaction statistics/candidate labels](sentinel-interaction-statistics.md) have complete exact-case source/JSON preservation, literal counts and explicit unavailable identity/risk; legacy candidate list shape is retained. [Stored country/score selectors and statistics](sentinel-stored-filters.md) preserve complete typed sources and traceable numeric/status counts; malformed geographic JSON cannot suppress valid neighbors, while recency and attacker-infrastructure interpretation are explicitly unavailable. [CLI service start/stop](sentinel-cli-lifecycle.md) reject before Sentinel imports/source access because no persistent service or cross-process stop protocol exists. [Local file-reader admission](sentinel-local-file-admission.md) separates file commands from campaign storage and applies stopped-owner guards with selected-case preflight; actual live/completed original-EML workers are exercised. [Campaign CLI admission](sentinel-campaign-admission.md) validates arguments before Sentinel access and preflights removal through existing passive storage; accepted add/remove use the database writer without constructing a network monitor, and removal requires an actual active-row update. Remaining file inventory/hash/resource interpretation and campaign writer/API/listing dispositions are open. | Next: remaining campaign writer/API/listing disposition, then S12 entry-point disposition. File inventory/hash failure/resource admission and concurrency remain open; first scan is an instance baseline, not historical change detection. Accepted campaign mutations retain default writer initialization; removal preflight is passive but not an atomic writer snapshot. General non-JSON publication and stored-data size/output admission remain open. Read-only mode is not an atomic snapshot of concurrent writers. Geographic location, user agent, timing and IP similarity cannot alone establish attacker/victim identity. Network monitoring belongs to S14; no live target is needed for passive stored-data checks. |
| S12 | 26 tracked operational **Python** scripts outside the package, listed below. `tools/analyze_inbox.py` has a [verified supervised offline launcher](legacy-inbox-launcher.md); `start_canary.py` has an actual unavailable-before-I/O rejection check in `integration_canary_boundary_real.py`. The [legacy campaign-list alias](legacy-campaign-list.md) also has actual passive configuration/storage, argument and inert-import checks. The [legacy interaction diagnostic](legacy-interaction-check.md) also has actual passive complete-row/configuration, cold import and argument checks. The [legacy origin updater](legacy-origin-update.md) explicitly rejects before source I/O or collection, with actual original-EML preservation checks. The [legacy abuse-template publisher](legacy-abuse-draft.md) rejects before source I/O; actual supervised English/Italian local review drafts remain available and sealed. The other 20 lack a general entry-point validation record. Two additional shell launchers are registered separately: `deploy.sh` (S12/S13/S14) and `paw/modules/encrypted_clicking/init_crypto.sh` (S14). | Decide support or archival status for all 28 registered operational scripts, including the shell launchers; do not close the register with shell paths omitted. Supported local paths need admission, no-egress, bounds, honest outputs and source preservation. Shell deployment/privileged active paths remain deferred until their S13/S14 checks; Python presence or a package build does not validate them. |
| S13 | [Clean Windows Python 3.13 installation](clean-installation.md) passed on its recorded earlier version. Wheel source/metadata checks exist; current project requires Python >=3.11. | Rebuild current wheel and prove it contains current source/assets/entry points. Final isolated dependency installation and supported platform/optional-component checks; successful build alone is not a clean install. Document required/optional/unavailable components and runtime versions. |
| S14 | DNS/RDAP/provider/redirect/TLS/JA3/intelligence/monitoring/detonation modules exist. Some local collectors and browser/crypto mechanisms have loopback tests; live suspicious infrastructure and full egress are not validated. The two shell launchers below and their deployment/container configuration remain **unvalidated/deferred**. | After local stabilization, assess the user-proposed Windows isolation solution (Linux alternative), enforce/test outbound boundaries, then test actual collectors/detonation with source/time/provider provenance, timeouts, error handling and artifact sealing. Include launcher/privileged-storage/configuration dispositions before closing this family. Proxy/encryption/container configuration alone is not proof of containment or authenticity. No suspicious endpoint access on this host during this checkpoint. |
| S15 | Canary deployment rejects before I/O; observation storage within sealed cases is intentionally unavailable. | Only enable with separate bounded observation storage, verified isolation, source integrity and honest behavioral semantics. No fabricated visits, session tracking or attacker attribution. Unavailable state is the supported current contract. |
| S16 | Local web workbench prototype exists; backend worker/API contracts are tested. Further GUI development is paused. | After engine and egress contracts, build complete option/profile/key/export parity, observable phases, cancellation, partial results and provenance views. Verify actual user flow; backend tests do not establish GUI completeness. Finish release documentation and acceptance on the supported package. |

## Command coverage

The 16 primary parsers and `geo` alias are read from `paw/__main__.py`; this
enumeration does not execute services. HTTP API is a separate ingress, not a
seventeenth CLI command. Default egress behavior must be considered when running
analysis; here every applicable preset uses explicit `--no-egress` (`quick`
already forces it).

| Commands | Current boundary | Remaining family |
| --- | --- | --- |
| `analyze`, `quick`, `full`, `forensic`, `trace` | Real supervised analysis, supported EML; three scoring profiles; optional exports/anchoring are availability requests. | S01-S09; network stages S14. `full`/`forensic` request STIX and abuse drafts; requests do not validate formats. |
| `deobfuscate` | Supervised offline literal/file interpretation, bounded UTF-8 source with provenance; no URL fetch. | S01, S02, S05. |
| `verify`, `export`, `query` | Local evidence integrity, ZIP export and stopped-case SQLite reads. | S08; integrity is not email authenticity. |
| `help` | Parser/help inventory exists; no worker is launched. | S01/S13: reconcile examples, defaults and honest capability wording. |
| `update` | In-place modification of sealed cases unavailable. | S08: keep rejection explicit; any future versioning is a separate justified capability. |
| `monitor` | Local file integrity is distinct from campaign network monitoring and database actions; service start/stop explicitly unavailable before source access. | Local file commands have stopped-owner admission independent of campaign storage; remaining file-helper/campaign management audit S11, in-process lifecycle/active collection S14. Do not treat all subcommands as offline-safe. |
| `geographic` (`geo`) | [Passive stored geographic reports/statistics](sentinel-geographic-report.md) have actual source/output admission checks; `map` rejects before initialization. | Remaining S11 worker/lifecycle/listing consumers; identity/risk/maps unavailable. |
| `detonate` | Active explicit operation; prior loopback observation is not suspicious-target validation. | S14. |
| `canary` | Explicit unavailability before collection. | S15. |
| `gui` | Prototype launcher; full parity deferred. | S16. |

## Verification record at this checkpoint

Merged PR38 reviewed head `ba43285cd9092cd26ff9134df9caed31492a10b3`
has the same source tree as this baseline. Codex completed without findings;
CI108 succeeded. Recorded local general suite: 512 tests, 505 pass and seven
POSIX-only skips on Windows. Ten CID contracts, 13 actual CLI cases and five
loopback HTTP workers passed. This does not validate all 89 package files.

The private 20-original replay compared 280 existing JSON artifacts, 64 body
files and 40 old/new seals; scores and decisions were unchanged. The source,
body and CID catalogs were checked independently. It contains no attachments
or CID fields/references. Positive attachment/CID scope is checked separately
with real worker fixtures; constructed samples are not classification truth.
Original emails and raw private validation artifacts are kept outside Git.

On the clean baseline, the actual offline stress replay passed all 24
scenarios and produced 95 completed cases with valid seals, confirmed stopped
trees and no residual observed processes. It includes mixed-extension/error/MSG
batches, all five presets, batch sizes 5/20/50, 100/1,000 URLs, 512 KiB/1.8 MiB
text, 300 attachments, a 12 MiB attachment and oversized/empty input rejection.
The original public repository EML is included; constructed loads are not labels.
This checks the listed operational expectations, not every evidence field.

Actual shared CLI/HTTP checks also passed: active-case reader/query admission,
eight completed original-EML cases, original ZIP/verify access, read-only SQLite
queries, and real supervisor-crash recovery before partial sealing/export.
An actual wheel build passed current Python metadata, entry point and all 89
Python-source byte comparisons. It is not a new clean dependency installation.

The first stress harness attempt stopped during its own verifier import because
the source package was not on the parent harness import path. That run's CLI
batch exited successfully with confirmed tree shutdown; its log is retained and
it is excluded from the 24-scenario pass count. The full replay used explicit
trusted source-root PYTHONPATH. No production/test code or budgets were changed
to obtain these results. To run the source-tree harness from the repository:

```powershell
$env:PYTHONPATH = (Get-Location).Path
$env:PYTHONDONTWRITEBYTECODE = '1'
python tests/integration_engine_stress_real.py --suite all
python tests/integration_cli_api_real.py
python tests/integration_wheel_metadata_real.py
```

Use a trusted source checkout and installed required dependencies. These
commands run actual offline analyses/local loopback workers and a package build;
they do not start Docker or visit sample URLs.

## Static kit correction (S09)

The initial audit on merged PR38 reproduced two failures in actual static
helpers under no-egress: collector-shaped HTML lists lost a form target retained
for the identical scalar, and empty sources generated HTTP/POST attacker defaults.
A duplicate top-level pattern function was a separate reachability concern.

The focused correction handles scalar/list HTML, JavaScript and CSS independently,
retains source indexes and complete text hashes, and keeps malformed siblings and
omissions visible. The captured-file reader binds complete raw hashes to paths,
distinguishes replacement-decoded text, and enforces file/source/entry/depth and
observation budgets. The actual publishing consumer retains static observations
without turning their URLs into C2 infrastructure. Legacy risk/attribution remain
explicitly unavailable. See [the exact contract and boundaries](kit-static-evidence.md).

`tests/test_kit_static.py` checks actual functions, local constructed capture
files and the publishing consumer, including local sealing/ZIP preservation.
These fixtures are not remote collection or classification evidence. Full
`--no-egress` worker regression exercises the unchanged inactive boundary, not
this active caller. Form/tracker/header-forgery helpers remain open; S09 as a
whole is not declared complete.

## Completion order

1. Close the focused S09 helper/consumer audit and the passive S11/S12 entry-point
   disposition. Reconcile local extraction gaps S04-S06 against investigative
   needs; record explicit limits rather than extending scope by default.
2. Close final consolidated S01-S08 regressions and S13 installation/support
   boundary. Fix reproduced errors in focused PRs, each with review on its tested
   head; passing fixtures do not close S10 accuracy.
3. Complete independent S10 evaluation for any classification/attribution claims,
   or keep those claims explicitly unavailable/uncalibrated in the supported scope.
4. Verify controlled isolation, then actual S14/S15 active capabilities. Finish
   S16 interface parity and release acceptance on the final supported version.

This order replaces repeated open-ended expansion. A row can close with an
explicit unsupported boundary where justified; it cannot close by silently
discarding available forensic observations or asserting unimplemented success.

## Source ownership index

The following index accounts for every tracked package Python file at the
baseline, plus the focused kit module (90 current files). Assignment denotes the family responsible for audit, not complete
verification of the file; mixed local/active functions keep both boundaries.

- **S00 (11 files):** [paw/__init__.py](../paw/__init__.py), [paw/canary/__init__.py](../paw/canary/__init__.py), [paw/deobfuscate/__init__.py](../paw/deobfuscate/__init__.py), [paw/detonate/__init__.py](../paw/detonate/__init__.py), [paw/gui/__init__.py](../paw/gui/__init__.py), [paw/sentinel/__init__.py](../paw/sentinel/__init__.py), [paw/util/fsutil.py](../paw/util/fsutil.py), [paw/util/hashutil.py](../paw/util/hashutil.py), [paw/util/timeutil.py](../paw/util/timeutil.py), [paw/util/validators.py](../paw/util/validators.py), [paw/web/__init__.py](../paw/web/__init__.py).
- **S01 (7 files):** [paw/__main__.py](../paw/__main__.py), [paw/core/batch.py](../paw/core/batch.py), [paw/core/parser_mail.py](../paw/core/parser_mail.py), [paw/deobfuscate/input.py](../paw/deobfuscate/input.py), [paw/standalone.py](../paw/standalone.py), [paw/standalone_worker.py](../paw/standalone_worker.py), [paw/web/worker.py](../paw/web/worker.py).
- **S02 (4 files):** [paw/core/job_registry.py](../paw/core/job_registry.py), [paw/core/network_policy.py](../paw/core/network_policy.py), [paw/core/process_recovery.py](../paw/core/process_recovery.py), [paw/core/runtime.py](../paw/core/runtime.py).
- **S03 (11 files):** [paw/core/auth.py](../paw/core/auth.py), [paw/core/authentication.py](../paw/core/authentication.py), [paw/core/dkim_keys.py](../paw/core/dkim_keys.py), [paw/core/dkim_offline.py](../paw/core/dkim_offline.py), [paw/core/header_inventory.py](../paw/core/header_inventory.py), [paw/core/ip_observations.py](../paw/core/ip_observations.py), [paw/core/mailbox_domains.py](../paw/core/mailbox_domains.py), [paw/core/mime_header_inventory.py](../paw/core/mime_header_inventory.py), [paw/core/received.py](../paw/core/received.py), [paw/core/received_timing.py](../paw/core/received_timing.py), [paw/core/trust_boundary.py](../paw/core/trust_boundary.py).
- **S04 (3 files):** [paw/core/mime_analysis.py](../paw/core/mime_analysis.py), [paw/core/mime_body_evidence.py](../paw/core/mime_body_evidence.py), [paw/core/mime_cid.py](../paw/core/mime_cid.py).
- **S05 (8 files):** [paw/core/url_evidence.py](../paw/core/url_evidence.py), [paw/core/url_sources.py](../paw/core/url_sources.py), [paw/deobfuscate/core.py](../paw/deobfuscate/core.py), [paw/deobfuscate/homoglyph.py](../paw/deobfuscate/homoglyph.py), [paw/deobfuscate/html.py](../paw/deobfuscate/html.py), [paw/deobfuscate/javascript.py](../paw/deobfuscate/javascript.py), [paw/deobfuscate/text.py](../paw/deobfuscate/text.py), [paw/deobfuscate/url.py](../paw/deobfuscate/url.py).
- **S06 (1 file):** [paw/core/attach.py](../paw/core/attach.py).
- **S07 (6 files):** [paw/core/domain_age.py](../paw/core/domain_age.py), [paw/core/domain_unicode.py](../paw/core/domain_unicode.py), [paw/core/ml_scorer.py](../paw/core/ml_scorer.py), [paw/core/profiler.py](../paw/core/profiler.py), [paw/core/rdap_registration.py](../paw/core/rdap_registration.py), [paw/core/scoring.py](../paw/core/scoring.py).
- **S08 (9 files):** [paw/core/abuse.py](../paw/core/abuse.py), [paw/core/evidence.py](../paw/core/evidence.py), [paw/core/exporter.py](../paw/core/exporter.py), [paw/core/graphs.py](../paw/core/graphs.py), [paw/core/index.py](../paw/core/index.py), [paw/core/signature.py](../paw/core/signature.py), [paw/core/stix.py](../paw/core/stix.py), [paw/core/verify.py](../paw/core/verify.py), [paw/web/api.py](../paw/web/api.py).
- **S09 (5 files):** [paw/core/kit_static.py](../paw/core/kit_static.py), [paw/core/form_analysis.py](../paw/core/form_analysis.py), [paw/core/header_forgery.py](../paw/core/header_forgery.py), [paw/core/trace.py](../paw/core/trace.py), [paw/core/trackers.py](../paw/core/trackers.py).
- **S10 (1 file):** [paw/core/attribution_matrix.py](../paw/core/attribution_matrix.py).
- **S11 (5 files):** [paw/sentinel/config.py](../paw/sentinel/config.py), [paw/sentinel/database.py](../paw/sentinel/database.py), [paw/sentinel/file_monitor.py](../paw/sentinel/file_monitor.py), [paw/sentinel/geographic_reports.py](../paw/sentinel/geographic_reports.py), [paw/sentinel/intelligence_analyzer.py](../paw/sentinel/intelligence_analyzer.py).
- **S14 (16 files):** [paw/config/proxy_config.py](../paw/config/proxy_config.py), [paw/core/dns_enrichment.py](../paw/core/dns_enrichment.py), [paw/core/ja3_fingerprinting.py](../paw/core/ja3_fingerprinting.py), [paw/core/redirect_chain.py](../paw/core/redirect_chain.py), [paw/core/rekor.py](../paw/core/rekor.py), [paw/core/tls_fingerprinting.py](../paw/core/tls_fingerprinting.py), [paw/detonate/runner.py](../paw/detonate/runner.py), [paw/intelligence/criminal_hunter.py](../paw/intelligence/criminal_hunter.py), [paw/intelligence/enrich_last_hunt.py](../paw/intelligence/enrich_last_hunt.py), [paw/intelligence/infrastructure_mapper.py](../paw/intelligence/infrastructure_mapper.py), [paw/intelligence/le_package.py](../paw/intelligence/le_package.py), [paw/intelligence/threat_intel.py](../paw/intelligence/threat_intel.py), [paw/modules/encrypted_clicking/encrypted_clicker.py](../paw/modules/encrypted_clicking/encrypted_clicker.py), [paw/modules/encrypted_clicking/paw_integration.py](../paw/modules/encrypted_clicking/paw_integration.py), [paw/sentinel/ip_analyzer.py](../paw/sentinel/ip_analyzer.py), [paw/sentinel/monitor.py](../paw/sentinel/monitor.py).
- **S15 (1 file):** [paw/canary/server.py](../paw/canary/server.py).
- **S16 (2 files):** [paw/gui/launcher.py](../paw/gui/launcher.py), [paw/gui/tk_gui.py](../paw/gui/tk_gui.py).

## External operational Python sources

- [_list_campaigns.py](../_list_campaigns.py): [passive canonical CLI alias](legacy-campaign-list.md), verified with actual storage/configuration and import/argument checks.
- [advanced/analyze_trackers_advanced.py](../advanced/analyze_trackers_advanced.py)
- [advanced/attribution_confirmation_engine.py](../advanced/attribution_confirmation_engine.py)
- [advanced/deception_countermeasure_engine.py](../advanced/deception_countermeasure_engine.py)
- [advanced/derive_host_ip_asn_advanced.py](../advanced/derive_host_ip_asn_advanced.py)
- [advanced/kit_static_mapper_advanced.py](../advanced/kit_static_mapper_advanced.py)
- [advanced/operational_pattern_predictor.py](../advanced/operational_pattern_predictor.py)
- [advanced/quantum_resistant_forensics.py](../advanced/quantum_resistant_forensics.py)
- [advanced/strategic_correlator.py](../advanced/strategic_correlator.py)
- [check_db_fields.py](../check_db_fields.py)
- [check_victims.py](../check_victims.py): [complete passive interaction diagnostic](legacy-interaction-check.md), verified against actual saved/legacy/error SQLite and inert import/argument paths.
- [generate_geo_report.py](../generate_geo_report.py)
- [run_analyzer.py](../run_analyzer.py)
- [scripts/update_origin.py](../scripts/update_origin.py): [explicit unavailable in-place update boundary](legacy-origin-update.md), verified against an actual completed original-EML analysis and sealed/missing/legacy/ownership-state fixtures; versioned enrichment remains S14 work.
- [start_canary.py](../start_canary.py)
- [tools/analyze_inbox.py](../tools/analyze_inbox.py)
- [util/analyze_trackers.py](../util/analyze_trackers.py)
- [util/attribution_confirmation_engine.py](../util/attribution_confirmation_engine.py)
- [util/build_flow_mermaid.py](../util/build_flow_mermaid.py)
- [util/deception_countermeasure_engine.py](../util/deception_countermeasure_engine.py)
- [util/derive_host_ip_asn.py](../util/derive_host_ip_asn.py)
- [util/kit_static_mapper.py](../util/kit_static_mapper.py)
- [util/make_abuse_templates.py](../util/make_abuse_templates.py): [explicit unavailable legacy publication boundary](legacy-abuse-draft.md); actual supervised English/Italian review drafts and source/seal preservation checked, broader S08 publication audit remains open.
- [util/operational_pattern_predictor.py](../util/operational_pattern_predictor.py)
- [util/quantum_resistant_forensics.py](../util/quantum_resistant_forensics.py)
- [util/validators.py](../util/validators.py)

`setup.py` belongs to S13 and is not counted among the 26 operational Python scripts.
Tracked repository test files (including root workflow/system scripts) are
separate evidence producers, not implicitly validated operational entry points.

## Shell launchers and deployment boundary

The tracked shell/PowerShell/batch extension census (`.sh`, `.bash`, `.bat`,
`.cmd`, `.ps1`, `.psm1`, `.psd1`) finds these two launchers. Together with the
26 external operational Python files, the register covers **28 operational
scripts**; one shell launcher is inside the package directory. The 90-file current
package source index above counts Python files only. No launcher was executed
to produce this inventory.

| Source | Ownership and observed behavior | Disposition and closure |
| --- | --- | --- |
| [deploy.sh](../deploy.sh) | S12 entry point; S13 dependency/package installation; S14 Docker build/container test and advertised analysis/detonation/canary commands. Its Python 3.8 version check differs from the current >=3.11 package requirement. | **Unvalidated/deferred.** Review actual dependency/version/configuration handling, advertised available commands and container/egress behavior, then decide supported replacement or archival status. Earlier clean Windows installation/wheel checks do not validate this launcher. No Docker or deployment was started here. |
| [paw/modules/encrypted_clicking/init_crypto.sh](../paw/modules/encrypted_clicking/init_crypto.sh) | S14 privileged storage/bootstrap: creates keys and a vault image, formats/opens/mounts a LUKS filesystem and executes the clicker. | **Unvalidated/deferred.** Storage lifecycle, key handling, privileges and active worker isolation need a separate contract and a support/archival decision in the controlled environment. A crypto primitive test does not validate this script; it was read without execution. |

Container/deployment configuration belongs to S13/S14, and frontend assets and
build configuration to S16; they are outside the Python/script counts. Tests of
package contents or Python workers cannot close those configuration boundaries.
