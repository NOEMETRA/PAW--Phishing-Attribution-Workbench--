# Evidence, score and residual consumer audit

Baseline: merged PR96, `d7399a5a7443e6ad3809960d9856930a550a9205`.
This is a finite disposition of the current offline assessment publication path,
with a correction for HTML observer availability (G06). It is not a certification
of every renderer, collector, helper or independent classifier accuracy.
Original cases and seals remain historical evidence and are not rewritten.

## Evidence to numeric score

The [score ledger](score-explanations.md) remains schema 2. Its finite, unrounded
component sum produces `raw_score`; clipping produces `decision_score`; the
selected profile thresholds produce the decision before two-decimal display
rounding. A profile modifier is a parameter, not observed evidence. The heuristic
is uncalibrated and is not a phishing probability.

| Source family | Numeric treatment and current boundary |
| --- | --- |
| Received/header diagnostics and structural additions | Unverified header observations. The three named Received additions retain zero automatic contribution under their existing contracts. Header syntax/timing observations do not establish who transmitted the message. |
| Authentication | Only completed independent failures enter the authentication component. Receiver claims and missing checks do not enter as verified failure. Supplied local DKIM key provenance remains unverified. |
| Sender/domain metadata | Domain-age and spelling comparisons retain individual observations and limitations; they are heuristics, not verified ownership or operator attribution. Missing comparisons contribute no invented risk. |
| Text, HTML and JavaScript observations | Current production artifacts give no risk contribution. Descriptive rows, truncation, parser failure and missing optional dependencies are coverage evidence. |
| URL transformations | Current legacy nontext transformation heuristic remains uncalibrated. Candidate/source records and literal/non-target distinctions follow source v6. This change does not alter those records or arithmetic. |
| Dynamic observations | Existing detonation/canary metadata parameters remain separate. Offline workers skip collection; no dynamic result is invented. Active acquisition and authenticity require S14/S15 acceptance. |
| Caller additions | Named, finite additions through `finalize_score`, with caller provenance; engine-owned component names are reserved. Direct arbitrary dictionary mutation is not a trust boundary. |

## Reproduced G06 boundary

Five actual baseline `full --no-egress` cases retained originals and produced
scores of 0.05 under the strict profile. They demonstrated:

- An iframe with no declared dimensions acquired the legacy
  `invisible_iframe` indicator because missing values defaulted to numeric zero.
- A supplied document produced 270 hidden-selector matches, 270 script records
  and 1,030 form inputs, without independent observer publication limits or
  omission counts. The outer HTML status was partial because the separate
  encoded-attribute observer exceeded its node limit; that did not explain the
  other observers' coverage.
- None of the five cases exposed an HTML observation stage in score coverage.

A bare width attribute did **not** reproduce the initially suspected exception:
both real parser versions represent it as an empty string. Exception behavior is
tested by explicit fault injection; this is not a claim of a naturally reproduced
parser crash. Before this correction the optional observers swallowed such
exceptions into empty results, and the outer status depended only on the
encoded-attribute observer.

## Supported observer contract

Existing single-document HTML schema 2 and independent-document schema 3 remain
in use, with additive `observer_schema_version: 1` and `observer_coverage`.
Hidden elements, forms, iframes and inline scripts share one publication boundary:

| State | Meaning of counts and result |
| --- | --- |
| `completed` | Enumeration returned; `observed_count = inventoried_count + omitted_count`, with zero omitted records. An empty completed collection means no matches in this parser-selected static observation, not browser absence. |
| `partial` | Actual enumerated records/inputs exceed a publication limit. Counts name retained and omitted observations. This is not additional risk. |
| `failed` | The observer or selector raised; exception type and an issue code are recorded, without arbitrary exception text. Its empty fallback has zero retained records and **unknown** total/omitted counts (`null`), never a completed zero-match scan. Previously computed rows of that failed observer are withheld; other observers still run. |
| `not_evaluated` | Optional parser unavailable. Total/omitted counts are unknown; empty output is an unavailable fallback. |

Each observer publishes at most 256 records per document. Forms also publish at
most 1,024 input matches across retained form records; the input totals include
inputs in omitted forms. Hidden totals count selector matches, so the same element
can occur more than once. Form input matches are descendants per parsed form,
not browser form association. Nested malformed trees may count the same input
under multiple forms. Retained script-pattern arrays and iframe indicator counts
describe retained records only; an omitted row cannot contribute an aggregate.
These legacy `suspicious_*` names are descriptive pattern matches, not detection
results. Script text remains a 200-character preview, now with preview truncation
counts; hidden element text is also a 200-character preview with truncation
counts. Full original
HTML remains in the document and its bound MIME text artifact.

These are **output record limits**, applied after enumeration. They do not bound
the parser tree, enumeration CPU, individual attribute length or total result
bytes. The supervised worker's existing MIME/input/deadline/memory admission
continues to apply; direct library callers must bound inputs and aggregate
documents. No new browser parser, resource collector or CSS interpretation is
introduced. Encoded-attribute node/candidate/size limits retain their own status
and do not claim exact unknown totals beyond their scan boundary.

Missing, bare, CSS-like, negative or unsupported iframe dimensions are not
invented zero. The retained legacy `invisible_iframe` indicator now requires a
literal nonnegative decimal declaration equal to zero or one. It still does not
establish visibility: each iframe explicitly records `visibility: not_evaluated`
and which dimension attributes were supplied. No CSS/layout or rendering runs.

The outer HTML status is partial whenever a candidate or optional observer is
not completed. Each independent document retains its own coverage and limits;
one document's failure/omission does not manufacture a result for another.

## Publication consumers

`html_observation_coverage` projects metadata without duplicating source HTML or
observation rows. The worker binds original documents to MIME part/text/hash
before persisting this view. The following are current supported consumers;
passing selected cases establishes the listed correspondence, not every input
shape or frontend renderer.

| Consumer | Source and disposition |
| --- | --- |
| `deobfuscation_results.json`, `headers.json` | Same complete analysis, including document observer coverage and MIME source binding. |
| `analysis_coverage.json`, `report/score.json` | Same coverage object. `stages.html_observations` equals deobfuscation `coverage.html`; absence of HTML is `not_evaluated`, with zero documents. Numeric components are unchanged by diagnostic states. |
| Executive Markdown | Dedicated literal JSON coverage block plus the stage list, decision score, thresholds and component explanations. Unknown counts stay null. |
| Technical Markdown | Existing literal full deobfuscation JSON includes the same metadata, original documents and observations. Attachment coverage/table remain separate. |
| Local MIME/JSON review drafts | Preserve full score and coverage in their assessment; no send, recipient, authenticity or ARF/X-ARF conformance claim. The subsequent residual-consumer contract also gives the plain text template a literal complete assessment and explicit current/legacy view. |
| SQLite and query | Stores the rounded display score. This does not independently preserve thresholds, decision or coverage and must not recompute a verdict from the column. The subsequent read-only assessment annotation retains missing decision/profile/coverage as unknown; existing fingerprint provenance is separate. |
| HTTP case/list responses | Return the persisted score/coverage/deobfuscation and literal reports after stopped-owner admission. The list summary is the complete persisted score for completed cases. |
| ZIP export and verify | Preserve selected source/report bytes and integrity inventories; neither export nor a matching seal establishes source authenticity or accuracy. |
| Standalone deobfuscation | Direct engine output includes observer coverage; case-level stage/report/source binding belongs to supervised email analysis. |
| Diagrams, terminal, active publishers and UI | Existing scoped contracts remain; residuals below are not closed by adding this coverage view. |

## Finite residual dispositions

The following source-inspected residuals originated at this baseline. Their
subsequent [publication contracts](residual-consumer-contracts.md) give R01–R07
supported or unavailable dispositions; R08 remains final candidate acceptance.
They are not silently covered by G06 or the historical tests above. This inventory is limited to current
assessment/coverage publication and the HTML perimeter; it does not replace the
[whole-engine register](engine-stabilization-checkpoint.md).

| ID / owner | Concrete residual and next acceptance criterion |
| --- | --- |
| R01 — S08 | Current consistent score decisions drive Rich colors; all profile/rounding boundaries and actual cells are checked. Unknown/legacy/inconsistent views are neutral. Numeric scoring is unchanged. |
| R02 — S08 | Read-only query annotations retain recorded rounded values without inventing decisions/profiles/coverage; new missing index scores are SQL NULL. Plain drafts include the common view and full recorded assessment. Historical cases/database rows are not rewritten. |
| R03 — S08/S14/S15 | Dynamic report sections use bounded literal JSON with unverified acquisition/identity/risk scope. No risk label is derived from stored visitor metadata. Actual active collection/behavior acceptance remains S14/S15. |
| R04 — S08/S14 | Literal saved provider fields explicitly leave Rekor inclusion verification unavailable. The direct verifier returns None; content integrity verification separately reports NOT_EVALUATED instead of treating unavailable inclusion as a cryptographic pass or failure. Existing provider exclusions remain; actual inclusion/authenticity is not established. |
| R05 — S08/S13 | PGP publication is explicitly unavailable before key/output access; requested manifest signing has unavailable coverage. Ordinary ZIP remains supported; requested ZIP signing rejects without changing existing archive/signature bytes. Independent signer/proof acceptance remains S08/S13. |
| R06 — S08/S16 | Named historical JSON/report consumers share strict bounded type/encoding/ambiguity/resource admission and named errors; healthy API neighbors remain readable. Rich saved hypotheses are literal/unverified. Runtime journals, arbitrary SQLite schemas/cells, active-provider terminal branches and frontend acceptance retain separate contracts. |
| R07 — S09/S14 | Retain G05 as an explicit narrow legacy kit CSS capture: resource interpretation unavailable, network_target false, exact capture/provenance preserved. No main-scanner parity, escape decoding or resource resolution is claimed. |
| R08 — S01/S02/S13 | Final isolated installation and Windows/POSIX optional-component/preset/batch/interruption acceptance remain candidate gates. Current serial source/wheel/CLI/API regressions preserve the consumer contracts; they do not constitute that final combined acceptance. |

G01/G02 retain their [attachment preservation/unavailability](attachment-capability-coverage.md)
decisions; G03/G04 remain generic/excluded interpretations. G06 now has the
bounded diagnostic contract above. Independent corpus labels, holdout evaluation
and calibration remain S10. The private 20-original pilot has no attachments and
cannot substitute for positive observer fixtures or independent phishing labels.

## Validation record

The focused direct contracts cover each observer failure, actual parser/selector
fault injection, missing optional parser, empty completion, exact record/input
boundaries, duplicate selector counts, retained-only aggregates, script previews,
unsupported dimensions, independent documents and state isolation/no egress.
The real integration exercises six full CLI cases and four owned-loopback HTTP
workers, including drafts, SQLite display score, API list/detail, reports and ZIP.
These constructed inputs are regression fixtures, not classifier ground truth.

Final serial validation on 23 October 2026:

| Check | Actual result |
| --- | --- |
| Full contract suite, Python 3.13.5 / BeautifulSoup 4.13.4 | 1,011 tests: 997 passed, 14 expected Windows exclusions. Eleven new observer methods. |
| Selected observer/HTML/context/score/literal-report contracts, Python 3.13.15 / BeautifulSoup 4.15.0 | 60 passed on the second actual Windows runtime. |
| New observer integration, repeated on both runtimes | Six full CLI cases / four owned-loopback HTTP workers per runtime; same fixtures, not independent labels. |
| Previous HTML text-context integration | 15 CLI / six HTTP, including source v6 and exact 5,000/4,096/904 source-link accounting. |
| Previous literal-report, attachment-capability and URL-source integrations | Respectively three/one, eight/six and nine/five CLI/HTTP cases. |
| Five exact-original baseline replays | Same raw inputs; MIME/auth/URL/attachment/Received evidence and all previous score fields agree after separately verifying later, aware UTC domain-age/Received reference times and the new HTML coverage stage. Historical baseline bytes/hashes and old/new seals verify. |
| Real wheel | Python requirement/entry points and all 95 package Python sources match the current checkout. This is not a clean dependency installation. |
| Freeze | All 286 tracked Python/workflow hashes remain unchanged throughout the serial matrix and its completion. Only documentation and private verifiers changed after freezing. |

The final matrix completed **52 CLI cases / 26 HTTP workers**, including repeated
fixtures and the five baseline replays. Earlier development executions and the
five original baseline cases are not added to that total. The first development
integration completed its case checks but failed Windows temporary-directory
cleanup because the harness retained its own SQLite reader; explicit reader
closure repaired that harness defect. The repeated integration then passed.

The first private exact-replay verifier stopped on the expected Received
reference timestamp. Its failure log is retained. The corrected verifier reads
the same five completed cases, validates both later UTC reference timestamps
separately, and compares every other prior field without rerunning analysis or
changing runtime/test/workflow sources. Public static contracts, changed-document
file links and diff checks also pass; private logs and case files stay outside Git.

Fresh exact-head Copilot review and CI remain integration gates. No sample
URL/DNS access, attachment execution, Docker or active provider acquisition is
part of this audit. These historical measurements do not substitute for the subsequent R01–R07 publication tests, R08 final acceptance or independent accuracy evidence.
