# Residual consumer publication contracts

Baseline: merged PR97, `ccc946c5f61f197d088a924583e512241fafd56f`.
Copilot recommended approval with no open issues on `95f3688a753cb4675f4d34978c0e3896acd928ac`;
all three head/merge checks passed (`40010089025` / `40014199646`).
This is the next finite disposition of [R01–R08](evidence-score-consumers.md),
within the current offline candidate. It does not enable active acquisition,
independent signatures, a browser, UI completion or classifier calibration.

## Reproduced boundary

The baseline passive/supplied-data probes reproduced:

- Strict score 0.69 had a malicious decision with a yellow Rich verdict; the
  conservative 0.74 suspicious decision was red. The fixed 0.72 color threshold
  disagreed with profile-specific decisions; numeric decisions were already correct.
- Each dynamic Markdown helper produced an image and two inline HTML nodes from
  a supplied literal endpoint value. The Canary helper also derived a High-risk
  label from unverified stored reputation metadata. Parsing was passive: no URL
  or image was fetched.
- The API reader accepted `NaN`; a nonempty array manifest raised `AttributeError`
  in the case list. A missing score passed to the index writer became numeric zero.
- Kit CSS retained a combined quoted argument/comment capture under the label
  “CSS url() argument”, without an explicit non-resource disposition.
- Three actual full no-egress cases preserved originals and structured scores,
  but plain-text drafts did not contain the unrounded decision score/coverage view.

The first synthetic API probe attempted to create an asyncio event loop inside
the no-egress guard and was refused. Its record is retained; the separate
read-only probe outside that guard reproduced the nonempty-array manifest error.
No email analysis was run without `--no-egress`.

The first development integration of supplied Rekor fields additionally exposed
`verify_case` treating an unavailable inclusion verifier as a BAD proof and
mixing that result with content integrity. This is repaired in the same family.
The supplied-provider fixture is not an actual log entry or acquired observation.

## Current dispositions

| Residual | Supported boundary and remaining gate |
| --- | --- |
| R01 | Rich color uses the internally consistent current score decision, including its actual profile/unrounded ledger. Unknown, legacy or inconsistent metadata gets an unavailable/neutral presentation. The numeric scorer is unchanged. |
| R02 | A common descriptive assessment view distinguishes current internally consistent metadata, legacy display-only values, invalid metadata and missing assessment. SQLite/query annotations are computed in memory without migration or sealed-case writes. No decision/profile/coverage is inferred from a rounded column. Plain-text drafts include the same view and full recorded assessment; structured drafts retain their existing complete assessment. Missing new index scores are SQL NULL, not zero. |
| R03 | Detonation/Canary report helpers publish bounded literal JSON with explicit unverified acquisition/identity/risk limitations. Supplied legacy values and types remain data; no risk label is computed from them. Original saved artifacts are retained. Active collection/browser/identity acceptance remains S14/S15. |
| R04 | Technical Rekor output retains literal anchor/proof fields and read errors with `verification.status: not_evaluated`, `result: null`. `treeSize` presence never establishes verification. The unimplemented direct verifier returns None. `verify_case` returns content-inventory integrity only and separately prints Rekor NOT_EVALUATED if provider files exist, including malformed/unpaired files. Existing circular-provider exclusions remain unchanged; this is not proof validation. |
| R05 | PGP publication is explicitly unavailable pending signer/proof acceptance. The direct signer rejects before inspecting paths/keys or writing. A CLI ZIP signing request (`PAW_PGP_PRIV`) rejects before the export publisher reads case/key/output paths, preserving existing ZIP/signature bytes; unset that variable for ordinary ZIP export. CLI stopped-owner admission is a separate earlier guard. A manifest signing request permits ordinary supervised analysis with explicit unavailable coverage and no key access/signature output. No signer identity or authenticity is established. |
| R06 | Saved JSON/text consumers share the bounded, typed, strict reader described below. API neighbors survive malformed artifacts with named errors; reports are not lossily decoded. The Rich summary uses literal text for values and preserves an unverified stored hypothesis instead of interpreting arbitrary confidence as an identity. Runtime control journals, arbitrary SQLite schemas/cells, active-provider terminal branches, browser rendering and UI acceptance retain their separate contracts/gates. |
| R07 | Retain the narrower existing kit CSS regex, rather than expand parsing. Its exact capture is marked `grammar: legacy_css_url_regex_v1`, `resource_interpretation: not_evaluated`, `network_target: false`. G05 is disposed as a qualified lexical observation for this candidate; shared resource grammar/parity requires a separately justified capability. Main URL source v6 is unchanged. |
| R08 | Preserve these contracts in current CLI/API/query/export/regression and wheel checks. Final isolated dependency installation, supported Windows/POSIX optional-component/preset/batch/interruption acceptance, independent corpus/holdout and later isolation/egress/UI remain named candidate gates. This PR does not declare that final matrix completed. |

R01–R07 have current supported or unavailable dispositions within the listed
boundaries. R08 remains a final candidate acceptance gate. This does not close
every S08/S13/S14 helper or any independent attribution-accuracy requirement.

## Assessment projection

`assessment_view` never changes the supplied score object. It names its source
and always leaves authenticity unassessed. For schema 2, it checks native finite
numeric metadata, a supported profile, component sum/clipping/rounding and the
current derived metadata against `finalize_score`. Coverage must be an object;
this is not a schema validation of every nested coverage field or evidence truth.

Only internally consistent current metadata exposes its recorded decision,
decision score, thresholds, profile and coverage. A historical rounded column
retains its finite native [0,1] display value, with decision/threshold/profile/
coverage/calibration unknown. Boolean, nonfinite, string or missing scores do not
become zero. SQLite infinities retain their typed spelling in `score_source`
while the JSON numeric slot is null; stored database bytes remain unchanged.

The API's original score/summary fields still expose admitted persisted objects;
the additive `assessment_view` supplies interpretation/availability. A legacy
recorded decision may remain in the raw source while the view's decision is null.
Neither query nor an old source is silently upgraded to a current decision.

## Saved artifact admission

`consumer_views.py` applies to the API's named case JSON artifacts and reports,
local draft source reads, the Rich summary's three saved observation artifacts
and the technical report's saved Rekor fields. Expected roots are objects, except
attachments and URL evidence which are arrays. Raw originals remain unchanged.

- Per artifact: at most 64 MiB UTF-8 bytes; strict decoding, regular opened-file
  identity, no final symlink/FIFO and case-relative containment where supplied.
- JSON: duplicate keys and `NaN`/infinities (including exponent overflow) reject;
  at most 1,000,000 traversed value nodes and depth 128. Keys are bounded by input
  bytes. Byte admission precedes parsing; node/depth admission follows parsing.
- API list/detail/statistics: one aggregate 128 MiB accepted-source-byte and
  1,000,000 visited value-node budget per invocation. Read bytes are charged even
  if decoding/parsing fails; visited nodes are charged until validation stops.
  It does not certify process memory, concurrency isolation or elapsed CPU time.
- Unsupported shape/encoding, ambiguity, limits and read errors return unavailable
  artifact values plus named diagnostics. A valid neighboring case stays readable.
  Statistical country/ASN fields are type-checked before aggregation.
- Text views keep the API's existing universal-newline normalization. Original
  file/ZIP bytes and JSON string escape values remain unchanged; strict decoding
  replaces the old lossy report-decoding fallback.
- Dynamic/Rekor literal JSON views publish at most 256 KiB ASCII JSON characters.
  Larger/nonfinite/non-JSON supplied values receive an explicit unavailable view,
  rather than clipped evidence. Full source artifacts/caller values remain intact;
  these are publication limits after serialization, not parser/CPU limits.

The operational runtime/job journal reader is intentionally separate: changing
recovery semantics is not part of this historical-evidence projection. Filesystem
checks do not establish an atomic snapshot against unrelated external writers,
physical OS isolation or authenticity. API stopped-owner admission still runs
before exposure; the shared readers do not replace that protocol.

## Integrity and unavailable proofs

`verify_case` checks indexed file contents and, for modern cases, complete file
inventory. A match is not email authenticity, a valid signer or a Rekor inclusion
claim. Existing provider statement/anchor/proof files remain excluded under the
recorded circular-inventory policy. Their presence, absence or invalid JSON does
not independently prove or disprove the content hashes. Content tampering still
fails. No existing index, root, case or seal is rewritten by these projections.

PGP signing is unavailable; retained old signature bytes are neither removed nor
validated. HTTP ZIP export remains a file archive and does not request signing.
No Rekor fetch, key retrieval, attachment execution, Docker or suspicious endpoint
access occurs in this work. The Python guard is application policy, not OS isolation.

## Validation

The direct contracts exercise profile thresholds and actual Rich cells, modern/
legacy/inconsistent score views, strict JSON/UTF-8/shape/size/node/depth admission,
SQL NULL/read-only legacy annotations, literal dynamic/provider values and output
limits, unavailable proof semantics, PGP refusal before I/O, narrow kit CSS,
both draft languages and malformed API neighbors.

The actual integration covers all three profiles with CLI analyses of one
constructed message and the repository's public original, both draft languages,
ordinary ZIP and refused PGP requests preserving existing outputs, read-only CLI/
HTTP queries, three owned-loopback API workers and damaged artifact reads isolated
from healthy neighbors. A separate actual direct offline engine fixture inserts
explicitly supplied saved-provider fields after scoring to exercise the report
branches, not simulate acquisition. Newly generated test artifacts are deliberately
damaged/restored; historical user cases and baseline seals are untouched.

Final serial validation, 23 October 2026, on the corrected source freeze:

| Check | Measured result |
| --- | --- |
| Full suite, Python 3.13.5 / BeautifulSoup 4.13.4 | 1,030 tests: 1,015 passed, 15 expected Windows exclusions. Nineteen new consumer methods. |
| Selected consumer/score/terminal/engine/index/report/kit/MIME contracts, Python 3.13.15 / BeautifulSoup 4.15.0 | 107 tests: 105 passed, two expected Windows exclusions. |
| New actual residual integration, both actual runtimes | Six completed CLI cases, three owned-loopback HTTP workers and one direct offline supplied-publication fixture per runtime. Three profiles, two draft languages; repetitions are not independent labels. |
| Previous G06, literal-report, attachment-capability and URL-source integrations | Respectively six/four, three/one, eight/six and nine/five completed CLI/HTTP cases. |
| Legacy draft publication | Two actual supervised public-original EML analyses, English/Italian unsent drafts and guarded legacy refusal/import/help checks. |
| CLI/API ownership and recovery | Eight completed original-EML cases plus actual live-reader/query refusal and supervisor-kill recovery; a separate interrupted-artifact API check preserves damaged bytes through partial sealing. These lifecycle scenarios are separate from ordinary completed-case counts. |
| Exact-original replay | Three same-input baseline cases; all prior score fields and named header/MIME/auth/URL/attachment/Received evidence match after separately verifying later UTC domain-age/Received reference times and the additive unavailable/skipped manifest-signing stage. Historical baseline bytes/hashes and old/new seals verify. |
| Actual wheel builds | Requirement/entry points and all 96 current Python sources match. A second bounded build check additionally verifies both modified plain-text template bytes and retains its wheel privately. No clean dependency installation is claimed. |
| Freeze | All 293 tracked Python/template/workflow hashes, including 289 Python/workflow files and four templates, remain unchanged through the final 13-job matrix and the changed-template wheel check. |

Changed-document links, the public static contracts and diff checks also pass.
Logs, old/new cases, frozen hashes and wheel stay outside Git. Fresh exact-head
Codex review and CI remain integration gates. Passing tests and constructed
fixtures are not independent accuracy evidence or R08 final candidate acceptance.

The first frozen matrix stopped at the prior G06 HTTP report comparison: the new
reader initially retained raw CRLF in text views, unlike the existing universal-
newline API behavior. That failure and its four preceding successful jobs remain
recorded privately. Validators stopped before the reader and its regression test
were corrected. The original G06 integration then passed; final validation uses a
new freeze/matrix. Tests were not relaxed to accept a changed API representation,
and neither source file bytes nor ZIP bytes were normalized or rewritten.

The first PR98 CI run stopped because the new consumer unit step ran before
the existing CLI/API dependency installation (`markdown_it` was unavailable).
The workflow now runs that step after installation. Runtime, tests and templates
retain the final matrix's frozen bytes; the workflow ordering is checked by a
fresh CI run. Copilot could not review because its quota was exhausted; the
owner requested Codex review for the corrected head.
