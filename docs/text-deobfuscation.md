# Text preservation and descriptive visual comparison

The former text path applied global spelling/style edits as deobfuscation:
digits became letters, ordinary `l` became `I`, accents and currency symbols
were replaced, punctuation/capitalization rewritten and abbreviations expanded.
The engine iterated those editors with a visual character map up to four times,
then counted the generated transformations plus a layering bonus as suspicion.
This measured the editor's activity rather than independently observed concealment.

A private offline audit reconstructed text from all 20 original MIME messages
and reconciled the persisted pre-change text results. All 20 were rewritten and
all reached text score `1.0`, adding `0.18` to final attribution under the existing
`0.6 * text * 0.3` blend, including the ten owner-recognized legitimate messages.
Character substitution, noise removal and case correction appeared in every
case; abbreviation expansion in nine and homoglyph normalization in five.
This finding is an execution/heuristic audit, not adjudicated accuracy evidence.

## Version-2 text contract

`TextDeobfuscator.deobfuscate_text` and the main engine now preserve the decoded
input string in both `original_text` and `final_text`, including numbers, accents,
case, whitespace, punctuation and URL spelling. The generic text editor and its
private rewrite/scoring routines have been removed. The engine analyzes text
once and no longer feeds visual comparisons through repeated text layers.

`text_schema_version: 2` exposes original descriptive counts and a
`visual_comparison` object. The limited existing character/brand map remains a
comparison aid; its derived text and transformation records are explicitly
`comparison_only`, with incomplete Unicode-confusables coverage. That object is
neither decoded MIME evidence nor verification of impersonation or maliciousness.
Its text is never used as a recovered URL or as the final text of the message.

The artifact's `assessment_status` is `descriptive_only`, `calibrated` is false,
`transformations` and `suspicion_indicators` are empty and `suspicion_score` is zero.
The numeric field remains for the existing blend/API contract; zero contribution
means no validated text-obfuscation risk signal from this path, not a benign
verdict or a completed phishing assessment. `readability_improvement` remains
zero for compatibility; editorial readability is no longer claimed as analysis.
Content observations continue separately in the auxiliary content assessor.

Both the exported direct text API and the main engine return the same indicator
field. Aggregate results expose `coverage`, `assessment_status`, `calibrated`
and `score_scope: nontext_transformations_only`. Text-only (including empty text)
results are `descriptive_only`, with aggregate `suspicion_score: null` and
`complexity_rating: not_evaluated`. With no supported analyzed input, the status
is `not_evaluated`. Nontext-only inputs are `heuristic_only`; mixed text/nontext
inputs are `partial`, with text risk detection explicitly `not_evaluated`.
The numeric aggregate in those cases describes only nontext transformations;
it does not assess text or establish a negative detection result.

The human `deobfuscate` CLI shows these coverage limits, suppresses numeric
suspicion/complexity for text-only input, and labels any nontext number as an
uncalibrated transformation heuristic. JSON consumers must handle a nullable
aggregate score; nested text scores remain zero compatibility contributions.

URL refanging/decoding, original URL identities and candidate provenance remain
in the URL-specific module. HTML and JavaScript analysis and their heuristics
are outside this correction; ordinary HTML decoding may still add points.
The subsequent [HTML correction](html-evidence.md) removes that routine-decoding
contribution and extends descriptive coverage to HTML. The historical pilot
measurements below remain as recorded; JavaScript requires a separate audit.
Historical sealed cases are not rewritten. Consumers of the old altered text
must use preserved text or the explicitly descriptive comparison metadata.

## Validation scope

Constructed regressions cover ordinary text, multilingual/currency content,
numbers and URLs, visual comparisons, repeated analysis, final-score effects
and real encoded-URL recovery. They verify contracts, not classifier accuracy.
The real full-CLI integration checks persisted text against original MIME
alongside score-ledger, original-byte and seal checks.

Further work remains on HTML/JavaScript transformations, header/domain signals,
legacy entry points and representative independently adjudicated holdout data.
Reducing a heuristic contribution alone does not demonstrate improved detection.
UI and the separate Linux detonation lab remain deferred.

The final serial Windows suite ran 183 tests: 178 passed and five POSIX-only
tests were skipped. Eight text regressions cover preservation, comparisons,
scoring, repeated analysis, encoded URLs, direct/engine schema parity, aggregate
coverage and actual human/JSON CLI entry points. The preservation/score regressions
failed against the old path and pass after the correction. Eight supervised
full-CLI content cases and eleven real
offline URL cases passed, including original-byte and evidence-seal checks.

The private full `--no-egress` run completed all 20 original EMLs in 25.090 seconds,
with 115.88 MiB peak sampled process-tree RSS (50 ms sampling). Original bytes,
execution records and seals verified. Text matches original MIME extraction;
nontext deobfuscation artifacts, URLs, remaining headers, authentication and MIME
metadata are unchanged. Every raw score reconciles after removing exactly `0.18`.
One verdict changes from Suspicious to Inconclusive; all 20 are now Inconclusive.
The ten owner-recognized legitimate scores range from `0.05` to `0.16`; four
suspected-phishing scores range from `0.20` to `0.21`; the possible-fraud score
is `0.35`. Provisional labels and attribution decisions are separate; these
ranges do not validate detection, and Inconclusive does not mean benign.

Thirteen cases still have nonzero URL/HTML deobfuscation contributions. Those
signals need a separate audit. No accuracy metrics or speed-improvement claim
are made; the historical four-hour online run remains unreproduced.

The subsequent review correction only adds aggregate coverage and fixes direct
API/CLI presentation. Compared with the first text-preservation run, all 20
final score artifacts, original text, visual comparisons, URL/nontext artifacts
and remaining evidence are unchanged. All 20 expose partial aggregate coverage
and text risk detection not evaluated. New coverage/schema/CLI regressions
reproduce the reviewed defects before this correction; nullable aggregate values
do not change nested compatibility contributions or final attribution weights.
