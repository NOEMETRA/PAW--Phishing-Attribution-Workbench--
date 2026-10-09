# Final heuristic score explanations

The final score is an attribution-review heuristic, not a calibrated probability
or a binary phishing classifier. A successful offline run and matching evidence
seal establish execution and local integrity, not sender authenticity or accuracy.

## Numeric defect and contract

The old engine rounded the base score to two decimals, added Received anomalies
to that rounded number, then reclassified it. A valid constructed score input
produces `0.5192` under the strict profile: `score_case` called it Inconclusive,
but `finalize_score` read the displayed `0.52` and promoted it to Suspicious.
Intermediate clipping also lost a conservative profile's negative offset before
later additions. These are arithmetic defects, not evidence for new thresholds.

`report/score.json` now has `score_schema_version: 2`:

- `score_components` records the additive contributions. `raw_score` is their
  finite unrounded sum, before clipping to [0, 1].
- `decision_score` is the clipped unrounded value used for classification.
  `score` is that value rounded to two decimals for compatibility/display only.
- `profile`, `thresholds`, `decision_basis`, `decision_scope` and `calibrated`
  expose how the verdict was computed. Existing profile modifiers, weights and
  thresholds remain. Verdicts use exact `>=` comparisons with the unrounded
  decision value; neither a tolerance interval nor display rounding promotes
  a value below a threshold.
- `component_sources` explains the provenance and limits of each contribution.
  Claimed headers, independent verification results and profile parameters are
  explicitly distinguished. Components are grouped contributions, not a claim
  that every observation proves maliciousness.

| Component | Interpretation |
| --- | --- |
| `header_observations` | Header timing/syntax and optional HELO/PTR diagnostics; the chain is unverified |
| `verified_authentication_failures` | Only independently completed verification reporting fail |
| `sender_domain_heuristics` | Sender/reply spelling, structural lookalikes and optional domain measurements |
| `deobfuscation_heuristics` | Transformation-based heuristics; ordinary encoding can contribute |
| `dynamic_observations` | Optional detonation/canary metadata, without actor attribution |
| `profile_modifier` | Selected parameter, not independently observed evidence |
| `received_*` | Named structural anomaly additions from unverified Received claims |

The existing blend for deobfuscation is
`clamp(0.6 * text + 0.25 * max_url + 0.15 * html) * deobfuscation_weight`.
It is explained, not statistically validated by this change. Missing enrichment
does not add points. The CLI leaves ASN/recurrence flags disabled; campaign
correlation remains unavailable. Malformed/nonfinite numeric score metadata is
rejected rather than converted into a successful verdict.

The subsequent [text-preservation correction](text-deobfuscation.md) removes
editorial rewrites from the text path. Newly produced version-2 text artifacts
contribute zero; limited visual comparisons remain descriptive. The blend and
URL/HTML contributions remain unchanged. Historical scores below describe the
pre-correction pilot and are not rewritten.

`finalize_score` still accepts legacy dictionaries containing only `score` and
the `additional` argument; such a base is explicitly labeled `legacy_base`.
New callers add through `additional` or `additional_components`. Directly
modifying the displayed value of a version-2 score or supplying a ledger that
does not reconcile with its raw sum is rejected. Finalizing again without new
signals is idempotent; omitting the profile retains the artifact's profile
(legacy inputs default to `default`). Changing a version-2 artifact's profile
is rejected: recompute with `score_case` under the requested profile so its
modifier and thresholds agree. Legacy plain-score inputs still accept a profile
on their first finalization. Historical sealed cases are not rewritten.

Caller additions cannot use engine-owned names (`header_observations`,
`verified_authentication_failures`, `sender_domain_heuristics`,
`deobfuscation_heuristics`, `dynamic_observations`, `profile_modifier` or
`legacy_base`), including when absent from the input ledger. Ordinary custom
additions carry caller provenance; supported Received additions describe only
unverified structural claims. This prevents the additions API from presenting
a caller value as independently verified evidence. A ledger is not a trust
boundary against arbitrary modification of an input dictionary.

The executive Markdown report includes decision value, thresholds and components;
CLI summaries also show the value before display rounding. The GUI rebuild
remains deferred; consumers must migrate to the explicit version-2 fields.

## Private pilot and remaining validation

Twenty original EMLs are stored outside Git with restricted local permissions.
Separate static content triage reads original MIME using stdlib decoding and
inert HTML text parsing, without selecting categories from PAW scores. It is
assistant triage, not independently adjudicated human ground truth. The mailbox
owner previously recognized ten legitimate subscriptions/account operations.

The other ten, acquired from Spam, comprise four suspected phishing messages,
one possible fraud, three commercial-spam candidates and two uncertain messages.
No linked page was opened, no attachment executed, and sender authentication
was not independently established. Provisional categories remain separate from
the folder annotations; none are included in classifier accuracy metrics.

A pre-change audit reconciled all 20 persisted scores. Deobfuscation contributed
in all 20 cases, including the ten owner-recognized legitimate messages; sender
identity heuristics contributed in eight and Received additions in ten. None had
a verified authentication-failure contribution. The ten legitimate scores ranged
from 0.23 to 0.34, suspected-phishing scores from 0.38 to 0.39, and commercial-spam
candidate scores from 0.24 to 0.39. These overlapping uncalibrated scores do not
establish a validated separation of classes. Nineteen attribution decisions were
Inconclusive and one Suspicious; Inconclusive does not mean benign.

Regressions cover unrounded boundaries, clipping, ledger reconciliation,
verification provenance, finite numbers and legacy callers. The real supervised
full-CLI integration checks persisted score/report contracts alongside original
bytes and seals. Fixtures are regression inputs, not accuracy labels. Further
work includes independent adjudication, a larger representative holdout corpus,
the meaning of transformation/header/domain heuristics and attribution labels,
legacy scripts, clean installation and the separate Linux dynamic-analysis lab.

## Measured validation of this change

The serial Windows suite ran 175 tests: 170 passed and five POSIX-only tests
were skipped. Seventeen score-contract tests exercise the numerical defects and
ledger rules. Eight supervised full `--no-egress` CLI cases also passed, checking
the persisted explanations, original bytes and evidence seals.

The final private full run of all 20 original EMLs completed in 33.021 seconds,
with 123.42 MiB peak sampled process-tree RSS (50 ms sampling). All originals,
seals and execution records verified; all raw component sums reconciled against
the pre-change audit. Displayed scores and decisions changed in zero cases:
19 Inconclusive and one Suspicious. Header/URL/auxiliary artifacts were
semantically unchanged. The existing unordered set of detected technique names
changed list order in 20 cases; comparison normalized only that descriptive list,
without normalizing ordered URL inventories or transformation records.

These measurements establish regression behavior for this offline pilot.
Accuracy metrics remain unset, and this run does not reproduce the historical
four-hour online analysis or establish a speed improvement.
