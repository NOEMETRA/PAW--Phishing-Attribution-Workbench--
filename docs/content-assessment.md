# Auxiliary content observations

The former `MLScorer` multiplied every character by 0.05. A neutral 600-character
body exceeded its high-risk threshold and recommended blocking. In a private
20-message original-EML pilot, all messages received that recommendation,
including all ten messages the mailbox owner recognized as legitimate. Length
alone exceeded the threshold in every case. These folder/owner annotations do
not establish independently adjudicated phishing ground truth.

This module is a rule-based diagnostic, with no trained model, validated risk
thresholds or calibrated probability. Its version-2 output records observations
and leaves risk assessment explicitly `not_evaluated`. No matches do not establish
safety; matches can occur in legitimate notifications, marketing or quoted text.

## Version-2 artifact contract

The real `trace`/`full` flow continues to store the result at `headers.ml_score`.
Consumers must check `schema_version: 2` and the accompanying metadata. The old
name `phishing_score` is retained as an **uncalibrated indicator sum**, not a
probability or phishing verdict. Old and new scores are not directly comparable.

- `method: static_content_heuristics`, `assessment_status: heuristic_only`,
  `calibrated: false`, `score_kind: uncalibrated_indicator_sum` describe the scope.
- `weights`, `contributions` and `evidence` explain each included lexical signal.
  Existing weights for phrase/pattern counts and language co-occurrence remain;
  this change does not calibrate them. English phrase rules and Danish/English
  word co-occurrence do not provide general multilingual coverage.
- Length, original-case capitalization ratio and punctuation are descriptive
  features only. Appending neutral text or punctuation cannot add to the sum.
- Matching uses word boundaries and accepts whitespace between phrase words.
  Phrase and regex matches are searched independently within subject and body;
  joining fields cannot create evidence. Each rule contributes once even when
  both fields match it. Language co-occurrence can use words actually present
  in different fields. Subject and body supply lexical content; `From` display
  names do not supply
  content phrases. This is not semantic understanding, intent or quotation analysis.
- Sender address spelling is `sender_pattern_score`, replacing the misleading
  feature name `sender_reputation`. It describes digits, hyphens, dots and listed
  TLDs in a parsed address. Display names do not supply these address patterns.
  Missing/unparsed addresses add no signal; `coverage.sender_verified` is always
  false. Address parsing does not independently verify syntax, identity, domain
  ownership, authentication or reputation.
- `risk_level` is always `not_evaluated`. The unvalidated `clean`, `low_risk`,
  `medium_risk` and `high_risk` categories and their unreachable low-risk branch
  are removed. Their thresholds are not replaced with new arbitrary thresholds.
- `recommendations.block_email` and `inject_canary` are always false.
  `flag_for_review` means an observed weighted indicator needs human context,
  not that the message is malicious. Reasons name the contributing features.
  `action_status: not_authorized_by_heuristics` makes the boundary explicit.

`HeuristicContentScorer` and `analyze_content_indicators` are the descriptive
entry points. `MLScorer`, `get_ml_scorer` and `score_email_for_canary` remain
compatible imports and return the same version-2 contract. Consumers relying
on old risk strings, thresholds, private methods or `sender_reputation` must
migrate. Historical sealed cases retain their original artifacts.

## Relation to attribution and validation

The auxiliary artifact and the older, separate `phishing_analysis` diagnostic
do not feed `score_case`/`finalize_score` in the current engine. The final score
and attribution thresholds are unchanged. Attribution `Inconclusive` is not a
benign classification. Main score interpretation and independent per-message
triage remain open work; this fix does not establish classifier accuracy.

`tests/test_content_contracts.py` covers neutral length/style, missing sender,
word boundaries, whitespace/case, evidence/contribution consistency, legacy
imports, offline operation and separation from the final attribution score.
`tests/integration_content_assessment_real.py` runs eight constructed EMLs through
the actual supervised `full --no-egress` CLI and verifies exact originals, seals
and persisted artifact contracts. Fixtures are regression inputs, not an accuracy
corpus. Both are included in GitHub CI.

Initial Windows validation on 9 October 2026: 155 contract tests, 150 passed and
five POSIX-only skips; five real supervised full-CLI regression cases passed. The 20
private original EMLs were rerun through `full --no-egress`: all originals and
seals verified, URL/evidence inventories and complete final score artifacts
unchanged from the preceding engine run. All 20 auxiliary artifacts now state
`not_evaluated` risk with no block/canary recommendations. Thirteen contain
indicators flagged for contextual review; the other seven are not declared safe.

The original-EML run took 31.914 s with 126.75 MiB peak sampled process-tree RSS
(50 ms sampling). This is an observed offline workload, not a speedup claim,
accuracy measurement or reproduction of the historical four-hour online run.
Raw messages, per-message diagnostics and private run artifacts stay outside Git.

The GitHub review found a remaining field-boundary defect: subject `action` plus
body `required` manufactured evidence for `action required`. This also existed
in the pre-PR scorer. Matching now runs independently per field, including regex
patterns, and merges matching rules without double counting. Regression tests
reproduce all splits of multiword rules, split regex patterns and genuine
same-field matches. Final Windows validation: 158 contracts (153 passed, five
POSIX skips) and eight real full-CLI cases. A fresh 20-original-EML offline run
verified originals and seals, unchanged auxiliary artifacts, URL/evidence
inventories and final scores. It took 23.803 s with 120.93 MiB sampled tree RSS;
these observations do not establish a speedup or accuracy.

## Evidence-linked mail review referral

The installed mail analysis now saves `mail_triage.json` in the sealed case.
The executive report and case API expose the result. The first rule refers a
message for review when parser-selected outer HTML declares a POST form with a
named password input and an absolute HTTP(S) action on a different registrable
domain from the sole parsed From. Domain comparison uses the bundled public and
private suffix snapshot. The From remains an unverified header identity.
Findings identify the MIME part, the hash and path of its captured text, and the
parser coordinates of the form and the input.

Partial MIME/form evidence and nested forms limit coverage. A structurally
admitted HTML part can supply positive evidence from its captured, charset-decoded
text while its payload transfer remains partial. The finding retains that status.
Without a finding, partial evidence yields `not_evaluated`. Duplicate action
or method declarations, direct disabled or reassigned controls, and inert
comment or template markup cannot satisfy the rule. Coverage refers to the
supported parser view. External identity providers and forwarded material can
look similar in static markup. The result is a human review referral with
`calibrated: false`. Sender authentication, actual browser behavior and
infrastructure attribution continue to have their own evidence.

`tools/evaluate_mail_corpus.py --static-triage` evaluates this referral separately.
Constructed CLI fixtures verify the evidence bindings and rule exclusions.
Use independently labelled development data for rule changes and reserve a
fresh holdout for estimating referral error rates.

A second rule compares the complete literal HTTP(S) URL shown as an HTML
anchor label with the absolute URL in its sole `href`. A different registrable
domain yields a review referral. Both domains use the bundled public and
private suffix snapshot. A literal IPv4 or IPv6 destination also yields a
referral when the displayed URL has a registrable named site. Both full-URL
comparisons work even when the From identity is ambiguous.

The comparison also admits a whole ASCII domain name as the anchor label
when the registered site of the named destination differs from both the
displayed site and the single parsed From site. The source includes that
unverified From domain. All variants record the endpoints and anchor
coordinates in the hash-linked MIME text. Relative targets, duplicate hrefs,
nested anchors, inert markup and labels in prose fall outside the comparison.
The parser admits a bounded subset of inline formatting and stops retaining
anchors after 256 candidates per document. Tracking redirects and link
rewriting can produce the same observed difference. The result describes
static markup and leaves the analyst to assess its context.

## Local multilingual text assessment

Install the optional dependencies in the PAW environment with
`python -m pip install '.[text-triage]'`. Stage `onnx/model_quantized.onnx`
and `tokenizer.json` from the pinned model revision in the same local
directory. The two files use about 675 MB of disk. The model is licensed
under Apache-2.0. [Model files and license](https://huggingface.co/Horizon-Labs/phishing-scam-detector-base/tree/c294bf142ff53db24dc9ef07f20149ffeddeae6d)

Run against a completed local case after the analysis worker has stopped.

```bash
paw assess-text --case cases/CASE_DIRECTORY --model-dir /path/to/horizon-model
```

On Linux with Docker Compose, use the [offline container setup](../QUICKSTART.md#analyze-offline-in-a-linux-container)
and put the two local model files under `$PAW_INPUT_DIR/model`. Build the
optional image, then point it at an existing case under `$PAW_OUTPUT_DIR/cases`.

```bash
docker compose -f compose.text-triage.yaml build
docker compose -f compose.text-triage.yaml run --rm paw assess-text \
  --case /data/cases/CASE_DIRECTORY --model-dir /input/model
```

The image installs inference dependencies at build time. The mounted model
files are read-only and the container has only its loopback interface.

The command checks the case seal and the model files' SHA-256 digests, runs
inference on CPU and prints a separate JSON record to stdout. Store any
redirected output outside the case directory to preserve its seal. The record
contains separate `legitimate`, `spam` and `fraud` scores, model identifiers,
the case root, references to captured MIME text and token coverage. The
command has no download step. PAW sets `ORT_DISABLE_TELEMETRY=1` before loading
ONNX Runtime and calls its telemetry-disable API before scoring. The application
offline policy is active during inference. Use a network-isolated host or process
when the operating system must enforce the restriction for native code.
[ONNX Runtime telemetry controls](https://github.com/microsoft/onnxruntime/blob/main/docs/Privacy.md)

Model input is the subject and normalized plain text from parser-selected
outer MIME parts. HTML is reduced to textual content. Inference uses the
first 384 tokens and reports truncation. Attachments, image content, sender
authentication and link destinations fall outside this score's scope.
The scores are uncalibrated for PAW and intended for analyst review. The
existing case's reports and attribution decision remain unchanged.
