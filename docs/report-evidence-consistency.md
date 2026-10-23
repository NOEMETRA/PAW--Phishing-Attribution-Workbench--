# Extraction-to-report literal evidence

Baseline: merged PR86, `e82e6842fbfa7082f1d334bfb4c5d37dda3e70d3`,
23 October 2026. Its exact-head Codex review has no findings; all three CI checks
pass on the reviewed head and the merge. This block addresses one shared S08
consumer boundary, not all remaining S03-S09 extraction capabilities.

## Reproduced defect and supported contract

An actual full no-egress analysis of an inert constructed EML preserves its
Received, Authentication-Results and body observations in JSON, but the technical
Markdown previously interpolated those observations as Markdown source. Passive
CommonMark parsing produced eight image/HTML nodes from source values, including
an image URL inside an unverified authentication comment. These are occurrences
of one boundary defect, not eight independently established extraction bugs.
No browser was opened and no resource was requested. The reproduction does not
establish a network-policy escape during analysis.

`paw/core/reporting.py` now supplies the common literal representation:

- Scalar observations use code spans containing JSON values. Quotes retain
  string/type boundaries; controls and Unicode use reversible JSON escapes.
  Backtick delimiters exceed source runs. GFM table cells also escape pipes.
- Structured observations use fenced JSON. JSON escapes source newlines, so
  source strings cannot introduce a closing fence on a line of their own.
- The technical report preserves its existing hop fields as literal values and
  names `received_path.json`. Its authentication, Received-anomaly and
  deobfuscation sections decode back to `auth.json`, `received_anomalies.json`
  and `headers.json.deobfuscation_analysis`, respectively.
- The executive candidate/domain/provider fields and attachment filename/MIME
  cells use the same scalar representation. NS/MX are represented as JSON lists.
  Missing values remain null or the existing empty-string observation; missing
  checks do not establish safety, forgery or authenticated attribution.

Original EML, extracted JSON, payloads, evidence paths, algorithms and score
contributions are unchanged. Existing sealed cases are not rewritten. This
changes the Markdown view consumed by readers, not the message evidence.

## Verification and remaining gates

On frozen runtime/test/workflow sources, the Windows Python 3.13 suite runs
890 tests: 876 pass and 14 platform exclusions remain. Three new unit contracts
use a passive CommonMark/GFM parser to recover typed values across markup,
backticks, table delimiters/backslashes, multiline/control and Unicode inputs.

The extended `tests/integration_attachment_report_real.py` runs three actual
full CLI cases (two constructed messages and the repository original EML) and
one actual loopback HTTP worker. It checks no source-created image/link/HTML
nodes, structured JSON equality, candidate/domain field equality, coverage/score
agreement, literal table rows/digests, unchanged original/payload bytes and
stopped owners. CLI ZIP, HTTP detail and HTTP ZIP retain both report files and
their source artifacts; case seals verify before and after export.

Six serial real integrations pass: that report flow, MIME body evidence (33 CLI
cases/14 HTTP workers), URL sources (9 CLI/5 HTTP), content assessment (8 CLI),
local DKIM evidence across all five presets and HTTP, and the actual wheel.
The wheel contains all 92 current package Python sources. Only the trace report
consumer and one new rendering module change production source; 90 existing
package sources retain their contents. All 236 frozen Python/workflow hashes
remain unchanged through validation; documentation follows stopped validators.

Reproduce the new boundary with normal engine/API dependencies installed:

```text
python -B -m unittest discover -s tests -p 'test_report_evidence.py' -v
python -B tests/integration_attachment_report_real.py
```

The parser checks do not validate every Markdown renderer, a browser, live
provider data, detonation/canary/Rekor publication or all legacy terminal paths.
Those paths retain their register dispositions. Final combined extraction
contexts, omissions/budgets and advertised capability reconciliation remain
open; independent accuracy/holdout, clean platform installation, controlled
egress and UI follow their separate gates. Constructed messages are regression
fixtures, not phishing ground truth. Exact-head review/CI of this block remains
required before integration.
