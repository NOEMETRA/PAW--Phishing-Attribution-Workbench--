# Offline engine validation and review scope

This change replaces simulated results with measured results or explicit
unavailability, supervises the CLI/API workers, and preserves original MIME and
sealed evidence. It includes an already implemented local workbench whose further
development is paused while engine validation continues. It is not a production
release or a completed validation of every repository script.

## Completed local checks

- 84 unittest contracts covering execution, authentication, MIME, supervision,
  queue cancellation, batch errors, numeric inputs, exports and evidence monitoring.
- 24 real CLI scenarios produced 95 cases, all checked with the evidence verifier.
  Scenarios include the repository's original public EML, explicitly constructed
  regression/load fixtures, mixed-extension batches, invalid inputs, 1,000 URLs,
  300 attachments and a 12 MiB attachment.
- Real API/worker/export and interrupted-job recovery checks; wheel contents
  compared with the final source and imported from an isolated install directory.
  This install reused host dependencies and is not a clean dependency install.

Observed on the Windows development host, with an external process observer:

| Offline workload | CLI elapsed | Peak sampled process-tree RSS |
| --- | ---: | ---: |
| 5 messages | 8.233 s | 99.3 MiB |
| 20 messages | 15.147 s | 118.4 MiB |
| 50 messages | 33.753 s | 121.2 MiB |
| 1,000 URLs in one message | 5.227 s | 105.0 MiB |
| 1.8 MiB text | 17.989 s | 283.3 MiB |
| 12 MiB attachment | 6.861 s | 262.2 MiB |

Times exclude subsequent evidence verification. RSS is sampled every 50 ms,
sums process RSS including shared pages, and can miss short-lived processes.
These measurements do not reproduce the previously reported four-hour online
analysis or establish classifier accuracy.

The measured CLI workloads used no-egress. One earlier local review invocation
accidentally omitted the flag on an innocuous constructed message with an
example.org sender; it was excluded from offline evidence and repeated with the
flag. No suspicious URL was visited. Raw local run reports and email content are
not included in this PR.

## Reproduction

Install the project dependencies, then run:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_*contracts.py' -v
python tests/integration_engine_stress_real.py
```

The stress script requires `psutil` for its external observer and writes to a new
run directory on each invocation. Inspect its result JSON for scenario expectations
and integrity outcomes. The GitHub workflow runs the contract suites on Linux;
Windows-specific resource/locking checks require the Windows host.

## Remaining work

- Validate original labeled legitimate/phishing EMLs and audit false positives,
  header handling, URL extraction/deobfuscation and score interpretation.
- Reproduce the historical long-running analysis with its original configuration.
- Validate POSIX supervision, clean installation and legacy standalone scripts.
- Build the separate Linux isolation/enrichment/detonation lab later. Current
  no-egress is a Python guard, not a native-code or OS sandbox.
- STIX and campaign correlation remain unavailable until validated. ARF/X-ARF
  compatibility outputs are local review drafts without asserted standards
  compliance. Offline CLI DKIM key ingestion and genuine SimHash are still open.

URL identity and derived-candidate handling have a subsequent focused audit and
regression set documented in [URL evidence](url-evidence.md). A private original
EML pilot exposes real URL rewriting defects; it does not yet establish classifier
accuracy or reproduce the historical online runtime.

The auxiliary content scorer has a subsequent audit and versioned observation
contract documented in [Content assessment](content-assessment.md). It removes
unvalidated action/risk recommendations caused by neutral text length; the final
attribution thresholds and the remaining accuracy-validation work are unchanged.

The original-MIME pilot now also has provisional content triage and a reconciled
final-score audit. [Score explanations](score-explanations.md) documents additive
contributions and the correction for verdict changes caused by intermediate
rounding/clipping. This exposes the existing heuristics; it does not calibrate
them or supply independently adjudicated phishing labels.

The next audited defect was text rewriting: all 20 original messages saturated
the text-transformation score, including the ten owner-recognized legitimate
messages. [Text preservation](text-deobfuscation.md) separates original text from
descriptive visual comparisons and removes that unsupported contribution. URL
recovery remains separate; HTML/JavaScript heuristics still need validation.

The subsequent [HTML audit](html-evidence.md) identifies the residual contribution
as routine entity decoding in 13 cases. Original markup is now preserved and
decoded attribute candidates remain separate, with explicit descriptive/partial
coverage. [Standalone JavaScript](javascript-evidence.md) now preserves source,
reports bounded unexecuted candidates and leaves risk/execution unassessed.
The [header identity audit](header-identity.md) corrects display-name parsing and
exposes selected field defects without risk penalties. Remaining domain/Received
signals still need validation; these fixture contracts do not measure accuracy.
The [Reply-To comparison audit](reply-domain-comparison.md) corrects first-mailbox
selection, raw-domain comparisons and points from unavailable operands, retaining
explicit persisted uncertainty. Remaining domain and Received heuristics are
separate unresolved checks.
The [Received audit](received-evidence.md) scopes selected IPs to supported From
clauses, preserves other candidates and removes unsupported private-address and
FQDN-only contributions. Recipient boundaries remain explicitly unevaluated;
timestamp/relay heuristics and other domain signals still need validation.
The subsequent [timing audit](received-timing.md) leaves missing adjacent
comparisons null, retains timestamp/address observations and removes unsupported
timestamp risk and relay/manipulation interpretations. Clocks and delivery remain
unverified; independent accuracy and remaining domain/legacy work are still open.

Codex review is requested in GitHub PR comments. Treat the review as an additional
check and resolve actionable findings with reproductions and focused tests; do
not interpret an empty review as full software validation.

The [Unicode domain audit](domain-unicode.md) removes the representation-dependent
0.20 penalty that treated every non-ASCII domain as mixed-script. Supported IDNA
spellings are descriptive observations, with script/homograph analysis explicitly
unevaluated. Other domain/brand/TLD heuristics and thresholds remain unchanged;
those heuristics still require validation.

The [display-brand comparison fix](display-brand-comparison.md) removes a name
mismatch penalty caused solely by a service subdomain beneath a matching public
registrable label. Hosted tenant exceptions, unambiguous From gating and numeric
provenance are explicit. Domain ownership is unverified; other domain-label/TLD
heuristics and attribution accuracy remain separate validation work.

The [domain-label comparison fix](domain-brand-labels.md) retains a brand-spelling
signal when a recognized registrable label is preceded by a service subdomain.
It bounds comparisons to normalized leftmost/PSL registrable labels, preserves
uncertain From identity and limits this rule to one 0.20 contribution. Spelling,
suffix structure and owner identity remain unverified; accuracy and TLD audits
are still open.

The [TLD observation fix](tld-observations.md) normalizes final-label comparisons,
requires usable From identity or an explicit legacy domain hint, and exposes
unevaluated cases without TLD points. Static-list membership is not a reputation
verdict. List/weight calibration and domain-age/RDAP correctness remain separate;
future registration dates are addressed separately by the
[nullable registration-age calculation](domain-age.md). Its real local contracts
reject future/naive/invalid timestamps without recent-domain points. Offline CLI
cases expose unavailable age/null indexed age; no registry date is simulated.
RDAP provenance/binding and numeric legacy hints still require separate validation.

## GitHub review follow-up: process launch and crash recovery

The first GitHub review found two P1 issues: audited `spawn`/`fork`/`exec` paths
could bypass the no-egress filter, and a crashed POSIX API could leave a worker
writing a case subsequently exposed as interrupted. The filter now also covers
these events and Windows shell/direct CreateProcess launch events.

The supervisor persists PID, process creation time, boot identity and the POSIX
group/session before releasing its worker gate. API startup and case readers
recover lost jobs, verify ownership, terminate the recorded POSIX group and
confirm there are no live writers before sealing/publishing an interrupted case.
The normal POSIX shutdown path also waits for the group to stop. Zombies are
already exited and cannot write files. Windows retains Job Object kill-on-close.
`psutil` is now a runtime dependency for identity and shutdown checks.

Missing identity, permission errors, a mismatching PID creation time, or live
descendants whose group leader has disappeared leave `recovery_blocked`: the API
does not seal, read case details, verify or export those files. Legacy lost jobs
without process metadata require manual investigation; recovery does not guess
which process to terminate. This change does not provide native-code/OS network
isolation or protection against deliberately escaped process sessions.

`tests/test_recovery_contracts.py` exercises real audited launch attempts and
fail-closed evidence access on every supported host. Linux CI additionally kills
a real supervisor, observes its worker and child's file writes continue, then
tests startup recovery, stable evidence, sealing and export; a mismatching process
identity test confirms an unrelated live group is left alone. These controlled
writer fixtures are process-recovery tests, not simulated analysis results.

## GitHub review follow-up: shared CLI/API ownership

The next review found that CLI cases used `.paw-jobs` without an `analysis_job`
manifest field, so the API's ownership guard could miss a live CLI writer. CLI
analyses now use the same `jobs/analysis_*` registry as API analyses, publish their
supervisor identity and final acknowledgment, and set `PAW_ANALYSIS_ID` before
starting the worker. The initial manifest write includes that owner.

The API recognizes an identified live CLI supervisor and leaves it running while
blocking case detail, verification and export. It recovers only after the owner
has exited. Shared discovery also recognizes legacy `.paw-jobs` progress records;
unknown legacy supervisors remain blocked until investigation or confirmed stop.
CLI `verify` and `export` apply the ownership guard as well. Internal worker
verification and post-shutdown sealing retain their existing execution context.

On Windows, psutil's boot timestamp estimate varies slightly between interpreters;
boot comparisons allow two seconds of estimation difference. PID creation time
is always compared exactly, and unknown or mismatching identity fails closed.

`tests/integration_cli_api_real.py` runs original public EML bytes through a real
CLI and a loopback HTTP API sharing one directory. It pauses the test's worker
while the CLI supervisor stays alive, starts the API, confirms blocked HTTP/CLI
readers and unchanged worker ownership, then resumes analysis and verifies exact
original bytes and the completed ZIP. A second real CLI supervisor is killed;
HTTP recovery must confirm worker shutdown before partial verification/export.
The same integration runs locally on Windows and in the Linux GitHub workflow.

## GitHub review follow-up: collections and completion acknowledgment

Collection endpoints now apply the same unstable-state rules as detail, verify
and export: queued/running/recovery-blocked cases expose only ID and status in the
case list, and their SQLite matches are omitted from query results. SQLite reader
connections are explicitly closed, including on Windows.

After observing that an external CLI owner has exited, API recovery reloads its
persisted state and shutdown proof before deciding whether recovery is necessary.
A successful acknowledgment published between the first read and the owner check
therefore remains completed. An unknown CLI owner is blocked without overwriting
its state. Synthesized legacy states are discovery caches: every registry read
refreshes them from the old control's supervisor/result files, and successful
completion removes stale recovery errors.

Regression tests cover all unstable collection states, discovery before legacy
completion, unknown-owner preservation, and a deterministic completion race with
a real subprocess publishing state then exiting. A read hook synchronizes that
race; it does not replace process identity or recovery outcomes. These metadata
fixtures are contract tests, not analysis outputs or an accuracy corpus. The real
original-EML CLI/HTTP integration additionally pauses a batch after its first case
has entered the actual index, checks list redaction and empty query results, then
resumes and checks completed collection/query results and verified original bytes.
