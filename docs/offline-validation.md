# Offline engine validation and review scope

The current audit register, source/command inventory, closure criteria and
remaining work are in the [engine stabilization checkpoint](engine-stabilization-checkpoint.md).
The opening check counts and workload measurements below describe the initial
offline cycle; subsequent focused changes have their own linked records.

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

## Current remaining work

Follow the finite family register in the [stabilization checkpoint](engine-stabilization-checkpoint.md):
remaining local helper/entry-point audits, final integrated regressions and
installation/support checks, independent labeled evaluation, controlled-egress
isolation and active capabilities, then GUI parity and release acceptance.
The objective is stabilization and forensic depth; historical runtime reproduction
and speed optimization are outside the current completion criteria.
Unavailable STIX/campaign attribution and unvalidated abuse-format compliance
remain explicit; supplied DKIM key provenance and classification calibration
are separate from successful offline execution and evidence integrity.

## Analysis worker import boundary

Supervised CLI presets and HTTP analysis launch `paw.web.worker` with Python's
safe import path (`-P`, Python >=3.11) and the existing absolute installation root
in a replacement `PYTHONPATH`. Evidence in the working/data directory cannot
shadow the worker's PAW package or dependency imports. The working directory,
relative output paths, supervisor, start gate, worker policy and decoder are
unchanged. This requires a trusted parent and installed environment; it is not
an OS sandbox or a guarantee about arbitrary independent Python entry points.

`tests/integration_worker_imports_real.py` exercises all five actual CLI presets,
a dependency shadow and two actual loopback HTTP worker/export flows, using the
repository's original public EML. Benign `paw`/`psutil` fixtures only write a
local marker and fail if unexpectedly imported; no analysis output is substituted.
Before correction, all eight runs imported the fixture instead of reaching the
real worker. After correction, they preserve original MIME, validate evidence
seals and offline execution, export actual API ZIPs and confirm process shutdown.
The test isolates parent bootstrap deliberately; Uvicorn's app directory is set
to the trusted source root so its own path insertion cannot load the fixture.

The full analysis with controlled egress remains a project objective. The user
has identified a Windows solution to assess after engine stabilization; the
separate Linux host is also available. Active enrichment/detonation and historical
online latency measurements follow isolation verification and are deferred here.

The hardcoded legacy email script now delegates to supervised offline `full`
analysis, with real import/CLI/batch/timeout checks documented in
[Legacy inbox launcher](legacy-inbox-launcher.md). This closes that one bypass;
the remaining standalone operational commands are still open.

The [selected-header SimHash audit](header-simhash.md) replaces the mislabeled MD5
prefix for new index rows and marks historical digests explicitly in CLI/API
queries. Original cases are not rewritten; this does not enable deduplication,
change scoring or validate campaign correlation.

A subsequent [clean Windows installation](clean-installation.md) installed all
runtime dependencies in an isolated Python 3.13 environment, exercised the
installed offline CLI/API and corrected the Python requirement in actual wheel
metadata. Other platforms, optional components and legacy scripts remain open.

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

The CLI `query` reader now also omits indexed cases whose shared CLI/API owner
has not confirmed worker shutdown, including missing/unknown acknowledgment and
legacy progress ownership. Explicit unowned queued/running/recovery-blocked
execution records are also omitted. It does not recover, kill or update jobs.
An index row with no recorded owner remains a historical observation; returning
it does not establish completed execution, integrity or authentication.

Queries open an existing SQLite database in read-only mode and close their
connection. They do not initialize/migrate the schema, acquire a write transaction,
or create empty storage when the index is absent. Legacy SimHash observations
are annotated in memory. Writer initialization and case indexing are unchanged.
Real SQLite contract tests cover a held writer transaction, unstable/current and
legacy ownership, missing controls, legacy schema/bytes and closed reader handles.
The actual CLI/HTTP integration reproduces the previous CLI exposure during an
active original-EML batch, then checks both readers hide the rows until shutdown
and return them after completion, with unchanged database bytes during queries.
The SimHash integration also checks actual CLI reads leave the old schema intact.

## Case identity and exclusive ingestion

A CI batch reported success with 21 case directories for 22 selected messages.
The ingestion path used second-resolution time and only four UUID characters,
then reused an existing directory. A controlled same-second/shared-prefix run
reproduced silent overwrite: both inputs were marked completed with the same ID,
and both success records referenced the second message. The failed CI log does
not retain the case IDs, so the exact historical collision cannot be confirmed;
the reproduced loss mechanism matches the missing-case symptom.

New cases use the full UUID hex suffix. Directory creation is exclusive before
writing input or manifest and before publishing the case as an ingest destination.
An exact ID collision raises `FileExistsError`; batch accounting reports that input
as failed while retaining the first completed case and its seal. Existing cases
are never reused as destinations. Historical IDs remain readable; no migration or
scoring/network-policy change is made.

`tests/integration_case_identity_real.py` runs actual supervised offline workers
with controlled timestamp/UUID generation. Distinct UUIDs sharing the old four
characters preserve both originals in separate sealed/indexed cases. An exact
UUID collision produces a partial batch, one intact first case and one explicit
failed input. Only identity generation is controlled; analysis, network guard,
indexing, process supervision and evidence output are real. These inputs test
ingestion integrity, not classification accuracy.

## Legacy canary evidence boundary

Canary deployment is explicitly unavailable until the isolated lab has separate
observation storage. The legacy token handler could append an unindexed file to
a completed case and invalidate its seal. The CLI, module, function and standalone
launcher now reject deployment before accessing evidence, starting a listener or
sending automatic mail. The launcher no longer changes directory at import time
or uses a default example case. See [canary status](canary-status.md) for the
measured reproduction and rejection tests. Existing observations remain readable;
the offline analysis engine and deferred detonation/Sentinel paths are unchanged.

## MIME body evidence

New cases preserve individual [MIME body evidence](mime-body-evidence.md) with
transfer-decoded payload bytes and separate charset-derived text. This makes
alternatives and replacement-decoding provenance inspectable per part without
changing the existing aggregate analysis or attachment/scoring contracts.

## Top-level header inventory

New cases also expose a separate [top-level header inventory](header-inventory.md)
with ordered duplicate occurrences, raw parser-value octets, derived text and
explicit limits. It preserves the existing selected-header, scoring and
authentication contracts; arbitrary header claims remain unverified.

New cases additionally expose the [MIME tree header inventory](mime-header-inventory.md)
for part/container and encapsulated parser-node headers. Ordered fields retain
separate inner-message scope, raw/derived provenance and global capture budgets.
The original top-level inventory and selected analysis contracts remain available.

The [MIME CID observation inventory](mime-cid-evidence.md) links supported outer
HTML attribute observations to captured Content-ID field candidates in the same
message scope. Duplicate/missing/limited sources and complex marker attributes
remain explicit; renderer resource selection and attached HTML are outside this
scope. Existing network URL targets, numeric scores and sender analysis are unchanged.

The [attachment ZIP inventory audit](attachment-archive-inventory.md) preserves
bounded member records and parser names, makes omissions explicit and propagates
ZIP limits/reader errors to attachment coverage while retaining other attachments.
It inventories declarations; archive members, macros and malware remain separate
unverified content-analysis scopes.

## Local DKIM public key evidence

Analysis presets accept `--dkim-keys` and HTTP analysis accepts `options.dkim_keys`.
The supplied, bounded JSON is snapshotted into each new case before sealing; no
DNS is queried. Actual signature pass/fail is kept separate from unverified key
provenance and cannot automatically add authentication-risk points. Without key
evidence the previous unavailable-check behavior remains. See
[local DKIM keys](local-dkim-keys.md) for the input contract, provenance boundary
and real RSA CLI/HTTP regression. No authentic key set for the private corpus has
been established by these constructed cryptographic tests.

The [standalone deobfuscation input audit](standalone-deobfuscation-input.md)
rejects conflicting sources and invalid UTF-8 instead of silently altering
reported original text. It preserves BOM/newlines, bounds file/string input and
applies the offline application guard during reading and decoder dispatch. This
does not add MIME parsing or risk calibration. The CLI now reuses the shared
process supervisor for a gated, always-offline standalone worker, with configurable
execution deadline and memory limits. Results require confirmed tree shutdown;
timeout/failure produces no successful partial result. Temporary transport files
are cleaned only after shutdown proof; they are not cases or sealed evidence.
Worker startup/read/analysis/result writing are bounded, while parent admission
and result rendering remain outside worker limits. Actual CLI timeouts and gated
worker/helper audits verify this scope; direct Python helper calls remain synchronous.
Worker startup excludes the analysis working directory from Python imports (`-P`),
and literal admission validates UTF-8 encoding and byte length before bootstrap or
transport creation. Real worker/CLI tests cover package/dependency shadowing and
multibyte/surrogate rejection without replacing analysis results.

### Evaluating a separately labelled holdout

Use `tools/evaluate_mail_corpus.py` from the checkout with PAW installed.
Supply one directory of stopped, sealed cases per profile. Keep the originals,
label manifest and case directories in private storage. The manifest is a JSON
array with one object per original. Each object records its `sha256`, its
campaign or message-family `group`, its `split` (pilot, development or holdout),
its independent `label` (phishing, legitimate or unresolved) and `label_basis`.
Set aside holdout groups before adjusting the engine. Document the independent
basis for each resolved label. A mail-provider folder alone cannot adjudicate
phishing. The program checks group overlap and missing or duplicate originals.

```bash
python tools/evaluate_mail_corpus.py --labels /private/labels.json --split holdout \
  --default /private/default/cases --strict /private/strict/cases \
  --conservative /private/conservative/cases
```

For each profile the output counts all three saved decisions by independent
label. The referral rule sends either elevated decision to analyst review.
A legitimate message sent to review is a false referral. A phishing message
with an inconclusive decision is missed by this rule. The matrix preserves the
inconclusive decision in both cases. Unresolved labels contribute to the matrix
and are excluded from rate denominators. An empty denominator yields JSON
`null`. Pilot and development runs produce counts only.

#### Evaluating local text referrals

Install PAW with the `text-triage` extra and prepare the pinned local model
directory described in [Content assessment](content-assessment.md). Run the
evaluator in an OS network boundary when processing untrusted evidence for
native code. `--text-model` accepts one or more profile directories.

```bash
python -I tools/evaluate_mail_corpus.py --labels /private/labels.json \
  --default /private/default/cases --text-model /private/horizon
```

The evaluator reads the same stopped, sealed cases as `paw assess-text`.
It loads one tokenizer and model session per invocation, then links every
assessment to the seal and original used for the label lookup. It reports
aggregate referrals at fixed `fraud` thresholds of 0.5 and 0.9. Messages
without usable text appear as `not_evaluated` and remain in the denominator
for missed referrals. Holdout reports include recall, precision and the
abstention rate. Precision requires referrals with resolved labels and both
label classes in the cohort. Unresolved labels stay visible in the counts.
Keep aggregate results outside the case directory to preserve its seal.

#### Historical reference holdout, 21 November 2026

The wheel from local commit `d32f58b` was run with `--no-egress` inside a Linux
network namespace. The holdout was fixed before execution. It includes 16
messages labelled phishing by José Nazario and 16 messages labelled non-spam
by the Apache SpamAssassin Public Corpus. Selection took eight messages from
each of two phishing mailboxes and the `easy_ham` and `hard_ham` archives, with
one representative per exact message hash or normalized subject. The mbox
inputs preserve the archived RFC 822 data after removal of the mbox delimiter.
The ham inputs preserve the archived member bytes. [Nazario source and classification](https://monkey.org/~jose/phishing/README.txt) · [SpamAssassin corpus description](https://spamassassin.apache.org/old/publiccorpus/readme.html)

All 96 runs completed across the three profiles with byte-identical archived
inputs and valid seals. Each profile returned 32 inconclusive decisions.
Under the documented referral rule, each missed 16 of 16 phishing messages
and referred zero of 16 non-spam messages. The strict profile's maximum
phishing score was 0.25 against the 0.52 referral threshold. URL inventory
found links in 15 of 16 messages in each class. Sender-domain heuristics
contributed to two cases per class. Authentication checks were unavailable
during offline analysis. The threshold and scoring logic stayed fixed
throughout the measurement.

The two classes come from different historical collections and include source
redactions. The experiment measures referrals on this cohort. Contemporary
deployment performance and independent adjudication of the separately stored
Gmail pilot remain open. The report contains aggregate counts and archive
hashes. The messages and case data are stored separately.
