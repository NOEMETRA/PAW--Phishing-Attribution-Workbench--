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

Codex review is requested in GitHub PR comments. Treat the review as an additional
check and resolve actionable findings with reproductions and focused tests; do
not interpret an empty review as full software validation.

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
