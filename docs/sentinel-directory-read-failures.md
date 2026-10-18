# Local file-monitor directory read failures

`FileMonitor.get_case_files` propagates errors delivered to the existing
`os.walk` error callback. A failed `scandir` open or directory iteration cannot
become an empty or successfully listed prefix inventory. The production repair
only supplies a rethrowing callback; traversal, sorting, exclusions, hash
comparison, owner admission and case verification algorithms are unchanged.

Actual two-file trees reproduced false deletion and baseline loss after an
explicitly injected directory PermissionError. Root failure returned zero files
and declared both sources deleted. A nested-directory failure returned only the
root file and declared the retained nested file deleted. Integrity reports
published counts zero/one instead of two. Recovery declared unchanged files new.
These are filesystem/output observations with fault injection, not OS ACL proofs
or actual directory races. No source bytes were deleted or changed in that probe.

The exception now reaches listing, per-case change checks, all-case monitoring
and integrity-report callers. A failed report does not publish partial counts;
CLI commands fail explicitly. PR71's existing all-case baseline rollback and
deferred check records handle the propagated error without additional changes.
Recovery uses the prior successful baseline. Existing missing/empty-case and
excluded-name behavior is retained. There is no new schema, collector, database
or replacement inventory engine.

This closes only the errors exposed through the `os.walk` callback. It does not
establish complete inventory admission: metadata errors that traversal helpers
may suppress, stat/existence checks, links/special files, resource budgets,
concurrent writers and integrity-only verification error interpretation remain
open. Returned file counts retain their existing exclusions. These scans are
not atomic filesystem snapshots or persisted historical detection.

Six unit contracts use actual root/nested files and directories with denied-open
and interrupted-iteration faults. The iterator returns a real directory entry
before raising. Tests check listing/report failure, initial/established case
baselines, selected-case rollback/deferred records, recovery, actual neighboring
modification and unchanged empty/missing/exclusion behavior.

The existing `integration_sentinel_hash_failures_real.py` retains its file-read
fault checks and adds root/nested directory faults on an actual stopped full
original-EML case. Seven cold API and twelve CLI dispatch processes check both
`monitor files` and failed `monitor integrity` admission, no partial check records,
preserved sources/seals and recovery. API imports are guarded; the existing CLI
bootstrap precedes its guard because of a local capability probe. Actual CLI
ZIP export preserves every original case file. A sealed neighbor is a declared
storage fixture, not another original-EML analysis. Faults are explicit injections,
not OS containment, live races, authenticity or classifier-accuracy evidence.

On Windows/Python 3.13 the serial suite passes 726 tests (718 passed, eight
platform exclusions), including the six directory and five file-read contracts.
The existing 18 local-file CLI scenarios also pass. An actual offline-built
wheel matches all 90 current package Python sources, console entry points,
Python metadata and both review templates. These are bounded validation results,
not a clean dependency installation or final platform acceptance matrix.
