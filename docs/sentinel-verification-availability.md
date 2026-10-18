# Local monitor verification availability

`FileMonitor.verify_merkle_integrity` now returns `(None, diagnostic)` when the
existing case verifier raises an exception. Existing callers map this to
`unknown`, without incrementing `compromised`. The diagnostic text is retained.
Only the exception result changes; case-verification algorithms and return
values, owner admission, file hashing, inventories, schemas and collectors do not.

Actual valid sealed files with explicitly injected denied-open, disappeared-open
and interrupted-read errors previously returned `False` and counted as
compromised. Restoring reads verified those same unchanged files successfully.
Malformed index JSON/UTF-8/scalar fixtures also raised rather than completing a
verification. These observations do not establish an evidence mismatch or prove
the source is healthy. Unknown means verification unavailable, not passed.

Successful `True` results remain `ok`. Returned `False` results remain
`compromised`, the existing compatibility label for a negative verification,
not attribution, intrusion, authenticity or a cryptographic-assurance conclusion.
Missing seals remain unknown. This change does not reinterpret every reason for
`False` inside the shared verifier; broader S08 verification semantics remain
open. Ownership errors still propagate before the exception handler, so a live
or unconfirmed writer cannot become an admitted unknown case.

An integrity CLI report can return command success while explicitly listing an
unknown verification and its error: the report was constructed, the check did
not pass. File-change scans still fail if hashing cannot read the source, with
prior baseline preservation. When an index is readable but malformed, the literal
file modification remains visible alongside unknown verification; the adverse
byte observation is not discarded or called a verified pass.

Six unit contracts use actual seals, mismatches, missing seals, malformed
JSON/UTF-8/scalars, explicit read faults, report counts, recovery, byte-change
observations and owner-state fixtures. The owner fixture is not a live-process
claim. `integration_sentinel_verification_errors_real.py` runs an actual full
original-EML no-egress worker and confirms stopped supervision before reads.
Three cold API and seven guarded CLI dispatch processes check unknown/error
diagnostics, unchanged mismatch counts, restored valid outcomes, continued hash
scan failure and exact source/seal preservation. Two neighboring valid/changed
cases are declared storage fixtures. Actual ZIP export preserves every original
case file. API imports are guarded; existing CLI bootstrap precedes its guard.
Faults are explicit injection, not OS ACL/live-race proofs, OS containment,
authenticity or classifier-accuracy evidence.

Local validation on Python 3.13 passed 732 tests: 724 passed and eight platform
skips (81.555 seconds). The prior real file/directory-read integration also passed
on this version: one additional full original-EML analysis, seven cold API and
twelve guarded CLI processes, with recovery and exact ZIP bytes. All eighteen
existing local-file CLI scenarios passed. An actual offline wheel matched all
90 package Python sources, metadata, console entrypoint and EN/IT review
templates. These are bounded checks, not final cross-platform acceptance.
