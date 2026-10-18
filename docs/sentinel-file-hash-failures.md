# Local file-monitor hash failures

`FileMonitor.calculate_file_hash` returns a complete SHA-256 digest or propagates
the open/read exception. A denied, disappeared or interrupted source is not a
missing digest that can be counted as deletion. An empty readable file remains
a valid digest. The former helper returned `None`, causing `check_file_changes`
to report an existing unreadable file as deleted, remove its baseline and then
report the unchanged file as new when reading recovered. Actual source files and
explicit read-denial injection reproduce this sequence without deleting bytes.

A failed `check_file_changes` does not advance that case's in-memory baseline.
`monitor_all_cases` also restores the baseline present before that invocation
when any selected case raises an ordinary exception. Case check records are
emitted only after every selected case scan succeeds, so a late hash error does
not publish partial check records or silently commit an earlier neighbor's
baseline. Recovery compares against the prior successful state. Real readable
modifications and actual deletions retain their existing comparison behavior.

These are error/baseline contracts for one synchronous monitor instance, not a
filesystem transaction, concurrency lock or persisted historical monitor. Owner
admission remains unchanged. First scan still establishes an instance baseline.
Inventory exclusions, links/special files, broader metadata failures, resource admission,
concurrent writers and integrity-only verification error interpretation remain
open. `verify_merkle_integrity`/`generate_integrity_report` and their compatibility
statuses are unchanged; a hash-scan exception does not certify those separate
verification outcomes. No database, collector, hash algorithm or output schema
is added. Passive file checks still avoid campaign configuration and storage.
The later [directory-read repair](sentinel-directory-read-failures.md) propagates
errors delivered by the walk callback, without changing seal verification.

Five unit contracts exercise real files/digests with explicitly injected denied,
disappeared and mid-read failures, first/established per-case/all-case baselines,
deferred records, empty files, recovery, modifications and real deletion. A
mid-read injection first returns actual source bytes and then raises; it is not
a fabricated hash. These injections are not OS ACL or live deletion-race proofs.
The all-case rollback is tested independently of direct hash-error propagation.

`integration_sentinel_hash_failures_real.py` creates a full original-EML case
under no-egress with stopped supervision and a valid seal, plus a sealed local
neighbor fixture. Its hash-specific three cold API and four CLI dispatch processes check actual
files, failure/recovery, preserved baselines and nonzero CLI failures without
partial case check records. Existing CLI bootstrap precedes its guard because
of its local socket capability probe; API module imports are guarded. All source
bytes and seals remain unchanged, and actual CLI ZIP export preserves every
original case file. No campaign/configuration/collector imports, new threads or
blocked network attempts occur during guarded dispatch. This establishes neither
OS containment, authenticity, historical tampering nor classifier accuracy.

On Windows/Python 3.13, PR71's full serial unit suite passes 720 tests (712 passed,
eight platform exclusions). The existing 18 local-file CLI scenarios also pass.
An actual offline-built wheel matches all 90 current package Python sources,
console entry points, Python metadata and both review templates. This is a
wheel/source comparison, not a clean dependency installation or final supported
platform acceptance matrix.
