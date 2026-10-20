# Sentinel local storage family

This block audits campaign management and local file observation together. It
does not enable remote checks, service control, new intelligence or UI behavior.

## Campaign effects and API/CLI correspondence

`CampaignDatabase.add_campaign` requires nonblank string case/URL values and
object-or-None JSON metadata with finite numbers. Validation/encoding precedes
the SQL transaction. Values remain literal; this is not URL visitation or
authentication. `BEGIN IMMEDIATE` serializes the existing-case check and insert,
including legacy tables without `UNIQUE(case_id)`. Removed cases remain enrolled;
adding them again fails, preserving the existing policy. Initial status is now
explicitly `active`, including legacy tables without the column default.

`CampaignDatabase.remove_campaign` selects and updates under the same write
transaction. Exactly one active row must correspond to the supplied ID and,
when supplied, exact case ID. Missing/already inactive/mismatched selections
return False, ambiguous selections fail and roll back. The affected-row count
and final removed status must agree; aborted or undone updates cannot be
acknowledged. Metadata, checks and neighboring canonical rows are unchanged.
This is not a general certification of arbitrary SQLite triggers or schema.

`SentinelMonitor.remove_campaign` delegates to that transition instead of
acknowledging an old selection after a zero-row update. The CLI retains passive
removal preflight before writer initialization, then uses the same case-bound
transition. Preflight plus default writer initialization is still not a single
atomic source snapshot; initializer/migration and database-path/link admission
remain separate limits. Busy/locked storage fails rather than claiming success.
The low-level generic status setter remains unchanged and has no removal-success
protocol. Active collection and monitor start/stop remain S14 work.

## File admission, limits and baseline ownership

Each case ID must name one direct child of the configured cases directory.
Absolute, drive-relative, parent and multi-component case paths are rejected
before ownership-source access. Relative configured roots are anchored at construction, so a later working
directory change cannot substitute another collection. The configured root,
selected cases and traversed
directories reject symbolic links and Windows reparse points. Selected files
must be regular non-link files. Existing hidden-name and pyc exclusions still
apply; hard links remain regular files counted per path. This is a scoped observation inventory, not the complete forensic seal
inventory. CLI and returned `inventory` metadata state the scope and non-atomic
nature of observations. Configured root ancestors are not an OS containment
boundary; hostile filesystem replacement is not generally contained.

Defaults, overridable by positive integer constructor keyword arguments:

| Limit | Default | Scope |
| --- | --- | --- |
| `max_cases` | 1,000 | Selected case directories |
| `max_files` | 10,000 | Selected files per case and whole selection |
| `max_bytes` | 1 GiB | Selected file sizes per case and whole selection |
| `max_file_bytes` | 256 MiB | Selected file size and bytes consumed by a hash |

Exceeding a limit fails; no complete report or baseline update is returned.
Whole-selection admission precedes any all-case baseline changes/check records.
These are source-count/byte limits, not a hard elapsed-time/memory bound or a
complete directory-entry/ownership-source/shared-verifier resource policy.
Large allowed sources and arbitrarily many empty/unselected directory entries
still require later whole-engine resource assessment.

Hashing compares path and descriptor file identity, type, size and mtime before
reading; POSIX also compares ctime. Windows ctime differs between path/descriptor
APIs after a write and is not used for that comparison. Descriptor/path metadata
and consumed size are checked after reading; changed files fail. The opener uses
no-follow/nonblocking flags where available. File-list/metadata correspondence
is rechecked before committing a case baseline. These checks detect the tested
mutations; they are not an atomic filesystem snapshot or protection against all
transient/metadata-preserving changes. Other processes can write outside these
observation windows. Existing stopped-owner admission remains required.

A reentrant instance lock serializes baseline-changing scans, including nested
all-case scans. On a later failure the prior invocation baseline is restored
without overwriting a concurrent scan of that same instance. Separate instances
do not share a baseline or filesystem lock. First scan is not historical change
detection; seals do not establish message authenticity or attribution.

## Verification

Eighteen new unit contracts exercise actual SQLite rows/files, two concurrent
SQLite connections, ambiguous legacy schemas, abort/undo triggers, invalid API
inputs, source paths, in-read and in-inventory mutation, budget failures and
same-instance serialization. Baseline modules fail 28 assertions and 29 errors
including subtests; two platform exclusions apply on the recorded Windows host
(unprivileged directory symlink and POSIX FIFO). Linked-directory/FIFO tests run
where supported; Windows reparse behavior is not an OS isolation attestation.
The final general suite passes 790 tests (780 passed, ten platform skips) in
93.884 seconds. An actual offline wheel matches all 90 current package sources,
metadata, entrypoint and both review templates. Four package sources change;
the remaining 86 are unchanged.

`integration_sentinel_storage_family_real.py` uses a full original-EML no-egress
worker with confirmed tree shutdown, then cold API/CLI operations, actual case
verification and ZIP byte checks. Its campaign rows and mutation/limit scenarios
are declared fixtures, not live target monitoring or independently labeled mail.
The prior campaign-layout/admission and file read-failure integrations are also
regressions for this family. The new integration passes five cold API and six
guarded CLI processes. Final-source read-failure integration passes seven API
and twelve CLI probes, with original EML/seal/ZIP preservation. Combined CLI/API
flow rejects a real live worker, reads eight completed original-EML cases and
checks cancellation/supervisor-crash recovery before verify/export. No source URL/domain is visited or resolved.

This closes the named storage-effect/selected-file contracts only. Remaining
S11 work includes initializer/path/link policy, broader stored JSON and publisher
resources, cross-process/concurrent-source snapshots and other intelligence
writers; S08 shared verification/authenticity and final S01-S08/S13 platform
acceptance remain open.
