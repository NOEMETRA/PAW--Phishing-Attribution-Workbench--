# Sentinel campaign command admission

`paw monitor add` requires nonblank `--case` and `--url`; `remove` requires a
nonblank `--case`. These checks precede Sentinel imports and configuration/storage
access. Values are retained literally; this is not URL validation or authorization
to visit the stored URL.

The [campaign column correspondence repair](sentinel-campaign-columns.md) binds
lookup/list fields to explicitly selected columns, so a changed physical schema
order cannot substitute another stored value during removal preflight.

Removal first opens existing saved storage through passive admission and selects
active campaigns with the exact case ID. Missing storage, unsupported WAL/journal
state, source errors, no match or multiple matches fail with a nonzero exit before
writer initialization. Removed campaigns are not active matches. An ambiguous
legacy table cannot silently select the first row.

Accepted add/remove commands use the existing default database writer, including
its initialization/migration behavior. Removal updates only the selected ID with
the same case and active status; a zero-row update fails instead of claiming
success after the selected campaign disappears or changes status. The later
[local storage family](sentinel-local-storage-family.md) shares the transactional
transition with the direct API, rechecks ambiguity inside the write transaction
and confirms final status before acknowledgment. Adds validate nonblank strings
and finite object metadata and enforce case uniqueness even on legacy tables
without the constraint; initial active status is explicit without a schema default. No network
monitor is constructed, collector invoked or service started by these commands.
`check` remains the separate active path deferred to S14.

Validation: `tests/integration_sentinel_campaign_real.py` executes 40 actual cold
CLI processes. Invalid arguments preserve missing, malformed, corrupt and legacy
sources. Failed removals preserve saved/absent/removed/legacy/ambiguous/corrupt/
WAL/journal sources byte for byte. Real SQLite add, duplicate rejection, removal
and repeated removal verify exact stored row effects. Two explicit fault
injections change actual SQLite rows between selection and writer admission and
verify no false removal success. These are regression fixtures, not evidence of
live concurrent-writer containment.

The Python network guard covers dispatch after ordinary CLI bootstrap; it is not
an OS sandbox or cold-import network attestation. Writer admission still uses the
default schema initializer, and selection plus writer opening is not an atomic
source snapshot. The local storage family also exercises API effects and concurrent SQLite
connections. General writer initialization/resource/link admission, cross-process
source snapshots, other intelligence writers and active monitoring remain open.
Existing removed-case reenrollment is rejected; stored case IDs remain literal. Stored URLs and successful mutations establish no phishing attribution or
accuracy claim.
