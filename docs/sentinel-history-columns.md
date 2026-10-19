# Stored check and alert column correspondence

`get_recent_checks` and `get_unacknowledged_alerts` now explicitly select their
existing ten/eight columns in decoder order. Previously `SELECT *` plus physical
offsets returned other source cells when a saved table had reordered columns or
a leading extension. Actual SQLite fixtures reproduced wrong check status,
message, metadata source and acknowledgment: rows selected by `acknowledged=0`
could be returned with `acknowledged=true`. Database bytes were unchanged.
These layouts are declared fixtures, not observed prevalence in the private
mailbox corpus.

Only the two SELECT projections change. Campaign filters, SQL time ordering and
limits, alert selection, Boolean conversion, JSON decoding/provenance, returned
keys, schema, migrations and writers remain unchanged. Extension columns remain
outside the existing returned fields. Missing required columns now fail with an
explicit SQLite error instead of substituting a neighboring cell. Non-JSON TEXT
decoding remains strict for selected columns. Stored status/time/risk labels
remain unverified claims; decoding is not active observation or attribution.

Together with the earlier campaign projections, this binds the four existing
campaign/check/alert record readers to their selected column names. It is not
closure of all S11 metadata, writer, resource, concurrency or collection work.
The active monitor consumes check history, but no active request or monitor
lifecycle is exercised or enabled here; that remains S14.

Six unit contracts operate on actual fresh/reversed/rotated/extra-leading-column
SQLite tables. Independent named SQL verifies every known returned field, raw
metadata and decoding status, read-only source bytes, campaign selection,
default/explicit/zero limits, time ordering, acknowledgment filtering, named
writers, acknowledgment updates and missing required columns. The cold-process
integration exercises six guarded API history readers and six separate status
CLI regressions over these layouts plus a missing-column fixture for each table.
API checks preserve source bytes and diagnostic JSON; the status CLI verifies
unchanged aggregate counts and is not a newly exposed history command. API
imports are guarded; normal CLI bootstrap precedes its application guard.

Local Windows/Python 3.13 validation passes 744 tests: 736 passed and eight
platform skips (82.463 seconds). The six new contracts fail before repair
(47 failures including subtests) and pass afterward. The prior campaign-layout
integration also passes on this version: five cold API and 23 guarded CLI
processes, including list aliases and actual add/remove row effects. Together
with the new integration this is eleven API and 29 CLI processes. An actual
offline wheel matches all 90 package Python sources, metadata, console
entrypoint and both review templates. These are saved-data checks; earlier EML
worker evidence stays versioned and final whole-engine/platform acceptance is
still open.
