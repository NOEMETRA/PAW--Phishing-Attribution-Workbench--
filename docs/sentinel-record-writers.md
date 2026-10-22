# Sentinel JSON record writers and persisted effects

This S11 family follows merged PR82, `52a70a9`. Its exact-head and merge CI
completed successfully, as did the corrected-head Codex review. This family
changes `paw/sentinel/database.py`; active analysis, collection and report
algorithms are unchanged.

## Reproduced boundary

The check, alert and interaction inserts used `metadata or {}`: falsy non-object
values silently became objects. JSON encoders accepted non-finite values,
coerced non-string keys and tuples, and could emit duplicate string keys after
coercion. Their own strict readers could then reject the newly written JSON.
Analysis updates reported `True` for absent IDs or ignored/reverted updates.
Checks and alerts could acquire nonexistent parent IDs because the connection
did not enforce the declared foreign key. A check and its parent's `last_check`
used separate clock calls. These failures are actual local SQLite regressions,
not evidence that a remote interaction happened or a classifier is accurate.

## Admission before storage

The campaign/check/alert/interaction metadata writers share one encoder.
`None` alone requests their existing empty-object default. Other metadata must
be native dictionaries. Geolocation, WHOIS and correlation updates require
objects; related IPs and interaction indicators require native lists of strings.
An analysis argument of `None` still means leave that field unchanged. Explicit
empty objects/lists and zero values are persisted. No new API for storing JSON
null or clearing SQL columns is introduced.

Nested values must use native JSON types, with string object keys and finite
numbers. Tuples, arbitrary objects, byte values, cycles and key coercion are
rejected. Native containers are copied during bounded validation before encoding;
this is not an atomic snapshot of caller-owned containers modified concurrently.
Each JSON field has these fixed limits, including metadata on campaigns:

- At most 1 MiB of encoded ASCII JSON, including punctuation and escapes.
- Container/value depth at most 64, with the root at depth zero.
- At most 100,000 visited nodes, counting dictionary keys as well as values.

The existing ASCII JSON spelling is retained. Limits are checked before the
writer opens a database connection; oversize input is not truncated or replaced.
These are payload/encoding budgets, not a hard process-memory bound. They do not
limit scalar text columns, total database size, row counts, existing saved JSON,
or report/HTML resources. Legacy sources remain readable under their separate
typed JSON evidence contract; no stored data is cleaned or migrated by this change.

New scalar fields must match their literal text/numeric API types. Booleans do
not alias numeric identifiers or scores. Analysis IDs are positive SQLite-range
integers. Numeric scores must be finite; scores are not calibrated or clamped to
a risk interpretation. Confidence inputs are finite numbers from zero to one;
response time is nonnegative and HTTP status is an integer from 100 to 599.
Literal interaction labels, status strings and IP/URL text are stored without
resolution, classification or authentication.

## Transactions and honest results

Writes use explicit transactions. Inserts require exactly one inserted row and
re-read the supplied columns at its returned rowid. Ignored, deleted or changed
inserts raise and roll back. Checks/alerts require one existing literal parent in
the same transaction; a check and `last_check` use one timestamp. Both that parent
timestamp and the inserted check are verified after the parent's update.

Analysis updates return `False` if no row was updated, including an ignored update,
rolling back intermediate effects before returning. They return `True` only
after exactly one affected row retains all supplied columns and
the update timestamp. Duplicate legacy IDs or reverted/changed fields raise and
roll back. Existing fields omitted from the call and unrelated ordinary rows
remain unchanged in the tested layouts. A call with no update arguments remains
an immediate `False` without changing the timestamp.

These postconditions check the requested columns at transaction time. They are
not a classifier for arbitrary schema/default/trigger behavior, a guarantee
against trigger side effects in other rows/tables, external writers after commit,
or power-loss durability. Read-only SQLite still rejects real writes. Other
mutators (`acknowledge_alert`, status updates and retention cleanup), consumer
resource budgets and cross-process snapshots retain their separate open scope.

## Verification

`test_sentinel_record_writers.py` uses actual SQLite, independent SQL, source-byte
comparisons, pre-connection guards and declared trigger faults. It covers strict
JSON/scalar admission, encoded byte boundaries, complete/empty/default payloads,
missing/duplicate IDs, ignored/reverted writes, parent effects and read-only errors.
`integration_sentinel_writers_real.py` runs six cold APIs and two guarded CLI
processes, saving and independently checking passive JSON reports/digests after
actual writes. Network attempts and remaining threads are checked; API consumers
cannot load collectors or HTTP/plot clients. CLI bootstrap occurs before policy,
as in the existing integration contract. No sample URL is visited.

The 24 contracts against the PR82 module reproduce 123 failed assertions and
eight errors including subtests. The final serial general suite runs 835 tests:
823 pass and twelve platform exclusions, in 85.267 seconds. On the same frozen
source, the six cold writer/report APIs and two CLI processes pass; an actual
original-EML full no-egress worker stops, then five local-storage APIs/six CLI
processes preserve every original case/input byte through verify and ZIP export.
The actual offline wheel matches 90 current package sources, metadata, entrypoint
and both review templates. Only the database package source changes; 89 Git
package sources are unchanged. Existing campaign/history cold-layout integrations
also pass during the block, before the final ignored-update rollback refinement;
the final suite, writer integration, full case and wheel are repeated afterward.
Application no-egress is not OS isolation, and
these constructed storage regressions do not establish attribution or accuracy.
