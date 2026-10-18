# Stored campaign column correspondence

The two campaign readers, `get_campaign` and `get_active_campaigns`, now select
their eleven existing columns explicitly in the order their decoder consumes.
Previously `SELECT *` bound those fields to physical table offsets. Actual saved
SQLite fixtures with reversed/rotated columns or an additional leading column
returned the wrong ID, case, URL, status and metadata source while the CLI still
reported success. The same source bytes read correctly in the fresh layout.
These fixtures establish a reader defect, not prevalence in the private corpus.

The later [check/alert projection repair](sentinel-history-columns.md) addresses
the same physical-offset problem in the two remaining history record readers.

The production change is limited to those two SELECT projections. Query filters,
JSON decoding/provenance, returned keys, schema, migrations, writer
initialization and mutations are unchanged. Unknown extension columns remain
outside these existing projections; this is not a complete raw-row export.
A missing required column now raises an explicit SQLite error instead of using
the value at its former offset. Existing strict non-JSON TEXT decoding remains
for the selected columns. No new ordering guarantee is introduced.

Campaign lookup and active listing use the same projection. This also repairs
the passive CLI/legacy list alias and the case/ID values consumed by removal
preflight. Accepted add/remove still use the existing writer; selection followed
by writer opening is not an atomic snapshot. A stored URL is not authorization
to visit it, and a stored status/risk label is not an independently verified
observation or attribution. Active monitoring remains S14.

Six unit contracts compare both readers with independent named SQL against four
actual schema layouts. They check all known fields, exact metadata source/status,
active/ID selection, missing results, named writers and status updates, missing
required columns, passive byte preservation and unchanged related readers.
`integration_sentinel_campaign_columns_real.py` checks five cold API and 23
guarded CLI processes against these layouts and a missing-column fixture.
Canonical/legacy list output must retain the actual ID/URL/status, passive reads
preserve bytes, and add/remove must have only the expected stored row effects.
Missing-column removal fails before writer initialization. API imports are
guarded; ordinary CLI bootstrap precedes its guard. These are declared stored
fixtures, not live concurrency, OS containment, authenticity or accuracy proofs.

Local Windows/Python 3.13 validation passes 738 tests: 730 passed and eight
platform skips (73.303 seconds). The six new contracts fail on the old queries
(28 failures including subtests) and pass after repair. The existing forty CLI
campaign-admission/mutation scenarios and seven passive-opening scenarios also
pass, including rejection of unsupported saved sources without changes. Together
with the new integration this exercises five cold API and seventy guarded CLI
processes. An actual offline wheel matches all 90 package Python sources,
metadata, console entrypoint and both review templates. These checks concern
saved campaign consumers; earlier original-EML analyses remain versioned
evidence, not a new whole-engine or final cross-platform acceptance result.
