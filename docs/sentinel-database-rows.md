# Sentinel interaction-record column correspondence

This focused S11 correction changes only the interaction-row readers in
`paw/sentinel/database.py`. No collector, URL monitoring, enrichment,
classification, geographic report or interface is enabled or rewritten.

## Reproduced defect

On merged PR44 (`7dff02c`), the fresh `victim_intelligence` schema places the
three interaction fields before `metadata`, `created_at` and `updated_at`.
Older schemas have these fields appended by `ALTER TABLE`; a partially migrated
schema can have another physical order. The general reader assumed the fresh
order, the risk/country decoder assumed the appended order, and the unanalyzed
reader assumed the original fifteen columns and omitted the interaction fields.
Actual SQLite databases and the existing writers reproduced misplaced metadata,
dates and interaction fields across fresh, legacy and partially migrated layouts.

All four reader methods now use `sqlite3.Row` on their own connections and the
same decoder of known column names. ID, IP and general list queries, the
unanalyzed list, and the risk/country filters therefore return the same stored
fields regardless of migration order. Other connections keep their existing
tuple representation; table definitions, migrations, writers, filters, ordering
and pagination are unchanged. Existing default limits remain 100 general rows
and 50 unanalyzed rows; these lists do not promise an exhaustive database export.

The decoder retains stored metadata, dates, scores, confidence, supplied labels,
Unicode and nested valid JSON. It consistently uses the general reader's
existing JSON fallback: object fields default to `{}` and list fields to `[]`
when SQL NULL, empty or malformed. Valid JSON is decoded without a new shape
validator, including JSON null, scalar and differently shaped values. This
fallback in the original row-mapping patch did not expose malformed raw JSON;
storage is not rewritten. The subsequent [stored-JSON contract](sentinel-json-evidence.md)
adds typed source and explicit decoding status, including ambiguity/non-finite
rejection. Invalid geolocation JSON can still fail the country SQL query before
decoding; SQL JSON admission remains a separate boundary.

## Verification and limits

Seven focused contracts operate on real temporary SQLite files under the
application offline policy. They cover the fresh schema and all sixteen ordered
subsets of previously appended interaction fields, actual initialization/
migration, named writes and updates, reopening, all six public query variants,
field correspondence with independent named SQL reads, Unicode/nested metadata,
SQL nulls, JSON compatibility, empty results, filters, ordering and limits.
After initialization, repeated reads preserve database bytes and source rows,
and the contracts attempt no blocked network operation. Constructed stored
records are regression inputs, not independently adjudicated interaction data.

On local Windows/Python 3.13, all seven focused contracts pass; the general suite
passes 627 of 635 tests with eight platform exclusions. The existing actual
CLI/HTTP integration passes with original EML bytes, explicit no-egress,
loopback HTTP, query/index byte preservation, evidence-reader admission,
stopped-case verify/export and supervisor-crash recovery. That email integration
is a regression check, not an interaction-reader exercise. A real rebuilt wheel
matches the metadata/entry points and all 90 current package Python sources;
this is not a clean dependency installation or an accuracy evaluation.

The default writable constructor still creates parent directories/database
tables and performs migrations. Reader-byte preservation after initialization
must not be described as read-only opening of an existing evidence database.
The subsequent [passive-opening contract](sentinel-passive-opening.md) supplies
an explicit read-only mode and the `monitor list` consumer. Campaign/check/alert readers and statistical,
intelligence, geographic-report and lifecycle behavior are not comprehensively
validated by the interaction-row correction. The later
[campaign reader correction](sentinel-campaign-columns.md) checks the two
campaign projections and their passive list/removal consumers separately.

Stored `victim_*`, `attacker_correlation`, risk scores and interaction labels
remain legacy names/claims. Correct decoding does not establish victim/attacker
identity, reliable geolocation, attribution or calibrated confidence. Full email
analysis does not automatically run these Sentinel readers. Active monitoring
and controlled egress remain S14 work; UI remains later work. No suspicious
endpoint, sample DNS resolution or attachment execution is needed here.
