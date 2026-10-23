# Stored Sentinel JSON sources and decoding outcomes

Current contract update: Read profiles now bound raw JSON bytes, cumulative decoded nodes and depth. Resource exhaustion retains typed source with `resource_limit` rather than a verified default; query/publication budgets fail explicitly. See
[supported offline Sentinel completion](sentinel-offline-completion.md). Earlier
evidence and counts below remain historical.

This S11 correction concerns only `paw/sentinel/database.py`. On merged PR46
(`29cd3a4`), malformed, empty and SQL-null JSON fields silently became `{}` or
`[]`. Alert metadata instead used unguarded `json.loads`, so one damaged alert
aborted the whole list. Duplicate object keys collapsed to their last values,
and non-finite constants/exponent overflow entered decoded records. Actual
temporary SQLite storage and public readers reproduced these behaviors before
the correction; they are not claims about independently labeled phishing data.

## Reader contract

JSON provenance relies on the correct source column. Subsequent
[campaign](sentinel-campaign-columns.md) and [check/alert](sentinel-history-columns.md)
projection repairs bind those record fields across physical table layouts.

The existing campaign/check/alert metadata and six interaction JSON fields now
use one decoder. Each returned record adds `json_evidence` with
`schema_version: 1` and `fields` keyed by the existing JSON column name. Each
field observation has `status`, `raw_storage`, `default_applied`, and
`verified: false`. This is a storage/decoding observation, not authentication of
the value, geolocation, interaction label or attribution.

`raw_storage` retains SQLite's returned value and storage type: TEXT uses the
exact string, including whitespace and Unicode; SQL NULL has a null value;
INTEGER retains the integer; BLOB uses reversible base64; REAL uses Python's
reversible `float.hex()` representation, including infinities. Undecodable UTF-8
TEXT uses reversible base64 with `type: text`, distinct from `type: blob`; no
replacement characters or alternate JSON encoding are substituted. This preserves
the returned SQLite cell, not original filesystem bytes, a database-page offset
or a history of changes. No hash, origin or observation timestamp is invented.

| Status | Compatibility field | Interpretation |
| --- | --- | --- |
| `decoded` | Decoded value, including JSON null/scalars | Parsing succeeded under the documented decoder; shape/claims remain unvalidated. |
| `sql_null` | Existing `{}`/`[]` default | Stored SQL NULL, distinct from the TEXT JSON literal `null`. |
| `empty` | Existing default | Empty TEXT/BLOB; original type/value retained. Whitespace-only JSON is invalid. |
| `missing_column` | null | Unmigrated interaction-indicators column absent; no stored cell or migration default. |
| `invalid_json` / `invalid_encoding` | Existing default | Parsing/byte decoding failed; raw source remains. |
| `duplicate_keys` | Existing default | Ambiguous object keys at any depth, including escape-equivalent names. No last-value interpretation. |
| `non_finite_number` | Existing default | NaN/Infinity constants or a numeric token overflowing float range; preserved only in raw source. |
| `unsupported_storage_type` | Existing default | Numeric SQL cell cannot be passed to the JSON decoder. |
| `decode_error` | Existing default | Runtime value/depth admission failed; not proof of invalid JSON syntax. |

Defaults are compatibility values, not proof of an empty healthy object/list.
`default_applied` is true for these fallback states, false for a decoded value
or missing column. A missing interaction type/confidence remains null through
the previous named-row contract; only JSON columns have field observations.
Valid scalar/differently shaped JSON remains decoded for compatibility. BLOB
parsing retains Python JSON's existing encoding handling; the source bytes are
still retained exactly as base64. Parsed values from ambiguous/non-finite JSON
change to explicit fallback plus source/status. Damaged alert metadata no longer
prevents other alerts and their source messages from being read.

The JSON readers defer SQLite's implicit TEXT conversion for these columns, so
invalid UTF-8 TEXT reaches the decoder and produces `invalid_encoding` instead
of aborting `fetchall()`. Valid UTF-8 TEXT remains a string, BLOB remains BLOB,
and TEXT corruption in non-JSON columns still raises an explicit SQLite error.
General connections, writers and SQL JSON filters retain their prior behavior.

Writers, schema/migration, filters, ordering, pagination, risk scoring and other
production modules are unchanged. Existing consumers still receive their flat
fields plus the additive evidence key. Current `monitor list` displays stored
URLs/statuses, not these field diagnostics. Geographic/intelligence projections
and exports may omit them; their propagation and interpretation require the
remaining consumer audit. Do not infer end-to-end report fidelity from the
database reader alone.

## Checks and remaining boundaries

Twelve new contracts use actual SQLite files/writers/readers under offline policy:
exact source/Unicode/nested values across ten public query variants, distinctions
among NULL/empty/JSON null/missing column, malformed alerts with valid neighbor
rows, duplicate/escaped keys, nested non-finite/overflow, BLOBs, SQLite TEXT
affinity and original numeric storage, all six named interaction JSON fields,
runtime depth failure, and invalid UTF-8 TEXT inserted with SQLite `CAST` across
all JSON columns, with a valid neighboring alert and strict serialization. The
TEXT/BLOB distinction is checked against actual `typeof` and byte projections;
non-JSON encoding failure remains explicit. Sources/rows/database bytes are unchanged after
reads. Strict JSON serialization of the exercised records succeeds; arbitrary
non-JSON fields such as a manually corrupted numeric confidence are not newly
validated. The previous sixteen row/admission contracts remain in place; their
named-storage comparisons exclude only the new envelope, which these dedicated
contracts validate separately.

On local Windows/Python 3.13, all twenty-eight Sentinel contracts pass; the general
suite passes 648 of 656 tests with eight platform exclusions. The seven-case
actual passive CLI list integration and existing original-EML CLI/HTTP no-egress
regression pass, including query/evidence-reader admission, stopped-case exports
and supervisor-crash recovery. A real rebuilt wheel matches metadata/entry
points and all 90 package Python sources. These broader checks do not prove
report fidelity, clean dependency installation or attribution accuracy.

During the review fix, an initial concurrent suite run had one process-deadline
test error: its child heartbeat was absent before the deadline. The unchanged
test passed in the complete serial rerun (656 tests, eight exclusions). Both
logs are retained; this is a scheduling observation, not a Sentinel decoding
failure or a change to process supervision.

The country filter and correlation SQL still use SQLite JSON functions before
row decoding: malformed geolocation may fail the query, and duplicate-key SQL
selection is not made into a validated country binding. General row counts,
statistics, geographic claims, partial-list/export accounting and lifecycle
consumers remain open. Stored field size/admission and output budgets are not
newly bounded here; this does not claim safe ingestion of arbitrary-size SQLite
files. Saved read-only admission retains the previous rollback-journal/WAL
boundary and is not an atomic snapshot of external writers. No collector, URL,
DNS, attachment execution, Docker or interface change is required for this patch.
