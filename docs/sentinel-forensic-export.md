# Stored Sentinel forensic export and verifiable digest

Current contract update: Stored-data query/JSON/report budgets and one-transaction read views now apply. The returned-list digest remains an integrity observation, without source authentication or an atomic filesystem snapshot. See
[supported offline Sentinel completion](sentinel-offline-completion.md). Earlier
evidence and counts below remain historical.

This S11 correction follows merged PR48 (`eaebec9`) and changes two production
modules: the analyzer and its database export reader. Actual saved SQLite export
reproduced a null `data_integrity_hash`: the helper serialized data but never
returned a digest. The projected output discarded WHOIS, user agent, metadata,
correlation, interaction labels/confidence/indicators and JSON source/outcomes.
It also claimed `automated_ip_intelligence` for a row still marked `captured`.

## Passive use and source fidelity

`IntelligenceAnalyzer(db_path, read_only=True).export_forensic_data(case_id)`
admits existing saved storage using the previous [read-only boundary](sentinel-passive-opening.md).
It does not initialize/migrate storage or import/construct an IP collector or
geographic renderer. IP analysis and correlation-update entry points explicitly
reject read-only mode before thread/collector work. The default constructor
remains writable and still constructs its IP analyzer; geographic plotting
imports now occur only when its geographic-report method is explicitly called.
Those reports, other statistics and active lifecycle are not certified here.

The returned schema version 1 keeps the existing `victims` list and compatibility
projection fields. Each entry adds `stored_record`, the complete named database
reader result including all [typed JSON sources and decoding outcomes](sentinel-json-evidence.md).
SQL NULL, JSON null, absent legacy fields, whitespace/Unicode, malformed JSON,
duplicate keys, non-finite JSON and invalid UTF-8 TEXT/BLOB retain their existing
reader distinctions through actual JSON serialization. These are stored claims,
not authenticated geolocation, risk, identity, interaction or source history.
The export is now complete and unredacted for these reader fields, including
metadata/user agents; it is not the previous metadata-sanitized projection.
It returns a dictionary for the caller to save; it does not publish or save files.

The export uses a dedicated uncapped database reader rather than the interactive
listing's newest-100 window. `case_id=None` selects every stored row; any string,
including the empty string, selects that literal stored case identifier through
a bound SQL parameter with binary comparison, before row decoding. The selected
list is ordered by stored `click_time` descending, then `id` descending for ties.
Non-string identifiers raise an
error. A legitimate empty selection returns zero records. Missing, corrupt or
incomplete storage does not silently become an empty healthy export. Database
reads remain unbounded by case/page budgets in this correction, and a reader
error aborts the export rather than returning an undeclared partial list.

`evidence_scope` is `stored_rows_unverified`; `chain_of_custody` is
`not_established`. Compatibility `evidence_chain.captured_at/analyzed_at` are
explicitly unverified aliases of stored `created_at/updated_at`, with source
column names alongside them. They do not prove capture or analysis occurred at
those times. `analysis_method` is null; no automated analysis method is invented.
`export_time` is the current export construction time, not a source-event time.

## Digest contract

`data_integrity_hash` is now SHA-256 of the **returned `victims` list**, after
building its projections, complete sources and timestamp-alias qualifications.
`data_integrity` declares its algorithm, `scope: victims` and serialization
`json_sorted_keys_ascii_compact_v1`:

```python
json.dumps(victims, sort_keys=True, ensure_ascii=True,
           separators=(',', ':'), allow_nan=False).encode('ascii')
```

Object keys are sorted; list order and values remain significant. This is a
versioned Python JSON recipe, not an RFC canonical-JSON claim. The digest covers
neither `export_time` nor top-level selection/count/contract metadata; it is not
a hash of SQLite pages, original email bytes or a sealed case inventory. Matching
it establishes agreement with that list serialization, not authenticity,
complete storage history, custody or attribution. Other case export seals retain
their existing separate contracts.

Unsupported non-JSON storage values, such as BLOB user agents or non-finite SQL
risk/confidence scalars, cause strict serialization to fail explicitly. They
are not stringified with `default=str`, coerced to a score or omitted from the
list. Extending typed raw evidence to all non-JSON columns is separate work.

## Checks and remaining work

Nine actual SQLite contracts verify complete record equality through a JSON
file round-trip, independent digest recomputation and tampering, exact case
selection and the known empty-list digest, all six JSON fields' decoding/source
states, invalid TEXT bytes, all sixteen original/partial layouts without
migration, missing/corrupt/incomplete storage, strict unsupported-value failures,
and passive collector rejection/later journal admission. The review regression
uses 213 stored rows with 105 rows in each of two cases: all rows and an older
case outside the newest-100 window are retained, including old invalid JSON TEXT
source bytes. Modifying the oldest record changes the full-list digest. Literal
empty/quoted/case-sensitive identifiers are checked. Selection happens before
decoding unrelated invalid rows; errors in selected rows still abort an export.
The earlier 33
Sentinel contracts remain in place.

A fresh-process integration guards saved export import, construction, reading
and file serialization without collector, requests or plotting imports, and
verifies exact returned sources plus SHA-256 after reading the actual JSON file:
210 rows in a full export and all 105 older-case rows in a separate saved export.
Expected IDs come from the fixture and individual lookups, not a capped listing.
Missing storage remains absent. The default writer constructor is separately
checked after requests bootstrap; no IP analysis is executed. Zero blocked
operations under the application guard do not establish OS isolation or certify
all dependency cold imports. WAL/pending journals still require a separate
supported saved-storage workflow; external writers are not frozen.

On local Windows/Python 3.13, all 42 Sentinel contracts pass. The complete serial
suite passes 662 of 670 tests with eight platform exclusions. Existing original-EML
CLI/HTTP no-egress regressions, stopped exports and supervisor-crash recovery pass.
A real rebuilt wheel matches metadata/entry points and all 90 package Python
sources; this is not a clean installation or an attribution-accuracy evaluation.

S11 remains open for geographic/intelligence report provenance, unsupported
identity/risk claims, statistics, SQL JSON filter admission, all-column typed
storage, resource budgets and other lifecycle consumers. Active egress is S14;
the UI remains later work. No sample endpoint, DNS lookup or attachment execution
is used for this correction.
