# Stored geographic observations

This contract covers the existing `GeographicReporter`, the geographic wrappers
in `IntelligenceAnalyzer`, and `paw geographic` (`geo`) report/statistics dispatch.
It describes stored claims, not independently verified locations, people,
attacker/victim identity or calibrated risk. Active geolocation is not performed.

## Sources and selection

The reporter uses the complete passive forensic-row reader. `None` selects all
cases; strings, including empty strings, are exact SQL-bound case selections.
Older rows are not truncated to the latest 100. `source_records` retains every
selected row, including typed JSON sources, malformed fields and rows excluded
from derived geographic counts. Reader admission rejects missing/corrupt storage,
pending journals and unsupported WAL state; errors propagate rather than becoming
an empty successful report. A valid empty database can produce an empty report.

`min_confidence` must be a finite non-boolean number in 0..1. Zero disables the
confidence filter, including for legacy absent/NULL or unusable stored scores.
A positive threshold requires a stored numeric score in 0..1 and applies that
threshold; this is a selection over an unverified stored value, not a calibrated
probability. Selected native values that cannot be represented faithfully in JSON
(including BLOB scalars and non-finite numbers) cause an explicit error before
output creation; filtered rows cannot hide such source failures.

Geographic interpretation requires an unambiguously decoded JSON object. Country,
region and city use original nonblank strings without inventing `Unknown` values.
Coordinates require numeric, non-boolean latitude in -90..90 and longitude in
-180..180; `(0, 0)` is valid, and numeric strings are not coerced. Any usable label
or coordinate pair can retain a row, including coordinates without a country.
Optional country exclusions compare stored labels case-insensitively and apply
before every derived count or coordinate observation; originals remain available.

`selection` assigns each source ID to included, unusable confidence, below
threshold, excluded country or unusable geography. `field_omissions` identifies
missing/unusable fields of included rows. `total_records` counts selected rows;
the compatibility name `total_victims` counts included geographic rows, not people.
Countries are complete; the five-country summary is explicitly a preview. Regions
and cities are structured lists with separate country/region/city fields, counts
and source IDs, replacing ambiguous concatenated keys. Interaction labels remain
literal stored claims. Coordinate observations carry their source row ID and
`verified: false`. All aggregates can be recomputed from retained sources and
selection; row counts do not establish unique persons or authenticated locations.

Risk, attacker/victim countries and interactive maps are explicitly unavailable.
Original coordinate observations remain available for later validated consumers.
No Plotly/pandas renderer, collector or remote map assets are imported here.

## Output and admission

CLI admission validates options before opening the configured Sentinel database
with `read_only=True`. Geographic CLI and the module CLI helper use the default
`sentinel.db` only when `sentinel_config.json` is absent. An existing unreadable,
malformed, duplicate-key or invalid configuration propagates failure before
opening storage; it must contain a nonblank string `storage.database_path`.
Other Sentinel configuration consumers retain their existing behavior.
`map` rejects before database or directory initialization.
Statistics and reporter construction create no output directories. Explicit
report generation honors `json`, `html` or `both`, under `reports/geographic` by
default. JSON contains complete sources and observations. HTML is passive escaped
text, a full country table and complete escaped JSON, with a restrictive CSP and
no scripts, links, images, iframes or external assets. Lone surrogates in displayed
labels use literal backslash escapes; valid Unicode stays unchanged and complete
JSON preserves the original values with ASCII escapes. It does not render email
HTML or navigate stored URLs.

Filenames use independent UUID stems and exclusive creation; case labels never
form paths and existing files are not overwritten. Serialization occurs before
directory creation. Write failures propagate and cannot print completed output
success. Multi-file publication is **not atomic**: an error can leave a partial
file or one completed sibling. Inspect the attempted paths reported by a write
error; directory creation failures also propagate. Returned `output_files` lists
only completed requested writes and is added after saving, so it is not part of
the saved JSON body or a signed publication manifest.

The default writable analyzer constructor and other statistical/lifecycle consumers
remain outside this contract.
Complete selected-row size/resource limits and general non-JSON storage support
remain open S11 work. Passive reads are not an atomic concurrent-writer snapshot.
The Python no-egress guard is application policy, not OS isolation.

## Verification

### Legacy checkout launcher

`generate_geo_report.py` forwards arguments to `paw geographic report`, using the
same configured passive database reader and existing report writer. Its former
hardcoded database/case and duplicate `PAW/reports/geographic` JSON copy are
removed. With no options it selects all stored cases; use `--case` for an exact
case, including an empty literal value. `--output` and `--min-confidence` keep the
canonical command's existing meanings. Output stays in `reports/geographic`.
Missing or invalid sources fail explicitly; help and rejected arguments do not
create storage or reports. Import alone does not load PAW or change arguments.

An actual baseline `--help` invocation under application no-egress created a
new database and three reports, and imported the IP analyzer. The focused
`integration_legacy_geographic_real.py` regression fails before the alias repair.
After it, 17 paired legacy/canonical scenarios check real saved/legacy SQLite,
complete rows, literal case selection, filters, JSON/HTML, missing/corrupt/config/
WAL/journal/output failures, source and existing-report byte preservation, inert
import and direct help. Only invocation timestamps and output names differ.
Guarded dispatch bootstraps the existing CLI before applying the network policy;
it does not establish cold-bootstrap or OS isolation. No geographic algorithm,
schema, collector, renderer or identity/risk capability is added.

### Canonical paths

`test_sentinel_geographic_report.py` exercises actual SQLite storage, complete
older-case selection, legacy layouts, typed malformed JSON, confidence and country
filters, coordinate boundaries, aggregate provenance, hostile labels, exclusive
output names and failure preservation. `integration_sentinel_geographic_real.py`
checks 25 fresh actual CLI/API/helper scenarios, requested files and unchanged source
trees, including cold guarded API import and unavailable maps before I/O.
CLI bootstrap precedes its Python guard; API import is guarded from entry.
These constructed storage fixtures verify execution and source fidelity, not
real-world geolocation accuracy or classifier ground truth. No browser or live
suspicious endpoint is exercised.
