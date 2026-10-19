# Supplied tracker-pattern observations

`paw/core/trackers.py` provides version-2 observations from supplied Unicode
HTML/JavaScript strings and a supplied list of log dictionaries. It never reads
capture files, fetches URLs, resolves DNS, runs JavaScript or observes a browser.
The supplied log records themselves are not independently authenticated events.

The separate [legacy case publishers](legacy-tracker-publication.md) are
explicitly unavailable before case access. Their CSV/ID/behavioral products are
not inputs automatically validated or migrated by this extractor.

Baseline failures reproduced on merged PR42 (`fb832c0`): the helper returned
`trackers_found` while its actual matrix consumer read `trackers`, losing all
matches; filenames/domain references became tracker IDs; substring matching
accepted lookalike/userinfo domains; missing method/status became GET/0; arbitrary
width/height strings made an image a tracking pixel; absent referrers and port
differences created third-party claims. Malformed URL/type inputs raised, and
shared references such as `matomo.js` generated campaign confidence. There were
no source bounds, hashes or offsets. These are static contract failures, not
independent classification findings.

## Sources, observations and output migration

The class entry points and convenience function remain available. Their output
uses `schema_version: 2`, one `sources` catalog and one `observations` array.
Convenience calls share all budgets across HTML, JavaScript and optional logs;
the former nested HTML/JS/network wrapper is replaced by catalog source kinds.
Compatibility arrays `trackers_found`, `network_trackers`, `tracking_pixels`,
`third_party_domains` and `correlation_keys` remain empty. Consumers must read
observations and the unavailable `interpretation` rather than treating those
arrays as absence of tracking. Summary counts are retained occurrences, not
unique trackers, visits or operators. Campaign correlation reports unavailable
confidence with empty matches; resemblance alone is not a sourced campaign.

Each admitted text source records SHA-256 and byte length of the complete
supplied Unicode string encoded as UTF-8. Optional `source_url` is unverified
caller context, not a fetched origin or part of that text hash. HTML is scanned
as literal text, including comments, attributes and script strings; it is not a
DOM interpretation. JavaScript is not executed. Pattern spans and identifier
spans are zero-based Python character offsets into the named source field.
Every repeated match remains a separate sourced observation, preserving spelling.

All seven existing registry families/categories remain. The two unescaped dots
in the Facebook URL and TikTok endpoint patterns are corrected to literal dots.
Patterns with a capture group retain that group as an unverified identifier
candidate; the three Google patterns retain their entire match. Filename/domain
and endpoint patterns without an ID capture retain the reference with a null
identifier candidate. Registry labels do not prove use of a vendor, a valid ID,
a loaded SDK or any tracking. Existing substring/case-insensitive lexical
matching otherwise remains intentionally descriptive, without calibration.

Each admitted log source retains a deep JSON copy of its **complete supplied
record** and a source hash over canonical JSON: sorted keys, ASCII escapes,
compact separators, finite numbers, encoded as UTF-8. This is not a hash of raw
JSONL, response bytes or packets; duplicate keys already lost by the caller's
dictionary cannot be recovered. Unknown JSON metadata, headers, timestamp,
request/response type and supplied method/status are preserved without defaults.
Missing/invalid URL fields are explicitly uninterpreted; the admitted record and
hash remain available. Canonical hashes do not depend on dictionary insertion
order. Request and response records are separate occurrences, not joined visits.

For bounded HTTP(S) URL strings, `urllib.parse.urlsplit` derives literal
hostname/path/query/fragment observations without navigation. Invalid brackets,
ports, ASCII whitespace/control characters and backslashes are uninterpreted;
other schemes and relative references are unsupported for these supplied logs.
Registry hostname comparisons require exact equality or a dot-delimited subdomain,
excluding userinfo/query/path/lookalike matches. Exactly one terminal DNS root
dot is removed only for this registry comparison; multiple terminal dots do not
match. Registry observations retain the parsed hostname in `value` and record
the derived `comparison_hostname` and `comparison_method`. Original URLs,
canonical record hashes, URL components and literal referrer comparisons remain
unchanged. They are parsed string matches,
not provider ownership or browser URL validation. A separate registry-pattern
scan of the full admitted URL can retain identifier/reference candidates even
when URL interpretation is unavailable. No truncated URL becomes a target.

Image extensions are path observations, not verified dimensions or tracking
pixels. Query strings and separately supplied `query` metadata remain literal.
Only a supplied root `referer` is used for literal hostname equality; equality
does not establish same origin/site, and inequality does not establish third-party
ownership. `Referer` inside supplied headers is preserved but not interpreted.
Header authenticity, requests, image bytes and actual dimensions are unavailable.

## Bounds, omissions and malformed records

Defaults per call: 1 MiB per text/canonical-record source, 2 MiB combined admitted
bytes, 1,024 log entries, 2,048 observations, 4,096 characters per observation/URL
context, 16,384 JSON nodes across records, nesting depth eight (root depth zero),
and 4,096 bits per JSON integer. JSON keys count as nodes. All limits require
positive integers and reject booleans. Text and canonical JSON have different
encoding scopes; escaped canonical characters consume their full serialized size.

Oversized/invalid text is rejected whole without prefix interpretation/hash.
Invalid JSON records, nonstring keys, unsupported types, cycles/depth, nonfinite
numbers, large integers and node/byte-limit failures are not given a complete
record hash or partial record substitute. Admission of records checks the remaining
combined byte budget before serialization. Long unrelated JSON metadata is
retained within source budgets; the observation-value limit does not apply to
the entire record. A long URL can retain its complete admitted record/hash and
bounded lexical matches while URL component interpretation is unavailable.

Log-entry overflow explicitly counts omitted entries; admitted-prefix source
records identify original list indexes. Record-level rejection is described in
its catalog status/reason. Observation totals and omissions share one budget,
including long matches. All such failures/omissions make the inventory `partial`.
`completed` only means supported supplied-input processing completed; it cannot
prove that trackers are absent, logs are authentic or the page is benign.

## Consumer and actual verification scope

The identified active caller is `detonate/runner.generate_enrichment_files`:
`page.content()` goes to `extract_from_html`, then `enrichment_trackers.json` and
the combined `AttributionMatrix` input. Version-2 consumption now reads
observations and retains counts, source indexes/kinds/hashes/admission failures
and partial status with unavailable confidence. Registry-pattern counts are
accompanied by an independent copy of the complete tracker `coverage`, including
processed bytes, total/omitted observations, total/omitted log entries and issues.
The retained `evidence_count` remains distinct from these omission totals; missing
coverage remains null rather than becoming fabricated zero counts. Registry
pattern counts are separate from ordinary supplied-log literals, avoiding a tracker claim for an
unrelated URL. Other matrix sources and historical version-1 imports are outside
this correction; the sourced operator dataset remains unavailable.

The active caller and collection/writer behavior are unchanged. Its later DOM
snapshot need not equal previously saved kit HTML. Exact snapshot retention and
active browser/network enrichment remain open S14 work. The full `--no-egress`
worker does not reach that caller. Log and combined-helper APIs have independent
static tests; they are not evidence that the runner uses every API.

`tests/test_tracker_observations.py` exercises the actual helper, all registry
families, repeated spans, admission/omission budgets, canonical log preservation,
malformed inputs and the actual matrix consumer. Its static fixture also writes
the supplied originals and actual runtime atomic JSON artifacts, then seals,
verifies and ZIP-exports them under offline policy with no writers. That is a
local helper/artifact test, not the active runner's publisher or a simulated
detonation. Constructed sources are not phishing labels; Python offline policy
is not OS isolation. Controlled egress and UI remain later stages.

The initial local Windows/Python 3.13 check passed 35 focused tracker contracts
and the general suite (615 tests, 607 pass, eight platform exclusions). The
terminal-root-dot review correction reproduces lost matches for all ten registry
domains and passes 38 focused contracts and the general suite (618 tests,
610 pass, eight platform exclusions), including original canonical hashes,
matrix counts, subdomains, double-dot rejection and lookalike boundaries.
The subsequent matrix-coverage P2 was reproduced on `1783b42`: a partial tracker
inventory retained 14 omitted observations or four omitted log entries that the
matrix summary dropped. Passing through the complete coverage fixes that loss;
39 focused contracts and the general suite (619 tests, 611 pass, eight platform
exclusions) pass. Coverage survives actual atomic JSON, sealing and ZIP export;
source/total byte, observation count/value, log entry, JSON node/depth and invalid
input reasons are preserved without shared mutable lists. Extraction is unchanged
from `1783b42`; only the tracker version-2 matrix branch changes in this follow-up.
Actual shared CLI/API ownership/read/query/verify/export and supervisor-crash
recovery passed on the preceding `bf4a676` commit with original EML and explicit
no-egress; those checks were not repeated for either review correction. These worker
flows do not exercise the active tracker caller. A rebuilt wheel matches current
metadata/entry points and all 90 Python-source bytes; it is not a new clean
dependency installation. Among those sources only the tracker helper and its
version-2 matrix consumer change. No private 20-original replay or independently
labeled classification evaluation is claimed by these checks.
