# Supported offline Sentinel completion

This block completes the finite supported **offline** Sentinel contracts after
merged PR83 (`17803da09691674fff2e5811e500f890767b6800`). It covers the whole existing
package and its CLI/legacy consumers as one family. Active collection, active
interpretation and in-process service lifecycle remain S14; this is not a claim
that their algorithms or every function have been validated.

## Module disposition

| Unit | Supported offline contract | Boundary |
| --- | --- | --- |
| `contracts.py` (new internal module) | Shared literal storage admission, native JSON copying/encoding and resource profiles; import opens no config/storage. | Application admission, not OS isolation or filesystem authenticity. |
| `config.py` | Strict bounded config, validated sections/profile, copied getters, bound database options and existing atomic publication. | Single writer; no cross-process compare-and-swap publication protocol. |
| `database.py` | Passive named-column readers, source-preserving JSON status, transactional writers, actual status/acknowledgment effects, UTC retention and bounded read views. | Supported fresh/migrated layouts; arbitrary triggers, collations and schemas are not certified. |
| `file_monitor.py` | Stable roots, all admitted regular files, bounded scans/reports, observed-mutation refusal and per-instance baseline rollback. | First scan establishes a baseline; no atomic filesystem snapshot or historical reconstruction. |
| `geographic_reports.py` | Traceable selected stored observations, bounded statistics/JSON/escaped HTML and stable exclusive output paths. | Maps, identity and risk unavailable; file pair is not an atomic publication. |
| `intelligence_analyzer.py` | Bounded passive report/export/statistics and candidate labels with existing unverified-source qualifications. | Active helpers refuse under no-egress; no validated attacker/victim identity or correlation. |
| `ip_analyzer.py` | Import without HTTP dependency and pure address/prefix syntax. | Active methods refuse before I/O under no-egress; provider/risk/correlation behavior remains S14/S10. |
| `monitor.py` | Local configuration/database management, explicit instance flags and active-entry refusal. | Persistent CLI start/stop remain unavailable; actual active service lifecycle/callbacks remain S14. |
| `__init__.py`, canonical CLI and legacy diagnostics | Public imports, configured profile propagation and offline command boundaries. | No new service, collector or UI capability. |

Nine existing package sources change and one internal source is added; 81 existing
package sources retain their Git contents. The wheel now contains 91 Python
sources. No dependency, database column/table or new operational launcher is added.

## Stored-data and publication budgets

Configure overrides in `storage.limits`; direct database/analyzer APIs accept the
same `limits` mapping. Only known keys and positive native integers below `2**31`
are accepted; booleans and implicit coercions fail before opening SQLite.

| Setting | Default | Scope |
| --- | --- | --- |
| `max_rows` | 10,000 | Rows consumed per cursor, including filtered/inspected rows. |
| `max_row_bytes` | 8 MiB | SQLite `SQLITE_LIMIT_LENGTH`; may reject at preparation/schema admission. |
| `max_result_bytes` | 32 MiB | Native payload consumed per cursor. |
| `max_sql_steps` | 10,000,000 | Approximate VM work budget per connection, progress interval at most 100. |
| `max_output_bytes` | 64 MiB | Strict ASCII JSON report encoding; geographic JSON+HTML combined and returned output metadata checked before writing. |
| `max_json_depth` | 64 | Decoded native JSON tree depth. |
| `max_json_nodes` | 100,000 | Shared across JSON cells/rows in one read context, isolated across concurrent readers. |
| `max_json_bytes` | 1 MiB | Raw JSON cell bytes before decoding. |

These bound admitted work/payloads, not process RSS, wall time or OS resources.
JSON strings also have a fixed 1 MiB native-length ceiling. Configuration and
record writes retain their separate fixed 1 MiB encoded/depth-64/100,000-node
contracts. Read-profile overrides do not enlarge those writer limits.

A JSON decoding budget failure retains typed raw source and reports
`resource_limit`, default application and `verified: false`. Query/result/output
budget failure rejects the operation rather than returning a healthy empty
result. Country selection rejects if required geographic JSON exceeded its
budget. Other malformed fields retain the previously documented omission/status
contracts. Unsupported non-JSON SQLite scalars in selected JSON publications fail
explicitly; this block does not introduce a lossless all-column binary format.

Every read connection uses one SQLite read transaction. Returned report metadata
states that scope and rejects an atomic-filesystem-snapshot interpretation. An
actual second-process writer is held from committing during the selected read
view, then commits after it closes. This does not establish source authenticity,
whole-file immutability or support for WAL/pending-journal sources.

## Mutation, configuration and local files

Status updates and alert acknowledgments return true only for an actual verified
transition; absent or already-matching rows return false. Reverted/ignored effects
roll back. Nullable legacy campaign status remains representable. Literal ID/IP
selectors do not turn zero, empty strings or booleans into broader queries; mode
and campaign-selector types are admitted before opening SQLite. Tied history
ordering includes record ID for deterministic results.

Retention samples its cutoff inside the write transaction. Only full timezone-aware
ISO timestamps are compared as UTC. Naive, date-only and malformed timestamps are
retained and listed; verified deleted counts cover checks/alerts together. Failed
or ignored deletion rolls back both tables. No case file or screenshot is deleted.
Arbitrary trigger side effects outside the requested effects are not certified.

All configured database consumers, including `check_victims.py` and its alias,
use the same strict loader/options. Getters return copies, preventing unsaved
container mutation. A configured `limits: null` is invalid; an absent key or direct
API `limits=None` still selects defaults. Successful config publication installs
the admitted copy, so later caller-container changes cannot alter live state. Storage rejects known links/reparse points, multiple hard
links, special files and Windows device/stream/normalization aliases. Those checks
do not prove absence of mounted/network backing or metadata-preserving races.

File scans now include hidden names and `.pyc` regular files as bytes, without
execution or extension exclusions. Limits cover files, bytes, directories (10,000),
depth (64), entries and output (64 MiB). Directory/entry work is shared across
all cases and repeated walks within each all-case operation; it counts traversal
visits, not distinct paths. A new invocation gets a fresh budget. Observed end-of-report inventory/metadata
changes fail; failed combined publication/console emission restores that instance's
baseline. `os.walk` preallocation and transient metadata-preserving changes are not
an OS snapshot guarantee. Console check records are not database persistence.

Geographic output roots are bound on construction/assignment, including defaults.
Every known ancestor is admitted; outputs are created exclusively. Budget errors
precede directory/output creation. An I/O failure can leave new partial output
files with an explicit error/attempted paths; existing outputs are never replaced.

## Active boundary and deferred work

Twenty-three active public/helper entry points are exercised under the application
no-egress policy with opaque arguments: they refuse before argument use, network,
storage or new worker threads. Imports do not load HTTP/plotting dependencies.
The fabricated IPify key is removed; that provider requires `PAW_IPIFY_API_KEY`.
No provider request or active target was used to validate this block.

S14 still owns actual start/stop/cancellation, remote collection, screenshots,
provider responses and controlled Windows/Linux isolation. S10 still owns
independent accuracy/correlation evaluation. Passive stored labels, coordinates,
user agents and timing do not establish identity, risk or authenticity. Global
engine acceptance, platform installation/support and UI remain separate gates.

## Executed evidence

On the final frozen runtime/test/workflow sources: **879 tests, 866 passed and 13
platform exclusions**, in 95.797 seconds on Windows/Python 3.13. The initial 36 new
contracts fail on the isolated merged-PR83 baseline (51 failed assertions and 24
errors including subtests, one exclusion); these are not 75 independent defects.

The final cold integration passes 2 API processes, 11 CLI processes (including
two legacy aliases), 23 active-entry refusals, configured profiles and one actual
concurrent SQL writer. The original-EML full no-egress local-storage integration
also passes (5 API/6 CLI, stopped supervisor, verify and ZIP/input bytes preserved).
The actual wheel matches all 91 sources, metadata, entry points and two templates.

During this block, the general suite plus 21 existing/new Sentinel/legacy/wheel
integration scripts passed serially. The final refinements only tighten Windows
literal aliases and pre-I/O mode/selector admission; the general suite, new cold
integration, original-EML storage family and wheel were repeated afterward.
The remaining integration matrix is earlier block evidence; GitHub CI runs the
committed workflow independently. POSIX-only behavior remains a CI boundary.

Runtime/test/workflow hashes (233 files) were frozen and rechecked before docs.
Private originals and validation artifacts stay outside Git. Constructed fixtures
are regression contracts; a real full run and matching seal establish execution
and preservation, not classifier accuracy or attribution.

## PR84 review verification

Four founded P2 findings are corrected in the same family: explicit null config
profiles, caller-owned config aliases after publication, the fixed HTML serializer
ceiling and per-case directory counters. Five added regression tests fail on the
initial PR84 head (five failed assertions including subtests and one HTML error).
They pass after the fixes, including actual JSON+HTML files individually above
64 MiB under a 192 MiB profile, with no serializer/I/O stub. The family now has
41 new contracts. Read-profile output limits apply equally to HTML serialization;
the combined publication limit still applies after escaping/formatting.

After these corrections, the general suite, cold completion, original-EML storage
family, configured admission, geographic, local-file, hash-failure, verification-error,
both relevant legacy integrations and actual wheel checks all pass serially on
frozen sources. Static contracts are repeated after documentation-only changes.
