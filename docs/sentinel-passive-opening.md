# Passive Sentinel database opening

On merged PR45 (`059faae`), an actual `monitor list` invocation with no database
created `sentinel.db` and displayed an empty campaign list. Opening an existing
legacy file through the default constructor also added tables and migration
columns before reading. These are appropriate writer initialization operations,
but not passive examination of saved storage.

## Supported saved-data path

`CampaignDatabase(path, read_only=True)` now admits an existing local file with
SQLite `mode=ro` and `PRAGMA query_only=ON`. It skips directory creation, table
initialization and migration. The bound absolute file path is encoded as a file URI,
so filename characters are not interpreted as SQLite connection options.
Connections are closed after use and recheck admission on each open. A missing
file/parent, directory or corrupt file is an error, not a new empty database.
An empty or unrelated SQLite schema is not repaired: a reader requiring an
absent table raises an error. This is not comprehensive schema validation.

The supported path is a saved, quiescent rollback-journal database. WAL-mode
headers and existing `-wal`, `-shm` or `-journal` sidecars are rejected before
SQLite opening. Read-only WAL access can create/update shared-memory files;
ignoring a WAL with immutable mode could omit committed observations. This
patch does neither. It does not checkpoint, delete sidecars, recover journals
or change journal mode. Preserve the whole original storage set; preparing a
consistent snapshot from a live/WAL database needs a separate supported workflow.
The admission check does not prove that external writers are stopped or freeze
another process: no atomic forensic snapshot/concurrent-writer claim is made.

The default writable constructor still initializes/migrates accepted storage;
the later [configured storage contract](sentinel-configured-storage.md) makes
that schema work transactional and rejects unrecognized nonempty namespaces,
aliases, replaced/missing targets and ambiguous configuration. Source binding
checks do not establish an atomic cross-process snapshot. SQL writes by the existing mutators fail
on read-only connections. This mode protects the main database from writes; it
is not a general sandbox for arbitrary caller-supplied SQL or filesystem access.

The [named interaction decoder](sentinel-database-rows.md) also reads original
fifteen-column and partially migrated tables without modifying them. Missing
`interaction_type`, `interaction_confidence` and `interaction_indicators` are
null. They do not receive migration defaults or fabricated confidence. Existing
JSON fields follow the [stored-JSON source/outcome contract](sentinel-json-evidence.md);
raw source and fallback status are exposed by the database readers. Other missing
required columns are not silently filled in.

## CLI consumer and verification

PR46 switched `paw monitor list` to this mode. It reads the configured database
path (default `sentinel.db`) and lists stored active campaigns, without
constructing/importing the monitor or intelligence collectors. A missing,
unsupported or damaged database exits nonzero and does not claim that no
campaigns exist. It prints stored URLs without visiting them. Its existing
active-only filter remains; this is not an exhaustive export or runtime-service
status check. The start/stop and writing/checking actions, geographic commands
and external scripts retain their current admission and remain registered for later audit.
The later [stored-status correction](sentinel-status.md) also switches
`monitor status` to passive admission and replaces the statistics placeholders.
Start/stop lifecycle behavior is not validated by either passive command.

Nine new actual SQLite contracts cover no creation/migration, existing source
rows on all sixteen ordered legacy/partial layouts, missing-field nulls,
repeated readers, handle closure, existing mutator rejection, special filenames,
missing/corrupt/empty storage and WAL/journal rejection on initial/later opens.
The previous seven row-mapping contracts also pass. An actual CLI integration
checks seven working directories: default/configured missing paths, current
schema, legacy storage without the interaction table, corrupt/empty files and
real WAL mode. File names/content remain unchanged on success and rejection.
After common CLI bootstrap, dispatch under offline policy attempts no blocked
network/subprocess operation and imports no Sentinel monitoring/enrichment
modules. Cold dependency imports are outside that dispatch check, as in existing
CLI integrations; it is not an OS isolation or cold-start egress guarantee.

On local Windows/Python 3.13, the general suite passes 636 of 644 tests with
eight platform exclusions. The existing original-EML CLI/HTTP no-egress
regression also passes: index/query preservation, evidence-reader admission,
stopped-case verify/export and supervisor-crash recovery. A real rebuilt wheel
matches metadata/entry points and all 90 package Python sources. These are
regression/package checks, not a clean dependency installation or comprehensive
validation of Sentinel reports or the other CLI actions.

Stored campaign URLs, risk, geographic and interaction labels remain unverified
observations/claims. Read-only access does not authenticate them. These are
real storage/CLI regression checks, not live collection or classifier accuracy
evaluation. S11 remains open for other reader/statistical/report/lifecycle
consumers and end-to-end provenance propagation; active monitoring is S14 work.
