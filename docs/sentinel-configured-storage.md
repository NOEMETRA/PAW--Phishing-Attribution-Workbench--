# Configured Sentinel storage admission

This family covers configuration loading/publication, database source admission
and schema initialization. It extends the named [local storage contracts](sentinel-local-storage-family.md)
without enabling a monitor, collector, detonation or UI.

## Configuration selects a source

Only a missing configuration or a valid empty object selects defaults. A present
unreadable file, malformed JSON, non-object root, duplicate keys, non-finite
numbers or invalid storage section/path fail. They cannot silently select the
default database. Configuration source reads and encoded saves are limited to
1 MiB, with actual consumed bytes and before/after metadata checked. This is not
a bound on every parser, publisher or engine resource.

Configuration filenames and the working-directory base for relative database
paths are bound at construction. `get('storage.database_path')` and
`get_storage_config()` return the resulting absolute database path; the JSON
source and its relative path spelling remain unchanged. Relative paths remain
relative to the construction working directory, not the configuration's parent.

`set` and `reset_to_defaults` prepare/validate a candidate before mutating memory
or source. A complete temporary file in the same directory is published with
`os.replace`; failed encoding, temporary writing or replacement preserves the
prior source and in-memory configuration. The loaded source fingerprint is
rechecked before publication; changed/replaced sources require reload. Successful
publication updates the fingerprint and memory without a fallible target read
after the rename commit. This is not a power-loss durability or multi-process
compare-and-swap protocol. Metadata-preserving edits/transient path swaps are
not generally detected; ctime is excluded from configuration fingerprints because
rename can change it. Permissions/ACL parity across platforms is not established.

## Literal filesystem and database identity

The shared private admission helpers accept literal local filesystem paths.
Blank/NUL paths, SQLite `:memory:`/`file:` forms, recognized UNC/device and
drive-relative Windows forms fail before storage access. They are not connection
options. SQLite URI construction uses the escaped absolute path, so literal
`#`, `%`, Unicode and option-like filename text cannot become URI parameters.

Known ancestors must be directories; symbolic links, Windows reparse points and
selected special files fail. Multiple hard links also fail: an alternative
database basename could conceal a journal belonging to the same physical file.
This policy concerns configured database/configuration files, unlike the separate
FileMonitor observation policy which retains regular hard-linked files per path.
Mapped/mounted storage and hostile filesystem races are not OS containment.

Database instances pin the admitted file's device/file identity. Later reads or
writes reject disappearance or replacement rather than silently recreating or
adopting another database. Established connections use escaped `mode=rw`/`mode=ro`,
never SQLite's implicit-create mode. Ordinary committed data/schema changes on
the same file remain visible; source identity is not a frozen content snapshot.
Checks around SQLite connection opening are not an atomic descriptor-binding
guarantee against all concurrent path swaps.

## Initialization and journal effects

Only construction of a writable instance can create a missing database, through
exclusive file creation. The newly created descriptor's identity must match the
selected pathname before initialization. Existing sources and every passive
opening reject WAL mode or any WAL/SHM/journal pathname, including dangling links,
instead of recovering/checkpointing saved storage. Established writable instances
still use ordinary SQLite journaling/locking for their explicitly requested
operations; this does not certify concurrent constructors or hot-recovery policy.

Initialization begins an explicit `BEGIN IMMEDIATE` before CREATE/ALTER. Existing
named storage objects must be tables, not views.
Nonempty schemas without any of the four recognized storage objects are rejected
without conversion; empty schemas remain valid initialization targets. This is
a basic namespace admission check, not proof of database identity.
Table creation and the existing three-column migration commit together; failure rolls back prior DDL/rows. This
does not validate every arbitrary legacy column/constraint/trigger schema.
Failed initialization retains a newly created target and its parents for
inspection. No database pathname is unlinked: another initializer could acquire
the same file after rollback. A rolled-back fresh target can be empty; retained
artifacts are not evidence of successful initialization. No recursive cleanup is
performed.
Passive construction still performs no table creation or migration.

## Verification and remaining work

`test_sentinel_storage_admission.py` exercises actual SQLite/filesystem sources,
schema rollback, failed candidate publication, hard-link aliases, source
replacement/disappearance, working-directory changes and strict configuration.
URI/network-form probes forbid directory/SQLite access; FIFO probes forbid body
opening. These are declared regression fixtures, not real target activity.
An initial legacy Windows URI probe left an NTFS fixture; its stream/metadata
were privately archived with a hash and the fixture removed. The final invalid
path probes prohibit access rather than reproducing that side effect.
Unprivileged symbolic-link and POSIX FIFO checks depend on host support.
The 21 contracts against baseline modules fail 38 assertions and two errors
including subtests, with two Windows platform skips. Final general suite:
811 tests, 799 passed and twelve skips, 85.585 seconds. An actual offline wheel
matches all 90 current package sources, metadata, entrypoint and both review
templates. Only configuration/database package sources change; the other 88
Git package sources are unchanged.

`integration_sentinel_admission_real.py` checks 46 cold CLI and four API processes:
invalid configurations cannot create fallback storage, failed saved-source
initialization preserves bytes, valid configured add/list/status/remove affects
the selected database, and failed API migrations/publication preserve sources.
The original-EML storage-family integration and existing campaign/passive/report
consumers are regressions on the same version. Analyses use `--no-egress`; only
explicit local loopback is allowed where used by existing integrations. On the
reviewed source, the original-EML integration passes five cold API and six CLI
processes after a real stopped full worker, preserving every original case/input
byte through CLI verification and ZIP export. Earlier campaign/passive/geographic
consumer regressions also pass during this block.

The first PR CI exposed an outdated cold-reader integration assertion: importing
the shared path helpers from `config` was rejected as if it constructed a
configuration. The campaign-layout and history-layout probes now forbid
`SentinelConfig` construction while permitting the helper import. Their existing
network, thread, active-module and source-byte checks remain. Both corrected
integrations pass locally: five API/23 CLI campaign processes and six API/six
status CLI history processes. This correction changes tests and their evidence
record only; package sources remain identical to the full/wheel-tested version.

Broader stored JSON/report rendering and resource limits, other intelligence
writers, cross-process snapshots and final engine/platform/installation gates
remain open. This source-admission contract is not authenticity, attribution,
classifier accuracy or OS isolation evidence.
