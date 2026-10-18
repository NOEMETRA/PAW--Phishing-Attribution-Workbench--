# Legacy interaction diagnostic

This is an optional diagnostic for existing saved data. Its present role is
passive inspection; future collection, behavioral investigation or cross-case
extensions require a separate investigative need and validation plan. They are
deferred while PAW's email-analysis engine is stabilized.

`python /path/to/checkout/check_victims.py` reads the configured existing Sentinel
database relative to the current working directory and prints the existing
`CampaignDatabase.get_victim_statistics()` report as JSON. Normal project
dependencies are required. The script does not change the working directory,
initialize/migrate storage, import a network collector or run analysis.

Only an absent `sentinel_config.json` selects the default `sentinel.db`. A present
configuration is read once with errors propagated; it must be a JSON object with
a nonblank string `storage.database_path`. Unreadable files/directories, invalid
UTF-8/JSON, duplicate keys, NULL or missing/invalid storage selection fail rather
than silently reading an unrelated valid default database. This script-local
selection leaves the shared `SentinelConfig` compatibility behavior unchanged.

Previously the script changed into a personal Windows directory at import time,
constructed the default writable database, read a latest-100 preview and printed
its length as a total. It looked up nonexistent `ip_address`, `user_agent` and
`timestamp` keys, substituting `N/A` for available `victim_ip`, `victim_ua` and
`click_time` sources. Its five displayed rows were a slice of that preview.

The diagnostic now runs only under its main guard or an explicit `main()` call.
Help and invalid arguments are handled before Sentinel/configuration access.
Accepted execution uses the existing read-only storage admission and complete
statistics reader. Output intentionally changes from a five-row text preview to
the full existing report, including all source records, typed original JSON
storage/decoding evidence, literal counts and unavailable interpretation reasons.
Missing or corrupt storage/configuration, incomplete schema, WAL/pending journals
and unsupported native JSON values fail nonzero without a partial report. A
healthy empty database instead yields a successful report with zero rows.

Legacy report keys such as `total_victims` are compatibility names. The report's
`evidence_scope`, `count_scope` and `unavailable` fields explain that counts refer
to stored rows, not people or authenticated visits; identity, calibrated risk and
recent-event interpretation are unavailable. Stored timestamps remain unverified
source strings, user agents are retained completely and absent values remain NULL.

`check_db_fields.py` is a checkout alias for the same diagnostic. Its former
hardcoded database/case and latest-50 field projection are removed. Its output
intentionally changes from an array of selected fields to the existing complete
report object, with stored fields in `source_records` and their JSON provenance.
It inherits the same configuration, read-only admission, arguments and errors;
no reader, schema, collector or option is added. Baseline guarded runs showed
50 of 210 matching stored rows, selection of an unrelated one-row default over
the configured 210-row source, and database creation even with `--help`.

`tests/integration_legacy_interaction_check_real.py` runs the same matrix against
both actual scripts: 44 processes in total, comprising 42 cold guarded
diagnostic/argument/import paths and two direct saved-source executions outside
the checkout without host `PYTHONPATH`. The alias fails the shared source-parity
regression before the repair and passes after it. Actual
saved/default/configured/empty/legacy and error sources remain byte for byte
unchanged. Two 210-row fixtures verify complete source ordering beyond the old
100-row cap, actual IP/UA/time fields, NULLs, duplicate-key JSON and invalid UTF-8
TEXT provenance. JSON output equals the existing full statistics API report.
Malformed native scalars fail without stdout data. Help/invalid options/import
preserve a malformed configuration without importing Sentinel. No CLI bootstrap,
collector imports, new threads or blocked operations occur in guarded processes.
The directory/empty-object/NULL/duplicate-path configuration regressions keep a
valid unrelated default database alongside the failing selection. A separate
explicit read-denial injection checks error propagation with real SQLite and
unchanged source bytes; it is not a Windows/POSIX ACL enforcement proof.

This dispositions two S12 scripts. Package readers/writers and the report schema
are unchanged. Existing complete-reader resource limits, concurrent-writer
snapshot guarantees and broader configuration/link admission remain open; the
Python guard is not OS isolation. No classifier accuracy, identity, authenticity
or new attribution capability follows from this diagnostic.
