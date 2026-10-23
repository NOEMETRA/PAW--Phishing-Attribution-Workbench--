# Stored Sentinel intelligence report

Current contract update: Shared query/JSON/output budgets now apply to the passive report family. Active helpers refuse under no-egress before I/O; their algorithms remain deferred S14/S10. See
[supported offline Sentinel completion](sentinel-offline-completion.md). Earlier
evidence and counts below remain historical.

This S11 correction follows merged PR49 (`ff86c77`). It changes only the stored
intelligence-report path in `paw/sentinel/intelligence_analyzer.py`; geographic
renderers, CLI actions, other statistics and active collection remain separate.
Actual SQLite reproduced an `AttributeError` on any selected row because
`_is_recent_victim` did not exist. An older case outside the newest-100 listing
window instead returned zero rows and another case's 105-row network grouping as
`attacker_infrastructure`, with an urgent investigation recommendation.

## Admission and complete sources

```python
report = IntelligenceAnalyzer(db_path, read_only=True).generate_intelligence_report(case_id)
```

The existing [passive boundary](sentinel-passive-opening.md) admits saved storage
without initialization, migration or IP/plot imports. Missing, corrupt,
incomplete and pending-journal/WAL storage does not become an empty report.
The default writable constructor remains unchanged; callers seeking passive
admission must use `read_only=True`. No new CLI action or output file is added.

The report uses PR49's uncapped selected-row reader: `None` selects every row;
every string, including empty or quoted identifiers, is an exact binary SQL
selection before decoding. Other types are errors. Rows are ordered by stored
`click_time` descending, then `id` descending. A valid empty inventory is allowed.
Unrelated invalid rows do not interfere with a selected case. Errors in selected
rows abort construction rather than returning an undeclared partial report.

Schema version 1 adds `source_records`, every selected named reader record,
including original timestamp strings, IP/UA, scores, interaction/correlation
labels and [typed JSON sources/decoding outcomes](sentinel-json-evidence.md).
No rows are dropped merely because their stored JSON cannot be interpreted.
Source metadata/user agents are unredacted; this method returns a dictionary and
does not publish or save it. Unsupported native non-JSON BLOBs/non-finite numbers
fail strict JSON serialization, as in the [forensic export](sentinel-forensic-export.md).
Typed support for every non-JSON column and storage/output resource budgets
remain open. Passive admission does not freeze external writers or establish
source history, authenticity, custody or integrity of an independently acquired file.

## Descriptive counts and unavailable conclusions

`status: success` means the selected stored report was constructed.
`evidence_scope: stored_rows_unverified` qualifies its contents. Stored status,
scores, countries, interaction labels and operator/correlation claims remain
unauthenticated. Counts refer to rows, not unique people or confirmed events.

| Output | Meaning |
| --- | --- |
| `summary.total_victims` | Compatibility name for the complete selected row count. |
| `summary.analyzed_victims` | Rows whose stored `analyzed_status` literally equals `analyzed`; no proof an analysis occurred. |
| `summary.stored_score_at_least_7` | Finite stored numeric scores at least 7 across selected rows; no calibrated risk threshold. Missing/text scores are not converted to zero. Negative or out-of-range stored numbers remain literal data. |
| `status_breakdown` | Counts of literal stored string statuses, including an empty string; non-string statuses are listed as unusable. |
| `risk_distribution` | Literal numeric scores for rows with stored `analyzed` status. Keys are string representations of stored numbers, so JSON round trips preserve the contract. |
| `geographic_distribution` | Literal nonblank country strings from successfully decoded JSON objects in rows with stored `analyzed` status. No country resolution/normalization, verified location or synthetic `Unknown` country. |

`aggregation_evidence` identifies source fields, counted/numeric IDs and unusable
IDs within each stated scope. Missing/malformed/duplicate/non-finite JSON, JSON
null, wrong shapes and blank/nonstrings stay in `source_records` and do not become
geographic observations. A fallback `{}` is not treated as successful decoding.
These lists let callers trace omissions and counts to the retained rows.

Compatibility `high_risk_victims` and `recent_victims_24h` are now null, with
reasons in `unavailable`. A stored score is not calibrated risk; no validated
timestamp interpretation exists for the former broken recency path. Original
`created_at` values remain available without invented recent/not-recent decisions.
`generated_at` records report construction time, not a source event.

`attacker_infrastructure` and `recommendations` are empty with explicit
unavailability reasons. The report no longer invokes the global SQL IP-prefix
correlator or recommends operational actions from it. IP similarity and stored
geographic/interaction labels cannot establish an attacker network. Original
`attacker_correlation` fields remain intact beside their unverified JSON sources.
An empty unavailable list must not be interpreted as proof there are no attackers
or that the source is safe. Other correlation/classification methods are not
certified or changed by this report correction.

## Verification and remaining work

Nine actual SQLite contracts cover complete 212-row/case inventories, selected
source fidelity through an actual JSON file, literal case admission, unsupported
shapes/scalars and traceable omissions, legitimate empty storage, uninterpreted
timestamp variants, all sixteen legacy/partial layouts without migration,
missing/corrupt/incomplete/later-journal errors and unrelated-case isolation.
Fresh guarded processes check full 210-row and older-case 105-row JSON files,
empty/missing/corrupt/incomplete/pending storage, exact source correspondence and
unchanged storage trees. Expected IDs come from fixtures and individual lookups,
not a potentially capped report/list oracle. No requests, collector or plotting
imports or blocked network attempts occur in those passive processes.

On Windows/Python 3.13, all 51 Sentinel contracts pass. The complete serial suite
runs 679 tests: 671 pass and eight platform exclusions. Existing original-EML
CLI/API no-egress, stopped exports and supervisor-crash recovery pass. A rebuilt
wheel matches metadata/entry points and all 90 package Python sources; this is
not a clean dependency installation.

These are constructed regressions, not attribution/classifier ground truth or
OS isolation. S11 remains open for geographic report admission/provenance,
remaining statistical consumers, SQL JSON filters, typed non-JSON storage,
resource limits and lifecycle checks. Active egress is S14; UI work is S16.
