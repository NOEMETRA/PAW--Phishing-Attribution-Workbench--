# Local file-monitor admission

Current contract update: The later contract admits single-link regular files only, includes hidden/`.pyc` bytes, and bounds directories/depth/output. Historical filename exclusions below are superseded. Known ancestor and output-root admission remain distinct from an OS snapshot. See
[supported offline Sentinel completion](sentinel-offline-completion.md). Earlier
evidence and counts below remain historical.

`monitor files` and `monitor integrity` dispatch directly to `FileMonitor` without
constructing `SentinelMonitor` or loading campaign configuration/storage.
`FileMonitor` no longer initializes a campaign database by default; an explicitly
injected database object remains available as `db`, but these file checks do not
use it. Existing Sentinel databases, configuration and sidecars remain untouched.
Local-file results are independent of missing or malformed unrelated Sentinel
configuration or database storage.

Every case-file listing and Merkle check uses the shared `require_stopped_case`
admission before checking seals or reading file bodies. A selected case with a
running/queued/recovery-blocked owner or without confirmed tree shutdown raises
an explicit error. Missing ownership source state also propagates as an error.
Both all-case methods preflight the selected cases before generating results or
advancing any in-memory baseline, and case readers recheck admission. The change
does not stop workers, recover jobs or seal cases. It is not an atomic snapshot
or a lock against concurrent writers; shared ownership discovery retains its
existing documented limits.

Previously, both commands created campaign storage on an empty directory and
could fail on unrelated configuration. More seriously, an actual suspended
original-EML worker with a live supervisor was still admitted: both commands
returned success and reported an already sealed case as integral while the job
remained running. The repaired commands reject that same ownership state before
producing case results. Per-case admission failures cannot become a healthy empty
change list through exception swallowing.

File-change comparison still uses this instance's in-memory baseline. The CLI
states that its first scan is not historical change detection; an empty returned
list is reported as no case observations returned. It does not establish absence
of tampering. The existing `ok`/`compromised`/`unknown` compatibility labels describe
verification outcomes, not authenticated email claims or a proven intrusion.
Missing seals remain unknown. No report is persisted to a campaign database.

The original admission repair was not a replacement inventory engine. The later
[local storage family](sentinel-local-storage-family.md) binds relative roots once,
rejects parent/absolute case IDs and linked/reparse/special-file paths, adds
selected file/count/byte limits, checks metadata correspondence around reads and
serializes same-instance baseline scans. Existing hidden-name/pyc exclusions
remain; counts are scoped observations rather than a complete forensic inventory.
The [hash-read failure correction](sentinel-file-hash-failures.md) and
[directory-read repair](sentinel-directory-read-failures.md) still propagate
ordinary read failures and preserve baselines; final-source regressions retain
these contracts. Broader resources and cross-process snapshots remain open. Seal
verification [exceptions now remain unknown](sentinel-verification-availability.md);
shared verifier semantics retain separate S08 limitations, including unsupported proof
authenticity claims.

`test_sentinel_local_files.py` exercises actual files and stored ownership-state
fixtures: default/injected construction, every case reader, missing owner state
and whole-selection preflight without partial baseline advancement. Those state
fixtures are not a claim that a process is live. `integration_sentinel_local_files_real.py`
checks 18 cold CLI processes with empty/missing case roots, real constructed
sealed/tampered/unsealed cases and unrelated damaged/legacy/WAL/journal/config
sources. Every source-tree byte remains unchanged and no campaign/configuration
or collector module is imported by dispatch.

The extended `integration_cli_api_real.py` uses the original EML and actual
no-egress CLI worker/API flow. Both commands reject the identified live worker,
then succeed on all eight completed cases without creating campaign storage or
changing case bytes. Existing supervisor-crash recovery remains exercised.
Cold CLI bootstrap precedes the application guard where applicable (urllib3
probes a local IPv6 socket); this is not OS isolation, classifier accuracy or
authenticity attestation. Other campaign management/listing disposition remains
S11, external entry points S12, active lifecycle/collection S14 and UI S16.
