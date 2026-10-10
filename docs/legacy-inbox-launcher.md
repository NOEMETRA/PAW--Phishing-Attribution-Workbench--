# Legacy inbox launcher

`tools/analyze_inbox.py` previously read a hardcoded private filename, followed
short links and invoked `CriminalHunter` directly, including when imported.
It did not expose no-egress, process budgets, sealed cases or job accounting.
Its JSON output in the source tree was not a supervised full-analysis result.

The script now delegates to the supported `paw full` CLI with `--no-egress`
always enabled. It requires an explicit file or directory; the old fixed filename
and `paw/intelligence/last_hunt_multi.json` output are no longer used.

```powershell
python tools/analyze_inbox.py C:\protected\samples --deadline 180 --stage-timeout 60
python tools/analyze_inbox.py --help
```

As with `paw full`, output goes into `cases/` and `jobs/` under the current
working directory. The strict profile, exports, process-tree supervision,
original MIME preservation, sealing and partial-batch accounting are shared with
the CLI. A failed or timed-out job exits nonzero. Importing the script starts no
analysis and changes no working directory or arguments. No network-enabled option
is provided by this adapter; detonation and remote enrichment remain explicitly
skipped. The Python offline guard is not OS isolation.

`python tests/integration_legacy_inbox_real.py` uses actual processes and workers,
without mocked analyses. It checks an inert import even with the old fixed input
present, single and mixed-extension directory analysis, filenames after `--`, an
invalid MSG causing honest partial results, a short enforced deadline and argument-only exits. It
verifies original bytes, evidence seals, strict/offline requests and stopped
process trees. Constructed messages are regression fixtures, not accuracy data.

A private replay of 20 original EMLs through this launcher completed offline with
matching original bytes and valid seals. Scores and decisions matched the prior
supervised CLI replay; all 20 attribution decisions remained Inconclusive. The
180 compared evidence JSONs matched apart from the independently reproduced
per-run domain-age reference. This establishes entry-point parity, not classifier
accuracy, a speedup or a reproduction of the historical four-hour online run.

This is a focused correction to one legacy email-analysis entry point. Standalone
detonation, canary, Sentinel monitoring/geographic commands and other repository
scripts have not been brought under the supervised email worker by this change.
The separate Linux lab and further UI work remain deferred.
