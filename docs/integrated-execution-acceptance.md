# Integrated execution-family acceptance

Measured on merged PR84, `9a6e9763de568f310548d25aa66b212853279d31`,
23 October 2026 (Europe/Rome), Windows/Python 3.13. The merge tree
`f0558c15c3816907751fba57d5f9ee45ce205137` matches reviewed head `05e28fe`.
All three GitHub checks passed on both that head and its actual merge. PR84's
five founded P2s were reproduced and corrected before merging; the final Codex
review has no findings or unresolved threads.

This is consolidated acceptance of existing execution/ingress flows (S01/S02)
and their stopped-case publication consumers (S08). It does not close every
extraction, interpretation, platform or release requirement. Runtime speed and
the historical four-hour online workload are not acceptance targets here.

## Executed matrix

The five existing integration scripts ran serially on that one merge, with no
runtime/test/workflow edits during validation. All passed. Every email analysis
runs under no-egress: `quick` forces it and the other presets request it
explicitly. HTTP targets are owned loopback servers. Fixtures are
actual inputs processed by real workers, not simulated analysis results.

| Existing integration | Observed scope |
| --- | --- |
| `integration_engine_stress_real.py --suite all` | 24 CLI scenarios, 95 completed cases with verified seals; five presets; original repository EML repeats; mixed-case extensions; empty and mixed invalid batches; unsupported MSG; batches of 5/20/50; 100/1,000 URLs; 512 KiB/1.8 MiB text; 300 attachments; 12 MiB attachment; oversized input and MIME-part rejection. |
| `integration_api_real.py` | Actual HTTP worker on an original repository EML, case/list/query/ZIP and report checks; invalid upload/MSG, worker timeout, queue deadline, queued/running cancellation and completed-job preservation. |
| `integration_cli_api_real.py` | Shared CLI/API directory, actual live CLI worker and reader/query admission, eight completed original-byte cases, local Sentinel access after stopping, verify/ZIP, then actual supervisor termination and recovery before partial seal/export. |
| `integration_api_recovery_real.py` | Actual API readers and partial sealing on deliberately truncated stopped artifacts. This is a damaged-artifact fixture, separate from the actual process termination above. |
| `integration_deobfuscate_input_real.py` | 35 standalone CLI invocations and a real input-helper audit: byte/hash provenance, BOM/CRLF/Unicode/literals, invalid UTF-8/ambiguous/oversized/nonregular inputs, numeric bounds, deadline stop, UNC/literal admission and cwd shadows; another original-EML full validates common-parser compatibility. |

The mixed invalid EML and MSG batches report `partial`, with successful/failed
inputs accounted separately. All 24 CLI scenario expectations pass, including
nonzero exit for requested rejection; a rejected input is not a completed case.
The harness checks supervisor `tree_stopped`, observed residual processes,
case integrity and blocked-operation records. Existing unavailable STIX and
correlation outputs remain visible rather than inferred successes.

After all matrix writers stopped, a separate read-only postflight compared all
95 completed CLI `input.eml` digests with the report's source inventory digests,
recorded case digests and the source bytes still present. All match. Every one
of those manifest policies and execution records has `no_egress: true`.
This establishes copy correspondence at the observation times; it does not
establish source authenticity or an unobserved history of source immutability.
The API integrations separately compare before-run original bytes with actual
case/ZIP bytes. Matching seals establish integrity, not authentication or accuracy.

233 runtime/test/workflow hashes were frozen and rechecked after validation;
the Git worktree was clean before this documentation-only checkpoint. Public
originals and constructed regression fixtures were used; private mailbox EMLs
and raw validation artifacts are not committed. No production change was needed
to make this measured matrix pass.

## Reproduction and evidence limits

From a checkout with the documented engine/test dependencies installed, run the
following scripts in order, setting `PYTHONDONTWRITEBYTECODE=1` and `PYTHONPATH`
to the repository root. Use the same Python executable for the whole matrix.

```text
python -B tests/integration_engine_stress_real.py --suite all
python -B tests/integration_api_real.py
python -B tests/integration_cli_api_real.py
python -B tests/integration_api_recovery_real.py
python -B tests/integration_deobfuscate_input_real.py
```

The stress script prints its unique external data/result path; `--output PATH`
can select the result JSON destination. Inspect each exit code and the recorded
scenario expectations. The additional 95-copy comparison above was a separate
postflight of those retained source/case files, not a new assertion added to the
stress harness in this documentation change. Other scripts use their documented
external/temporary storage. CI evidence is separate from this consolidated
Windows run; passing Linux workflow steps do not substitute for an unexecuted
platform-specific scenario.

The no-egress guard is application policy, not OS network isolation. Windows Job
containment in observed shutdowns does not establish network containment. Bounded
load fixtures, observed process stops and matching copies do not validate every
malformed input or optional provider. No sample URL, attachment or external
collector was visited/executed to produce this evidence.

## Remaining gates

- Keep malformed top-level EML admission and its CLI/API failure or partial-batch
  accounting explicitly open. Reconcile it and the remaining S01 source-kind,
  local-key and numeric combinations with focused contracts; this matrix is not
  an exhaustive ingress cross-product.
- Reconcile extraction-to-report evidence, omissions and unavailable capabilities
  across S03-S09; remaining renderer/resource and optional-format contracts retain
  their own closure criteria.
- Complete current-version isolated installation and supported-platform/component
  acceptance (S13). This checkout matrix is not an installed-wheel test.
- Independent labels, holdout and calibration remain S10; folder membership or
  constructed phishing-like content is not ground truth.
- Controlled Windows/Linux isolation, actual active lifecycle/providers/collection
  remain S14; UI parity follows the engine and egress gates.

The supported offline Sentinel family is integrated with its stated boundaries.
This execution matrix is accepted within the scopes above. The remaining register
is finite; further production changes require a reproduced defect or an explicitly
justified existing-capability gap.
