# Legacy attribution, countermeasure and dossier publication

The five external conclusion publishers are unavailable:

- `util/attribution_confirmation_engine.py`
- `advanced/attribution_confirmation_engine.py`
- `util/deception_countermeasure_engine.py`
- `advanced/deception_countermeasure_engine.py`
- `advanced/strategic_correlator.py`

On declared stored CSV/filesystem fixtures, all five launchers returned success
after overwriting analyst notes and invalidating an existing seal. The three
advanced launchers also created reports for nonexistent cases. The advanced
attribution matrix assigned 0.3 confidence and 0.95 integrity without evidence.
Countermeasure products included fixed confidence, example.com
monitoring endpoints or `monitoring_enabled: true` without deploying a service.
The dossier copied unverified legacy conclusions and labeled an earliest saved
request as where everything started; it did not establish an attack origin.
No target, real service or independently labeled actor was used for these proofs.

## Boundary

Each `main(argv=None)` now parses legacy syntax and rejects with exit 1 before
source, profile, token or output access. Exact help exits 0; missing/unsupported
arguments and long-option abbreviations exit 2. Base attribution retains exact
`--output/-o`; base countermeasures retain required `--profile/-p` and
`--output/-o`. The dossier retains exact `--disable-country-detection` and
`--place-tokens-file`. These options do not enable processing or publication.
Imports are inert; direct checkout invocation needs only the standard library.

Sixteen principal APIs raise `RuntimeError` before inspecting arguments:

- Base attribution: `analyze_real_attribution_evidence`,
  `generate_real_confidence_matrix` on `RealScientificAttributionEngine`.
- Advanced attribution: `confidence_matrix`.
- Base countermeasures on `RealDeceptionEngine`: `create_real_honeytokens`,
  `design_real_deception_network`, `setup_real_monitoring`,
  `create_real_fake_services`, `create_real_traffic_redirectors`,
  `deploy_real_honeypots`.
- Advanced countermeasures: `create_honeytokens`, `design_deception_network`,
  `counter_intel_ops`, `adversary_manipulation`, `write_outputs`.
- Dossier: `build_dossier`, `write_markdown`.

There is no tracked production consumer of these modules outside their own
definitions. Other prototype helper algorithms remain unchanged and unvalidated;
this boundary does not certify their lower-level scores, strings, file traversal,
resource use or provenance. They are retained for inspection, not advertised as
supported extraction, attribution, deployment or evidence verification.
Existing original artifacts are preserved; the package's separately documented
offline evidence extraction, verification and export remain available. No new
model, collector, active defense service or replacement dossier is introduced.

## Sixth external Python file

`util/validators.py` is an unused helper library with no operational main/CLI or
identified tracked production consumer. Its source has an explicit unsupported,
unvalidated disposition; algorithms are unchanged. Inert import is checked, not
URL/path security correctness. `paw/util/validators.py` is a separate package
helper and remains open under S00/S13. Neither is the validated universal PAW
admission framework. Any future consumer needs its own input and failure contract.

This completes dispositions for the 26 external Python files, not validation of
every helper function. The two shell launchers remain deferred S13/S14 work;
S12 must not be reported as fully closed while those dispositions remain open.

## Verification and limits

`test_legacy_conclusion_boundary.py` checks saved/missing/malformed sources,
output aliases aimed at source/profile/new paths, missing profile/token paths,
sixteen opaque-argument API rejections, exact help/errors/prefixes and inert
imports. Seven contracts fail before repair and pass afterward.
Before repair: 20 failures and 132 errors including subtests. The general suite
then passes 772 tests (764 passed, eight platform skips). All 90 package Python
sources are unchanged; the actual offline wheel matches sources, metadata,
entrypoint and both review templates. Fifty retained helper functions have
unchanged ASTs; the validator changes only its module documentation.

`integration_legacy_conclusions_real.py` runs an actual original-EML full analysis
with `--no-egress`, confirms its supervisor tree stopped, then tests cold guarded
launchers/APIs and direct stdlib invocations from outside the checkout. Completed,
sealed, unsealed, malformed, missing, outside and declared ownership-state
fixtures retain bytes, notes, seals and process state. Actual CLI verification
and ZIP export preserve every original case file and input EML.
This run passes 200 cold guarded processes, 31 direct stdlib invocations and one
inert validator-library import; guarded probes observe no source/output I/O or
blocked network attempts.

Audit hooks prohibit source/output I/O for guarded child probes; they do not
cover every metadata syscall or establish OS isolation. Owner metadata fixtures
are not live workers. The original email does not supply ground truth for actor
identity, origin, countermeasure efficacy or classifier accuracy. Whole-engine,
resource, installation/platform and independent evaluation gates remain open.
