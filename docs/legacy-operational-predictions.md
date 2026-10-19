# Legacy operational predictions

Both `util/operational_pattern_predictor.py CASE_DIR [--output OUTPUT | -o OUTPUT]`
and `advanced/operational_pattern_predictor.py CASE_DIR` report unavailability
before source/output access. Exact help exits 0, accepted arguments exit 1,
missing/unsupported arguments and long-option prefixes exit 2. The base retains
both exact output options without opening their paths. Imports are inert and
`main()`/`main(argv)` support stdlib-only direct invocation.

The base `ThreatActorBehaviorModel.predict_infrastructure_evolution` method and
the advanced `build_evolution`, `build_actor_timeline`, `predict_targets`,
`countermeasure_effectiveness` and `write_outputs` APIs raise `RuntimeError`
before inspecting arguments. NumPy is no longer imported by the unavailable
boundary: its two existing numerical helper methods import it only if explicitly
called. Their arithmetic is unchanged. Other prototype helpers remain
unvalidated and do not constitute a supported predictive model.

Actual declared CSV/filesystem fixtures reproduced success after overwriting
notes and invalidating seals in both launchers. Base `--output` could replace
its own just-read CSV source with JSON. The advanced launcher created a missing
case with four future/prediction reports: scheduled events and countermeasure
scores were produced without case evidence. Source placeholders include fixed
growth percentages, seven-day windows and confidence/effectiveness constants.
Supplied records, heuristic labels and the clock do not validate forecasts,
actor attribution, intervention points or countermeasure efficacy.

Only the unavailable main/high-level prediction/publication boundaries and
NumPy import timing change. Remaining helper algorithms retain their previous
implementation and remain unvalidated; no tracked production consumer outside
this pair invokes them. Existing files are preserved literally without trusting
or silently migrating prior claims. The 90 package Python sources are unchanged.
No replacement model, collector, output protocol or prediction system is added.
Independent evidence, model validation/calibration, uncertainty and versioned
publication would be necessary before supporting such claims. This is separate
from ordinary case integrity/export and the uncalibrated current email score.

Six unit contracts check saved/missing cases, both output aliases aimed at a
source/outside/new file, opaque arguments for all six APIs, exact help/errors/
prefixes, inert imports and rejection with NumPy import forbidden. The actual
original-EML integration runs full no-egress analysis, confirms stopped
supervision, then probes completed/sealed/unsealed/malformed/missing/outside/
ownership-state fixtures. Guarded processes forbid source/output I/O and optional
NumPy import; direct invocations run outside the checkout without PYTHONPATH.
Actual CLI verify/ZIP preserves all original case files. The file audit hook
does not cover every metadata syscall; fixtures are not live workers or observed
future events. No OS containment, model accuracy or authenticated attribution is
established by these checks.

Observed local Windows/Python 3.13 validation: six new contracts pass after
failing before repair (two failures and 29 errors including subtests). The
original-EML integration passes one full no-egress analysis, 55 fresh guarded
processes, nineteen direct stdlib invocations and actual CLI verify/ZIP with
exact original case bytes. All six APIs and both exact output aliases are
checked without NumPy import. The serial general suite passes 765 tests:
757 passed and eight platform skips (83.140 seconds). An actual offline wheel
matches all 90 unchanged package sources, metadata, entrypoint and both review
templates. Final installation/whole-engine/platform acceptance remains open.
