# Linux installation and R08 acceptance

Baseline: `main`, merged [PR98](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/98),
`62f19daf63eea781e7e6eb3e6a383f88573030a1`.
Measured 23 October 2026, Europe/Copenhagen. Branch: `codex/linux-r08-validation`.
This resumes candidate installation/platform acceptance; it does not reopen the
consolidated parser, scoring or R01–R07 audits.

## Environment and installation

Ubuntu 26.04.1 LTS, x86_64, kernel `7.0.0-38-generic`; CPython 3.13.7 and
3.14.4 from `/usr/bin`. The host has approximately 7.1 GiB RAM, 4 GiB swap and
167 GiB free disk at preflight. Both virtualenvs have
`include-system-site-packages = false`; user packages and checkout `PYTHONPATH`
are excluded from installed-package checks.

The distribution's `ensurepip`/venv support packages and global pip were absent.
Both ordinary `python3.X -m venv` attempts failed at pip bootstrapping. The
created isolated interpreters were completed with the
[official pip zipapp](https://bootstrap.pypa.io/pip/pip.pyz), installing pip
26.2.2 inside each virtualenv. No apt, sudo, global Python package or Docker
operation was needed. On a normally provisioned Ubuntu installation, install
the matching `python3.X-venv` OS package before using the ordinary venv command.

An actual `pip wheel --no-deps` produced `paw-2.0.0-py3-none-any.whl` from this
baseline. Both environments installed that wheel **with all 26 declared base
dependencies**, without `--no-deps` or editable installation. `pip check` passes
on both. This is a measured resolution, not a lockfile or vulnerability audit.
An initial 3.14 download failed with `IncompleteRead`; the retained retry log
records the successful unchanged installation.

Measured shared versions include BeautifulSoup 4.15.0, tldextract 5.4.0,
cryptography 46.0.7, psutil 7.2.2, FastAPI 0.162.0, Starlette 1.9.0,
Pydantic 2.14.1 and Uvicorn 0.54.0. Exact freezes, wheel and build/install logs
are retained outside Git.

The declared base set includes the Python Docker SDK (6.1.3), so pip installs
that library too. No Docker CLI, daemon, socket, container or image is used or
probed; the validation environment consists of ordinary virtualenvs and local
processes. This does not validate the container/deployment paths.

## PASS/FAIL matrix

| Check | Result and scope |
| --- | --- |
| Clean base-wheel installation, Python 3.13.7 / 3.14.4 | **PASS**; full dependency installation and `pip check` on each. |
| Complete existing unit/contract suite, both runtimes | **PASS** on each: 1,030 tests, 1,026 passed, four expected Windows-only exclusions. POSIX fork/forkpty/spawn, process-group recovery, FIFO/symlink/file admission and resource controls execute on Linux. |
| Installed console and packaged files, both runtimes | **PASS**; 103 package files (96 Python sources plus seven templates/localization/static assets) match the built wheel byte for byte. Imports resolve inside the virtualenv, outside the checkout. |
| Installed real CLI/API, both runtimes | **PASS**; five CLI presets plus one strict-profile HTTP worker per runtime, original bytes, complete ZIP contents, seals, score/coverage parity and confirmed stopped process trees. A separate CLI deadline expires and stops its tree. API static assets are served without launching a browser. |
| Cross-runtime installed score regression | **PASS**; component ledgers, raw/display/decision scores, profiles and decisions agree for all five presets on the same public original. Default/strict preset differences remain intentional. No historical artifact is rewritten. |
| Existing actual integrations and stress acceptance | **PASS after a reproduced legacy-harness correction**. The initial 80-script serial matrix had 79 passes and one MIME harness failure; both-runtime corrected MIME results are recorded below. All 75 unique scripts selected by the existing CI workflow passed. |
| Full offline stress matrix, Python 3.14.4 | **PASS**: 24 scenarios, 95 completed cases, mixed/error/MSG batches, all presets, 5/20/50-case batches, large bodies/URL sets/attachments and explicit refusals. Every listed check passes, with valid seals, stopped trees and no observed residual PID. Process observation is sampled, not proof of every transient process. |
| Base dependency import admission | **PASS** for 25 of 26 import probes on each runtime, including local `libmagic` buffer identification; **FAIL** for PGPy 0.6.0 (`ModuleNotFoundError: imghdr`). Installation success alone does not establish component usability. |
| PGP signing / Rekor inclusion / MSG / STIX | **PASS for explicit unavailability**, within existing contracts. PGP refusal occurs before key/output access; no compatibility shim or claimed signature is introduced. Inclusion proof, MSG conversion and STIX generation remain unavailable. |
| Optional `ml` dependency resolution | **FAIL** on the measured new-runtime scope. Wheel-only dry runs on 3.13/3.14 cannot satisfy `numpy>=1.24,<2`. A normal 3.14 dry run selects NumPy 1.26.4 source and fails metadata preparation at missing `Python.h`; no ML packages are installed. This is not a successful source build or ML acceptance. |
| Browser binaries, system packet capture, live providers, containers and privileged shell launchers | **NOT RUN / NOT ACCEPTED**. Playwright's selected Chromium executable is absent. No browser download/launch, `tcpdump` capture, Docker daemon, `deploy.sh`, `init_crypto.sh`, live provider or detonation is exercised. |
| Independent corpus/holdout and classification accuracy | **NOT AVAILABLE**. The public original is not independently adjudicated; constructed fixtures and repeated inputs are regression evidence only. |

The historical private 20-original Windows pilot/case store is not present in
this checkout. No private cross-host replay or equality of those old case files
is claimed. Current public-source originals, installed cross-runtime results and
the unchanged production-source hashes are separate evidence.

The NumPy constraint is outside the supported Python versions of its last 1.x
release: [NumPy 1.26.4 documents Python 3.9–3.12](https://numpy.org/doc/2.3/release/1.26.4-notes.html).
PAW's current `MLScorer` is an alias of the heuristic content scorer; a new
NumPy major version or a trained/calibrated model is not introduced to hide this
optional-component failure. PGP is already deliberately unavailable in R05, so
the incompatible installed PGPy is recorded rather than imported by signing paths.
The unused ML extra needs a separate support/removal disposition before claiming
optional-component installation acceptance on 3.13/3.14.

## Reproduction

The new acceptance script takes an **already installed clean environment**. It
does not install dependencies itself, use checkout imports, launch a browser or
contact sample resources:

```bash
python3.14 -m venv /path/outside-checkout/paw-env
/path/outside-checkout/paw-env/bin/python -m pip wheel --no-deps --wheel-dir /path/wheels .
/path/outside-checkout/paw-env/bin/python -m pip install /path/wheels/paw-2.0.0-py3-none-any.whl
env -u PYTHONPATH -u PYTHONHOME PYTHONNOUSERSITE=1 \
  /path/outside-checkout/paw-env/bin/python tests/integration_installed_package_real.py \
  --wheel /path/wheels/paw-2.0.0-py3-none-any.whl --output /path/new-results-directory
```

Use a new output directory for each invocation. `results.json` and bounded command
logs remain there; temporary case directories are deleted by the harness.
The parent harness uses only the standard library; isolated child imports check
the virtualenv location. The console runs with an external data working directory
and no `PYTHONPATH`; the installed API runs via `python -I -m uvicorn`.
Quick forces offline mode; every other analysis explicitly requests no-egress.

The added Linux workflow builds/installs and repeats this test on CPython
3.11–3.14. Its remote status must be checked on the PR head; adding a matrix does
not itself establish that the jobs passed. Existing source integrations use their
documented trusted checkout imports and remain separate from installed-wheel proof.

During harness development, the first two private runs stopped in its verifier:
one compared a non-normalized parent `sys.prefix`, the next requested a nonexistent
`final_score` field. The corrected verifier normalizes the prefix and checks the
actual `score`/`decision_score` schema. Both logs are retained; neither failure
required a runtime change or relaxation of an existing regression.

## Reproduced MIME harness defect and final source scope

The 80-script source matrix on 3.14 comprises the existing workflow's 75 unique
integration/build scripts plus CLI runtime, interrupted-artifact API recovery,
direct MIME, authenticated crypto and the full engine stress suite. The first
matrix is retained **with its failure**, not relabelled as an all-green run.
Its only failure was the additional old `integration_mime_real.py` assertion
that a generated HTML quoted-printable part must be completed. The same unchanged
script fails on 3.13.7. Its default SMTP generator emits a 78-byte encoded line;
the [consolidated MIME contract](mime-body-evidence.md) requires at most 76 for
completed transfer syntax and correctly records partial syntax while preserving
all decoded bytes. This is a stale fixture expectation, not a Linux parser defect.

The corrected harness retains that noncanonical case and requires its exact
part/transfer diagnostic, coverage status, original/decoded hashes, three
attachment payloads and valid seal. It also generates a canonical counterpart
with `max_line_length=76`, which must be completed without transfer issues.
Numeric ledgers/decisions must match across the pair. Both real runtime runs
pass the paired checks; focused existing MIME contracts pass separately.
The new Linux workflow now runs this paired source integration as well as its
separate installed-package check. No existing parser test or admission rule is
relaxed to accept the generated overlong line.

All 96 production Python files, original templates/assets, requirements and the
existing CI workflow retain their baseline bytes. Of 301 frozen pre-existing
Python/requirements/template/asset/workflow files, 300 are unchanged and the one
expected change is this reproduced MIME harness repair. Two new acceptance files
(installed-package script and Linux workflow) have their own final hashes. The
other 79 source jobs are not repeated after a harness-only repair; their tested
production bytes remain identical. Case artifacts from the failed probes are
retained separately; none is rewritten to obtain a pass.

## R08 closure

**R08 remains OPEN; Linux base offline acceptance passes in the measured scope.**
No product-code defect was reproduced in the measured supported offline paths.
The change adds installed-package acceptance and records real component limits;
it does not change numeric scoring, original bytes, the inventory/seal policy,
readers, parser scope or existing unavailable-capability contracts.

Before closing R08:

1. Complete/record the current candidate's Windows installation and integrated
   preset/batch/interruption acceptance, rather than substituting the older
   PR22/PR84 Windows records. PR98's Windows source-family checks retain their
   documented scope; this does not reopen those audits. Keep other OS/architecture/runtime combinations
   explicitly unmeasured; CI Linux jobs cover only their reported environments.
2. Decide the support/removal boundary of the unused ML extra and incompatible
   PGPy dependency. Preserve explicit PGP unavailability unless a separate signer
   contract is accepted. Distinguish base install, optional dependency resolution
   and actual capability execution.
3. Obtain PR-head CI and review for the acceptance additions and reconcile the
   final scope with S13. The two privileged/container shell launchers stay deferred
   under S12/S14; a wheel install cannot validate them.
4. Retain S10's independent labels/holdout requirement for any accuracy claim,
   or explicitly exclude such a claim from this offline candidate. No corpus is
   manufactured from these repeated fixtures.

S14 follows as a separate [two-PC Linux architecture proposal](s14-two-pc-linux.md),
with an isolation gate before any real detonation. No access to or validated
configuration of the second PC is claimed here.
