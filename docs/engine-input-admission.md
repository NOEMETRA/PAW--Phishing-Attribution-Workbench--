# Engine input-admission family

This block extends merged PR85 (`2ce5d842cef0c541f48f1ed3e845abfaa624f49d`)
with reproduced source-admission and numeric-limit fixes across the existing
CLI, core readers and HTTP ingress. It also measures the explicitly open
malformed-top-level-EML gate. No extraction/scoring algorithm, network collector,
new package module or dependency is added.

## Shared source and resource admission

`local_source_path` in `paw/core/batch.py` admits path syntax before filesystem
resolution/stat/open or worker controls. Blank/NUL paths and UNC spellings,
including forward/mixed/extended prefixes, fail before I/O. All five analysis
parsers, direct CLI dispatch, batch selection and mail/key readers use it; HTTP
analysis applies it to the raw requested path before containment resolution.
A fenced baseline probe across five entry points/six spellings reached the I/O
barrier in 24 of 30 calls; the barrier prevented actual external access.

`read_source_bytes` opens nonblocking/binary, requires a regular opened descriptor,
bounds size/read bytes and rejects observed size/mtime changes or short reads.
Mail keeps its 25 MiB default and `MimeLimitExceeded`; local DKIM keeps its
64 KiB limit, exact UTF-8 snapshot and unverified provenance. Nonblocking open
allows POSIX FIFO refusal without waiting for a writer. Missing/unreadable inputs
remain errors; there is no empty substitute. MSG remains explicitly unavailable.

This is lexical local-path and descriptor admission. It is not OS network
isolation, a pathname/physical-volume attestation or an atomic file snapshot.
Local symlinks/mapped backing are not certified absent by these checks; observed
bytes and admitted source claims remain distinct from source authenticity.
HTTP retains its uploaded-file namespace and rejects directories before queuing;
CLI retains supported files/directory batches and their existing failure behavior.

`RunLimits` byte/count fields now require native integers in `1..2**63-1`:
`memory_bytes`, `artifact_bytes`, `artifact_files`, `log_bytes`. Booleans,
fractional/coerced values and OS integer overflow fail before supervision.
Durations require positive finite native integers/floats, with oversized integer
conversion rejected as a validation error. API-specific existing bounds remain
stricter. No new timing/performance target is introduced.

## Malformed EML and failure accounting

A bounded nonempty wire input can be processed best-effort even when malformed.
Completion means evidence processing, not validation that it is a well-formed or
authentic email. Original bytes, parser defects and partial header coverage remain
visible; this block does not discard available observations by inventing a blanket
malformed-mail rejection rule. Actual CLI/HTTP fixtures cover body-only wire,
missing header/body separator and an absent multipart boundary.

Empty/oversized input, existing MIME-limit/parser errors and unsupported MSG remain
failures. A real mixed CLI batch yields four completed sealed cases (three malformed
observations and a normal neighbor), two failed inputs (empty/MSG), a `partial`
worker result and nonzero CLI exit. The CLI parent job still reports failure for an
incomplete batch; successful/failed inputs remain available in the worker result.
All five presets process the measured malformed inputs with declared defects.

The HTTP worker completes three malformed observations with partial coverage and
byte-preserving verify/ZIP. Invalid numeric/profile/options/key requests, a directory
and an empty upload create no analysis job. A nonempty MSG upload can be retained,
but its requested analysis finishes `failed`, with stopped workers and no completed
case IDs. Early semantic CLI refusals retain exit 1; argparse syntax errors retain
their existing behavior. Invalid local key files fail before job/case creation.
These finite scenarios establish the stated contract, not every malformed-byte
combination or independently labeled classifier accuracy.

## Executed evidence

On the final frozen runtime/test/workflow sources, Windows/Python 3.13:

- 887 general tests: 873 passed, 14 platform exclusions, 92.843 seconds.
- Eight new contracts fail on the baseline (38 failed assertions and 20 errors,
  including subtests; one exclusion). These are not 58 independent defects.
- New real integration: 50 fenced cold CLI preflights (30 UNC, 20 numeric),
  one fenced API process covering six UNC forms, all five actual CLI presets,
  a partial batch with four successes/two failures, three rejected key-file CLI
  invocations, three actual HTTP malformed cases, eleven invalid HTTP requests
  without jobs and one failed HTTP MSG analysis. The new integration verifies
  twelve completed cases and original-byte verify/ZIP correspondence.
- Existing signed-DKIM CLI/HTTP integration passes: actual RSA pass/body-fail,
  absent/malformed keys, unsigned/multiple signatures, all presets, immutable
  snapshots and unverified provenance. No DNS key retrieval is involved.
- Existing actual CLI runtime and shared CLI/API live-reader/crash-recovery
  integrations pass, followed by the actual wheel (91 Python sources, metadata,
  entrypoints and templates). All five integrations run serially.

235 runtime/test/workflow hashes were frozen and rechecked before docs. Six
existing package sources change and 85 retain their Git contents. No private EML
or raw validation artifact is committed. Static public contracts are repeated
after documentation changes. The POSIX FIFO test is excluded on this Windows host
and is selected by the committed Linux CI step; a selected test is not a claimed
CI pass before that run finishes.

Reproduce with the normal engine/API test dependencies installed:

```text
python -B -m unittest discover -s tests -p 'test_input_admission.py' -v
python -B tests/integration_input_admission_real.py
```

The new cold admission probes bootstrap first, then install no-egress and filesystem
fences: a regression cannot attempt actual UNC access. HTTP integration targets an
owned loopback server and its actual workers; constructed messages/keys are
regression fixtures, not classifier ground truth. The HTTP flow verifies the existing `/api/export/{case_id}` route.

The next family reconciles extraction-to-report evidence and omissions (S03-S09).
Current-version isolated installation/platform acceptance (S13), independent
labels/holdout (S10), controlled egress/active capabilities (S14) and UI remain
separate gates. This admission matrix does not validate those capabilities.

PR86 integration record (23 October 2026): reviewed head
`c694a8534d62f58abeba260b96223d990d732256`, merged as
`e82e6842fbfa7082f1d334bfb4c5d37dda3e70d3` with identical tree. Codex
reports no findings; all three head and merge CI checks pass. The test counts
and source inventory above describe that admission block, not later changes.
