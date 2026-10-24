# Offline immutable-input acceptance

This follow-up to PR103 selects a narrow Linux Python profile: UTF-8 source up
to 16 KiB, no arguments/dependencies, no NIC, one job per fresh overlay, and
bounded stdout/stderr only. No guest filesystem parser, browser or downloaded
code is accepted. Existing production PAW detonation remains unavailable.

`offline_input.py --validate-stdin` and its local Python API `admit()` validate
the same bounded schema without evaluating or compiling input. Fields bind job
ID, parent hash reference, exact source bytes/hash, profile, creation/expiry and
the current synthetic-only operator scope. Parent/digest fields assert linkage
and integrity, not authenticity. JSON duplicates and extra fields refuse.

`offline_input_matrix.py --synthetic-acceptance` exercises the local `run_job()`
API from its CLI under a bounded root PID1 service. There is no HTTP listener,
privileged production API or generic sample launcher. Independent runtime
admission additionally matches the immutable trusted synthetic catalog; a
well-formed arbitrary source still refuses. A monouse ledger is committed before
VM creation and admission expiry is rechecked after boot. Input is seeded at a
fixed root-owned read-only guest path, with guest-confirmed source and job hashes.

Four harmless fixtures use that same input/start/stop/quarantine path: a positive
uid/capability/no-NIC/null-stdin marker, an intentional bounded sleep with a
stubborn descendant, host cancellation of a similar job, and bounded output
overflow. Guest execution keeps the 64 MiB/16-task job cgroup and CPU/file/FD
limits; control remains outside the job cgroup. Output is read incrementally,
capped to 1024 bytes per stream, labelled completed/timeout/cancelled/failed or
output_budget, never interpreted as a maliciousness verdict. The full guest
cgroup is killed and empty before return, even if its leader exited first.

Every VM uses the reviewed no-NIC QEMU owner, DAC/AppArmor/seccomp, 512 MiB guest,
768 MiB host/64 tasks/no swap, eight I/O workers, core-disabled/256 MiB per-file
limits and the existing aggregate 2 GiB/128-task slice. Quarantine publication
requires the external VM UUID/PID/start identity stopped oracle. Unknown stop
blocks publication; fresh overlays must lack prior markers. VM/source/image/
host/canary and output custody are independently reconciled by
`verify_offline_input.py`. Tests and CI do not substitute for measured KVM runs.

## Remaining boundary

The input schema and synthetic adapter are acceptance infrastructure, not an
authorization to execute arbitrary hostile code. I08 still requires independent
review of effective runtime evidence, image/policy/version hashes and platform
maintenance disposition. Any future generic-input admission or production
CLI/HTTP integration is a material contract change requiring its own acceptance;
this profile does not silently enable it. Browser/egress, other interpreters and
R08 remain separate. Results and exact producer/CI heads are recorded in the PR
and private local evidence, including any failed attempt.

The initial runtime attempt was interrupted after the first positive job when
independent Codex review reproduced an API cleanup gap on partial startup and
acceptance of XML claiming root DAC/oversized guest memory/I/O pool. Its FAIL
export retains stopped writers, restored host and unchanged source freeze.
Startup is now inside the API cleanup region. The reader validates non-root DAC,
512 MiB guest memory with explicit MiB/KiB units and the eight-worker I/O budget.
Six inert methods include the real CLI, partial-startup fault and complete-export
corruption regressions. A fresh full runtime run is required on corrected sources.

## Frozen operational interface

The only supported operational adapter here is the synchronous, single-caller
local Python `run_job(gate, job, cancel=False)` API exercised by the synthetic CLI
matrix. Calls must be sequential, with one owned idle gate; parallel callers and
a production HTTP endpoint are not supported. No PAW detonation route points to
this lab API, and passing the admission CLI does not authorize execution.

A repeated call on a busy gate now refuses before consuming a ledger entry or
starting/stopping anything. The earlier implementation could stop the prior job
when the new startup refused; this was reproduced without a VM and corrected.
A startup failure before VM registration also retains its original exception
instead of masking it with a missing-state error. Two regressions bring this
family to eight inert methods. Startup/readiness failure, known stop, unknown
stop and partial output remain distinct from successful completion. The full
KVM matrix must be repeated for this final adapter revision; historical exports
keep their original producer heads and bytes.

Codex also reproduced a reset-observation race: the success child could create
its marker before the controller recorded the old-state observation. The reset
check now occurs before spawning; an existing marker refuses execution, and a
new child-created marker cannot change the saved observation. Two deterministic
stub regressions require no root/guest/payload execution. The input family now
contains ten inert methods. No new execution profile or production route is added.

The complete four-job repeat passes on producer `9503aca`, preserving 59 frozen
sources. Subsequent consolidation integrates the reviewed base's complete
producer/quarantine inventory checks and partial-startup stop correction. The
input reader's analogous directory/file symlink acceptance was independently
reproduced and now refuses; this brings the input family to eleven inert methods.
The final combined adapter must pass both the four-job matrix and a real paused
VM refusal before any payload is admitted. Unknown pre-admission file limits
are recorded as null, never fabricated as applied limits. These are interface
and evidence corrections within the same profile, not new execution features.
