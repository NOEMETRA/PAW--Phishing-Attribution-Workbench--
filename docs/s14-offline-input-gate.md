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
