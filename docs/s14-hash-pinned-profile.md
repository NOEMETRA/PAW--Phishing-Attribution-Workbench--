# Hash-pinned offline Python profile: maintenance, I08 and admission

This profile removes the compiled source-catalogue restriction from the new v2
adapter. The historical synthetic v1 authority/records and PAW fixed-fixture
request/import contract remain separate. No ordinary PAW analysis or HTTP route
launches privileged jobs. Source/scoring/original-case semantics are unchanged.

## Maintenance and effective boundary

On this PC six coordinated QEMU packages were upgraded to
`1:10.2.1+ds-1ubuntu3.3`, with no new packages or removals and no running guests.
QEMU utilities were already at that version. The effective guards and pinned
Ubuntu guest image remained unchanged; no reboot was requested. Unrelated
workstation updates were not forced through their staged rollouts. This is a
specific virtualization baseline, not a blanket vulnerability clearance.

The vendor's current signed release checksum still identifies the pinned image
`b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658`.
Its separately signed-checksum-bound package manifest identifies guest kernel
`6.8.0-147-generic` (package `6.8.0-147.147`). `hostile_maintenance.install()`
checks root-owned image/checksum/keyring preparation, actual vendor signature
fingerprint, image/manifest bytes, coherent QEMU component versions and reboot
status before installing a root-protected maintenance record. No guest filesystem
is mounted or interpreted on the host.

The v2 context binds the existing host/image/guard/mitigation/slice/source freeze,
plus QEMU binary hash, all seven QEMU component versions, full installed dpkg
inventory digest, hashed machine identity and effective CPU/microcode signature.
Any package or material configuration change invalidates the context, even when
more conservative than necessary. A hash/version does not prove absence of bugs.

Host KSM is active. V2 uses memoryBacking/nosharepages and requires effective
QEMU memory merging off, verified from the running process, without changing the
host's global KSM setting. Guest PMU, VMware I/O port and USB are disabled. The
existing AVX/AVX2/XSAVE disable policy remains checked in effective XML before
resume. The running QEMU executable hash must match the approved context.
Guest-visible CPU flags and kernel release are checked by an owned probe.

The profile remains one vCPU, no NIC/filesystem share/passthrough/vsock, guest
512 MiB, QEMU 768 MiB/64 tasks/zero swap, CPU50%, I/O pool8 and per-file256 MiB.
Aggregate slice2 GiB/128 tasks/zero swap and guest job64 MiB/16 tasks plus existing
CPU/FD/file limits remain in effect. Inputs are UTF-8 Python source <=16 KiB,
no arguments or additional dependencies. Python is an entry format, **not a
language sandbox**: treat its workload as a fully untrusted Linux process that
may launch guest programs/native instructions. Hypervisor/kernel controls are
the boundary; this is not certification against every escape or side channel.

## Explicit hash authority, with real-sample readiness separate

`hash_authorization.py` has no source catalogue check. A policy in fixed
root-owned `/var/lib/paw-s14/authorization-v2` explicitly lists approved source
SHA256 values. A root-issued grant additionally binds the exact candidate frame,
canonical candidate/source/parent-reference hashes, policy, purpose and <=15min
lease. No candidate assertion, correct digest, provenance string or mode flag
creates execution authority. Parent/provenance remain claims, not PAW custody
or email-authenticity proof. No host evaluation/compilation of input occurs.

Two policy modes have deliberately different prerequisites:

- `validation`: finite explicitly approved hashes plus exact approval-manifest
  hash. The controlled matrix uses only newly generated owned harmless bytes.
  It cannot masquerade as a real-sample readiness receipt.
- `sample-analysis`: exactly one source hash, and a root-protected unexpired I08
  readiness record binding this exact context and maintenance record to reviewed
  head, independent review receipt URL and two successful CI runs/seven jobs.
  A missing/wrong/stale/uninstalled readiness record refuses. It is a local
  administrative approval after evidence review, not a remotely signed GitHub
  attestation. The operator is trusted to verify those external facts before
  installing the record; an unprivileged candidate cannot self-approve.

Policies/readiness expire within24h; execution admission within15min. Root-only
fixed no-follow storage, owner/mode/type/size checks and O_EXCL+fsync consumption
reuse the established authority primitives. The v2 store does not migrate or
reset historical consumed grants. Both adapters share the global execution lock.
Each grant is consumed before VM creation, permanently even after startup
failure. New output paths cannot replay it. Busy/low-disk admission refuses
before consumption. Grant/readiness/context/consumption are rechecked after boot,
and again after stop before quarantine; policy/grant revocation or context change
blocks publication. Publication may use historical admission time for expiry,
without allowing late execution. Only known external stop can publish.

`hash_offline_operator.py` is an explicit root PID1 operation for one already
issued `sample-analysis` grant. It requires the candidate's exact frame SHA and
installed policy SHA, uses the fixed root control namespace and performs no
automatic grant issuance. It writes opaque stopped-job evidence, not a risk or
attribution verdict. `verify_hash_offline.verify_single()` independently checks
single-job custody without applying a benign fixture oracle. No real-sample
policy/grant is needed or issued merely to test candidate JSON.

## Controlled acceptance and I08 decision

`hash_validation_inputs.generate()` produces fresh nonce-bearing harmless bytes
outside all historical catalogues. The root operator separately approves the
complete manifest SHA; the matrix imports only those exact bytes/hashes into a
validation policy. The core adapter accepts by hash, not by membership in the
fixture generator. The eight new-VM cases are positive, expected failure,
descendant timeout, cancellation, output overflow, paused refusal, owner loss
and actual serial protocol failure; all grants are retried under fresh output
paths. Unknown-stop publication is separately checked inertly, not by making
an actual VM unkillable.

`verify_hash_offline.verify()` reconciles exact approved inputs/policy/maintenance,
all grants/consumption/local ledgers, source/image/binary/machine context, actual
UUID/PID identities, no-NIC/CPU/memory/DAC/AppArmor/seccomp controls, stop and
opaque bounded ordinal output. CI uses only inert owner-role and VM substitutes;
actual root/KVM evidence must be recorded separately. The shared legacy lifecycle
adds only an optional post-stop callback; default v1 behavior remains unchanged.

Before any real input: complete post-maintenance controlled runtime, reconcile
it, review the effective I08 record/maintenance/risk disposition independently,
and obtain exact-head green CI. Only then may the explicit operator install a
short-lived readiness record. Test that final route with another new harmless
source, then accept a real candidate only after specific source/hash approval.
Do not treat the code's existence, an old synthetic PASS or a readiness receipt
as an instruction to run a real sample. Browser/egress, arbitrary binary input,
other interpreter profiles and automatic PAW noncatalog custody remain outside
this profile and require separate contracts.
