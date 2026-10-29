# Finite no-NIC native runtime and owned acceptance

This P4 increment implements the already reserved `shell-owned-v1` and
`elf-owned-v1` recipes. It does not change the installed operator, enrollment,
polkit policy, allowed command names or aggregate budgets. It must first pass
exact-head review and required CI, merge/main CI and independent immutable
promotion. None of the draft tests below activates Root authority or a VM.
The [native client](vm-native-custody-contract.md) remains separate from the
accepted Python/HTML client and attachment contracts.

## Authority and ingress

`native_runtime.py` has a distinct Root-only
`/var/lib/paw-s14/native-authorization-v1` store and native v1 policy/grant/
consumption/readiness schemas. The context binds the native profile, current
maintained platform, guest controller, client contract and complete immutable
Root runtime inventory. Capture rejects a foreign active release, damaged source
snapshot or absent/currently mismatched protected maintenance receipt.

Every grant binds an exact request, case/selection/graph and source hash, profile,
policy and context; approving bytes alone cannot authorize a new request. The
exclusive consumption ledger is written before guest creation and survives
failure. Expired, cross-profile, revoked-readiness and uninstalled caller JSON
refuse. Explicit analysis-mode grants require a current scoped I08 receipt.
Only the finite recipe can issue unattended authority, and only for exact bytes
it regenerates independently from its immutable owned fixture code and nonce.
There is no ordinary-user CLI for Root policy/grant/readiness installation.

The new gate retains the accepted HashGate's no-NIC XML, nonroot QEMU, AppArmor,
seccomp, disabled memory merging and CPU/device restrictions, independent owner,
private input media and known-stop lifecycle. It embeds exact source bytes,
fixed controller and bounded seed configuration in the private cloud-init ISO.
It never mounts a guest disk, resolves ELF dependencies, extracts an archive or
runs a specimen/compiler/ldd/interpreter on the host. Job/report metadata keeps
source size/hash rather than duplicating the1MiB ELF body as hexadecimal; the
bounded request and private ingress retain the full bytes.

The fixed Root client lifecycle drops to UID/GID1000, clears groups and all
capabilities, uses no-new-privileges/private network+mount namespaces and obtains
a protected nonce/PID acknowledgment after independent kernel observation. The
shared helper adds finite native profiles/slots and an internal trusted context
reader; its legacy wrapper and budgets remain intact. Source/installed package
origin is checked. User-writable PAW/package code runs only after dropping Root.
The fixed installed client environment must match the reviewed111-file package
before actual activation; the previous108-file accepted environment is retained
until that gated update. Immutable Root code is independently checked by the
operator and serialized audit verifier, never trusted from a local JSON claim.

## Trusted guest boundary

`native_guest.py` refuses the development host: it requires Root in the expected
signed guest kernel with only loopback. Shell always uses fixed guest `/bin/dash
-- /opt/paw-input/sample.bin`; the shebang never selects an interpreter. ELF
executes that exact fixed guest file. The separate structural inspector restricts
it to the declared AMD64 executable/PIE profile; dynamic linking is done only by
the guest loader. Loader failures/unavailable libraries are execution outcomes.

Before exec, a CLOEXEC ready/go pipe lets the trusted parent inspect the child
without a blocking Popen preexec handshake. The child creates a new session with
no controlling terminal, closes the serial and extra descriptors, changes to the
writable fixed guest work directory before dropping identity, uses `/dev/null`
for stdin, enters the fixed job cgroup, applies rlimits, drops every capability
bounding bit while still privileged, then all groups/UID/GID and sets NNP. The
parent checks kernel PID identity, four UIDs/GIDs, empty groups, all five zero
capability sets, NNP, session/TTY/stdin/working directory, exact cgroup and actual rlimits before
releasing the fixed-path exec. Signals ignored by Python are reset for normal
native CPU/file-limit behavior. Neither source nor environment can choose a host
command, path, interpreter, systemd property or resource limit.

| Boundary | Unchanged budget |
| --- | --- |
| Aggregate host lab |2GiB,128tasks, no swap |
| Root parent recipe |512MiB,64tasks,100%CPU,1800s |
| Unprivileged PAW client |256MiB,32tasks,50%CPU,180s,8MiB file |
| QEMU / guest |768MiB host scope,64tasks,50%CPU, no swap /512MiB guest |
| Guest native job cgroup |64MiB,16tasks,20%CPU, no swap, group OOM kill |
| Guest child rlimits |192MiB AS,2s CPU,4096byte file,32FD, no core |
| Job wall / output |4s /1024bytes per stdout and stderr |
| Overlay / external stop |256MiB / strictly under12s with known UUID/PID absence |

The guest kills the whole cgroup even after a leader exit and proves zero
remaining writers before returning normal/error/limit output. Kernel memory/task
events and peaks accompany bounded streams. Host cancellation deliberately uses
the existing whole-VM stop path with empty output; it does not invent guest
post-cancellation observations. Failed startup closes/reaps owned resources.
The channel has strict typed pending frames and idempotent close for a protocol
fault followed by host cleanup. Unknown stop blocks publication.

These measurements rely on the trusted image/controller and host deployment;
guest reports are not remote attestation or a proof against arbitrary kernel/
hypervisor escapes. [Linux exec/NNP](https://man7.org/linux/man-pages/man2/execve.2.html),
[capability bounding removal](https://man7.org/linux/man-pages/man2/PR_CAPBSET_DROP.2const.html)
and [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) define the
interfaces used here; actual runtime observations are still required.

## Producer, verifier and publication

Native audits have their own fixed control-directory namespace. Independent
serialized verification checks complete source/proof inventories, exact request/
grant/consumption/admission, maintained image, VM/owner identity, no exposed host
filesystems/devices/interfaces, effective controls, external stop, guest boundary
and opaque output hashes/inventory. Failure witnesses separately prove paused
refusal, owner loss and serial loss with known stop and no quarantine publication.
Extra jobs/authority/files, changed parent/digests, invalid outcome, missing
boundary, modified snapshots and unknown writers refuse.

Only a current protected analysis-mode audit can publish to
`/var/lib/paw-s14-native-exports/REQUEST_ID`. The fixed Root parent is created
0750 for group1000 only when absent; existing wrong ownership/mode or links are
refused rather than repaired. The receipt binds the complete immutable inventory
and count, image/context/authority/result digests, timestamps and no-NIC stop.
Only fixed ordinal opaque artifacts are exposed read-only to the enrolled user.
The client imports them into a separate sealed private sidecar and checks the
original case inventory again. No sample output is rendered, expanded, executed,
classified or authenticated by publication.

## Owned matrix and outstanding acceptance

The shell recipe requires12validation cases plus two fresh source/installed PAW
smokes; ELF requires14plus two smokes. Cases include exact positive output/reset
marker, MIME-derived selection, nonzero exit, loop, bounded fork pressure,
output/memory/file limits, cancellation and the three host/control faults. ELF
also includes static PIE and a minimal dynamic PIE, generated solely as owned
bytes with RIP-relative instructions and explicit ELF metadata. These data are
never run on the host. The smokes exercise the full64KiB shell/1MiB ELF ingress.
Every consumed request must refuse replay; changed binding/digest and live busy
lock must refuse, unknown stop must not publish, and parent cases stay unchanged.

A scoped24h I08 receipt is installed only after all owned validation cases pass
and their hashes are saved, using the independently admitted exact review/head
CI proof. Both source and installed smokes must then pass before cached
acceptance is committed. Failure revokes the newly installed readiness while
preserving all logs/consumption. Cache reuse requires the current exact context,
unexpired/unrevoked receipt and matching protected validation/acceptance files.

Current evidence is inert unit testing and actual unprivileged CLI custody only.
It is not actual native VM/I08 acceptance. Required review, head/main CI,
immutable promotion, fixed-client update and all live owned matrices remain
mandatory before P4 closes. Explicit JavaScript-to-HTML browser handoff and
current Python/HTML acceptance also remain required, followed by P5 operational
batch/cancel/crash/recovery/replay/cleanup, rollback/revocation/restart checks and
final evidence consolidation. No real source, network or generic hostile-code
safety is enabled merely by this implementation or its local tests.


## Reproduced long-matrix timeout and bounded stages

The first actual Shell call on merged PR131 reached the unchanged1800s Root
service limit during its eighth case, `file`. The recipe had advanced through
positive, derived, expected error, loop, fork, output and memory; it did not
complete the full matrix or install I08. Journal evidence records the service
timeout. Subsequent read-only checks found the parent inactive with MainPID0,
no libvirt domain/network, QEMU or network namespace, unchanged protected
operator status and a clean source tree. Partial Root-private audits remain
preserved; those host checks do not claim a full acceptance result.

A fixed recipe call now executes at most three validation VMs. Shell needs four
such calls and ELF five, followed by a separate call with only the two final
source/installed smokes. These are finite internal stages of the same reserved
recipes, without new caller arguments, target/source paths or privilege. All
budgets, including the1800s parent cap, remain unchanged. Cold boots and
verification must still satisfy that cap; partition tests are scheduling
regressions, not a guarantee of host performance.

A completed stage writes a canonical protected summary and an exclusive Root
pointer bound to profile, stage index, exact maintained context and summary
hash. An interrupted/incomplete stage creates no resume pointer. Subsequent
calls require a contiguous prefix and independently re-read each cached stage:
complete copied immutable source/proof inventory, exact owned bytes and nonce,
original case inventory, consumed grant ledger and serialized normal/fault VM
verification. A changed digest, parent, ledger, profile/context or missing
prefix refuses. Historical consumed grants are checked at their recorded
admission clock; they are never refreshed or reused. Stages from the old
failed unpartitioned call have no pointer and are not imported into acceptance.

Each stage has its own client job and nonce; these remain explicit in the final
matrix rather than attributing every client acknowledgment to the final job.
`stage_only: true` is a per-call PASS, explicitly `i08_installed: false`; it does
not close a profile. Only the complete ordered matrix can issue readiness and
attempt the two fresh smokes, sealed exports and replay refusals. Failure after
new readiness installation revokes that receipt while preserving stage evidence
and consumption ledgers. A full result reports two current-call VMs separately
from the cumulative matrix case count. Actual staged Shell/ELF acceptance and
the independent reader reconciliation are still required; P4/P5 remain open.


## Fixed historical ELF smoke diagnosis

On reviewed main `3a8446b`, all14 ELF validation scenarios passed in five bounded
stages and each stage passed the independent ordinary reader. The first final
source-mode1MiB ELF smoke then failed inside `execute_native`. Its parent job
`9ab7f09d2a8640a39a7c2f9a2ab590ad` terminated normally as a failure; read-only host
checks confirmed MainPID0, no domain/network/QEMU/netns, unchanged operator
status and clean sources. Full ELF acceptance is not claimed. Shell's separate
14-case acceptance and its archive remain historical evidence for that context.

The final-smoke path omitted the backend's already sanitized diagnostics from
its public job result. An inert negative regression against the committed
function reproduces that omission; the corrected path preserves those metadata
before failing and still revokes new readiness. This does not identify or fix
the underlying1MiB backend failure, which requires the protected report.

The existing no-VM `vm-acceptance-v1` recipe now also reads only that fixed job
and request `e51ae5f1725d401592ed67eea27e04d2`. There is no caller-selected ID,
path, output selector or new command. It checks the fixed historical manifest
hash/full source inventory, exact regenerated owned1MiB bytes and policy
request/hash binding, failed outer result and absence of its revoked readiness.
It exposes only reviewed literal error-code words from that verified public
snapshot, bounded known-module line locations, report/serial hashes and fixed
serial flags. Raw exception/traceback/serial text, source bytes and output stay
private. A successful failed-job diagnostic is not a successful VM verifier,
execution acceptance or restored grant; it deliberately does not require the
failed acceptance verifier itself to pass. Missing/foreign/tampered evidence or
an unexpectedly live old receipt refuses the diagnostic.

Only after fresh review, head/main CI and independent immutable promotion may
this read-only historical diagnostic run. No new VM is authorized by it. The
underlying cause remains unclassified until the metadata are read and the
specific defect is independently reproduced. Source-changing promotion requires
fresh current-context readiness before further execution acceptance. P4/P5
remain open; no new real-source approval or network is enabled.


The actual PR133 historical read (no guest) returned `guest_channel_deadline`
in initial `Gate.start` readiness, with host-restored/writers-stopped attestations
and actual absence of the new revoked receipt. The preserved serial log is83727
bytes; it contains a failed-service marker and no observed kernel-panic/OOM or
Python-traceback marker. That proves the failed phase, not a particular root
cause or permission to increase a budget.

A follow-up adds structured facts from that same fixed log: bounded kernel/cloud
uptimes, events for six fixed service names, numeric exit status, reviewed guest
error words and fixed config/boot flags. Unknown units, raw text/paths and large
lines are omitted; event counts and timestamps are capped. A systemd PID in
brackets is not a kernel uptime. No selector, raw-log export, guest, source
authorization or budget changes are introduced. Actual underlying-cause
reproduction/fix and P4/P5 acceptance remain pending these observations.
