# Maintained no-guest runtime recipe

The enrolled operator already reserves `vm-acceptance-v1`. This increment gives
that recipe one finite operation: restore inactive local libvirt and the PAW
resource slice, then validate their effective state and existing image/context.
It starts no VM, network or fixture and enables no I08 or sample grant.

The dispatcher, polkit rule, static privileged files and argument allowlist stay
unchanged. Only the reviewed immutable payload worker implements the reserved
recipe. The ordinary deployment path first independently verifies review,
required exact head/main CI, source tree and snapshot; it then invokes the fixed
worker through PID1. No password file, generic command, workspace script,
caller-selected path or administrative argument enters this operation.

Before every fixed start, the recipe requires the effective nft guard and its
active service, no observed QEMU process or network namespace, no domain
definitions, no autostart entries and no libvirt hooks. Known QEMU is checked by
process/executable name and the installed binary's device/inode, including a
renamed process. This is a bounded host inventory, not arbitrary-process
attestation. Config directories/ancestors must be root protected and refuse
symlinks or writable entries. TCP/TLS libvirt sockets must be inactive. Unknown
or transitional service states refuse.

The loaded daemon must use the fixed package binary and default timeout
argument, default environment file and the reviewed PAW guard dependency.
Environment overrides, extra drop-ins, other executables and changed guard
dependency bytes refuse. Relevant protected config hashes are rechecked across
activation. The slice must declare the existing2GiB aggregate RAM, zero swap
and128-task limits before starting; the maintained platform predicate reads
the actual cgroup values afterwards. Guest and QEMU limits are unchanged.

The only administrative commands are `systemctl start machine-paws14.slice`
and `systemctl start libvirtd.service`, each only when inactive. The latter has
its existing local socket/guard dependencies. Active units are left active.
No enable/disable/reload, package installation, firewall/routing write, bridge
creation or domain/network start command is issued. Started units remain
available for subsequent maintained no-NIC work, subject to libvirt's existing
idle timeout. A failure is saved as FAIL; it does not revoke the enrolled
operator or infer permission for a broader recovery command.

The shared global execution lock excludes another PAW guest. Host interfaces,
routes and normalized nft rules must match before/after. After activation the
local libvirt connection must enumerate zero domains and only inactive,
non-autostart network definitions. The existing fixed image certificates,
QEMU/package/CPU/mitigation/platform predicates and browser context must pass.
Any unavailable observation remains a failure, without claiming an empty
inventory. There is no VM execution or general isolation acceptance here.

A successful protected result binds job, recipe, immutable release, effective
observations and context hashes, with zero executed samples and no readiness
installed. Elapsed time uses integer milliseconds, compatible with the existing
protected-state decoder's scalar contract. Root-owned reader evidence is published through the existing
descriptor-based exporter as750 directories/440 files for the enrolled owner;
ownership remains root. The caller cannot mint a PASS using workspace JSON.

24 inert tests replace every administrative command, libvirt interaction and
privileged storage operation. They cover refusals, exact finite commands,
idempotence, guard reobservation, failed starts, private exports and failed or
out-of-scope results. An actual temporary-file write/read through the protected
dispatcher decoder failed with `operator_proof_scalar` before the duration fix
and passes with integer milliseconds. Existing90 operator/release and44 browser regressions
also pass. These tests do not establish actual restart acceptance: that still
requires completed exact-head review, green head/main CI, immutable promotion
and one real invocation of this no-guest recipe with independent readback.
P3 remains open for its separate representation authority, adapter, scoped I08
and benign no-NIC execution/PAW sidecar matrix. New runtime tests live outside
the privileged lab inventory; its existing128-source cap is preserved.

The first actual invocation of reviewed PR116 on26 October, job
`e9944b8f17424a27a70c9664483c06b1`, failed before either service started. The
enrolled operator required no password and remained usable; the worker was
terminal and both units remained inactive. The new runtime caller had selected
the guard-specific normalizer for the entire nft ruleset. Three owned-data
regressions reproduced two integer-list `TypeError` failures and one lost
meaningful scalar value. The caller now uses the existing whole-ruleset
normalizer from `gw_validation`; both established normalizers and the guard
predicate remain unchanged. Tests retain set integers, map pairs/ranges and
scalar metadata spellings, ignore only existing volatile fields and detect
actual rule changes. The corrected runtime still needs exact review/head/main
CI, immutable promotion and a new real no-guest invocation before acceptance.

## Exact Brotli maintenance transition (27 October)

PR122 merged as `9451c2e1c5a1d0f7b3d9b49c6770aaf5f4dea3ff` after a
completed clear review of `3884e58064b46ea280f709017ed9bfbff72b9ba1` and seven
green head/main checks. Independent immutable promotion passed without a
password. The following owned attempt, `ec85c0112fd84c56b8d5b54d43e3361e`,
passed the corrected history check but refused current maintenance before
profile selection, client or VM startup. The job, its diagnostic and empty
terminal service/cgroup/domain/network observations are preserved outside the
checkout. This is not a successful P3 matrix.

During main CI, Ubuntu unattended-upgrade changed only `libbrotli1:amd64` and
`python3-brotli` from `1.2.0-3build1` to `1.2.0-3ubuntu0.1`. Read-only
reconstruction of those two previous versions recovers the exact prior whole
inventory digest. The existing maintenance predicate correctly rejects the
old receipt; it must remain strict. QEMU bytes, kernel and host identity were
unchanged; no reboot-required marker was present. Local APT metadata lists
the new versions in Ubuntu's resolute security/updates repositories. These
ordinary observations diagnose the drift; they are not privileged authority.

The existing no-guest `vm-acceptance-v1` recipe now additionally supports this
one reviewed transition. It reads only the fixed protected predecessor receipt
with SHA256 `4ab64d87b191dd6ea2879fae0f9e5f12eb255a8fe83062d34f577c2d8d7b1e44`.
The old inventory is pinned to
`4c4a2167cfbd316bd7923426ef249b25f459dc7181df5fbe55624bb4ffeaed80`, and the
new inventory to
`e214bcd487744333146303190396743973b1ad9755112c182b0bf7aa255c2ef3`.
Both exact package names/versions and reconstruction of the complete old
inventory must match. The unchanged maintenance validator checks all other
platform, host, QEMU, image and existing vendor-attestation bindings against
the protected predecessor. No new vendor signature or inspection of the
guest is claimed by this transition.

The deployment lock remains held by the operator; the refresh also holds the
global execution lock, requires an empty package audit/no pending reboot, and
reobserves full platform, guards and network before its single append-only
maintenance write. Existing identical bytes are idempotent; differing bytes
refuse. The prior record, policies, readiness and grants are never rewritten.
There is no package installation, network request, caller-supplied path,
command or authority, static privilege change, budget increase, VM or I08.
Unknown future package drift needs a separate reviewed transition.

Eleven new inert tests exercise the real maintenance/context validators,
exact transition, stale-receipt refusal, changed host/QEMU/kernel, hidden extra
delta, malformed/duplicate inventory, reboot/audit/race and immutable existing
receipt refusals. All 35 runtime tests pass with host/filesystem boundaries
explicitly substituted. Actual refresh still requires this increment's clear
exact-head review, seven green head/main checks, immutable promotion and a new
no-guest invocation with protected receipt readback. Only then may fresh owned
P3 jobs proceed. P3, P4 and P5 remain open.

## Fixed historical owned-failure readback

After the PR124 guest attempt stopped with an uninformative outer reason,
`vm-acceptance-v1` additionally reads only the fixed failed request
`fe3d0adb0130410eb510f8143451a036` from owned job
`ccec225bc95f4f4ca2f89927cc33adbb`. No caller supplies an ID, path, source,
command or output selector. The function requires Root, physically verifies
the prior release `9877cdd9eaedbd5d6ade1c85c2769747ff7fedc0` against its fixed
manifest hash, and requires the protected audit's matching snapshot inventory,
Python profile, exact immutable-generated harmless fixture bytes, request hash
and `owned-validation` policy/manifest with no readiness. This readback does not
revalidate historical data as current execution authority or change a ledger.

Only finite allowlisted reason/exception codes, six known-module basename/line
locations, hashes, boolean cleanup attestations and seven fixed serial marker
flags enter the protected runtime reader. The private result and serial files
are descriptor-read with2MiB/1MiB budgets. Raw traceback/error paths and serial
bytes are never published or evaluated. Serial flags are diagnostic string
observations, not trusted guest assertions or a PASS. The diagnostic retains
`source_result: FAIL` and explicitly carries no VM, I08 or real-source grant.

Current runtime/network/guard/resource revalidation and the existing exact
maintenance predicate remain mandatory; an already matching receipt is
idempotent. No package, guard, route, policy, grant, historical audit or source
snapshot is rewritten. This addition still requires clear exact-head review,
green head/main CI and immutable promotion before one actual no-guest readback.
Future privileged guest work must wait for diagnosis of this preserved failure.
