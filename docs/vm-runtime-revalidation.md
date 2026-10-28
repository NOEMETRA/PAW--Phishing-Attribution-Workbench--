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
the preserved pre-guest audit copy of prior release
`9877cdd9eaedbd5d6ade1c85c2769747ff7fedc0` against its fixed manifest hash,
exact protected inventory, proof and every source byte, and requires matching
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

PR125 main `2dd987b35ba924ec690d28ed08fd7eadd9bc32c6` passed clear exact-head
review and seven head/main checks, identical trees and immutable promotion
without a password. Its first no-guest diagnostic job
`648c6906981349a7ad69d7f6f2f0e512` refused `snapshot_exact_inventory` while
checking the historical deployment tree. No guest started, no diagnostic was
published, and terminal service/cgroup/libvirt/QEMU/netns readback was empty.

The Python gate's owner interpreter omitted `-B`. An actual harmless isolated
child importing a sibling module creates `__pycache__` even when source files
are0444; matching the service's0077 umask reproduces the exact immutable
inventory refusal. Isolated `-I` ignores `PYTHONDONTWRITEBYTECODE`, so the fixed
owner command now includes explicit `-B`. Its real-process regression checks
the complete snapshot before and after the child with the existing verifier;
the old invocation fails and the corrected invocation retains exact bytes and
inventory. Browser ownership already used `-B` and is unchanged.

The diagnostic now verifies the complete Root-private audit copy made before
guest startup, retaining the same pinned manifest hash and all inventory,
proof/source and fixture/policy checks. No cache is excluded from any accepted
inventory and no historical file is deleted. The historical deployment tree
is separately inventoried for diagnostic counts only: missing/extra counts,
inventory equality and whether every extra is bytecode for a manifest module.
No extra path or content is published; a dirty tree stays inadmissible for
execution/rollback. The actual protected extras are not claimed to be bytecode
until this metadata is read. Unknown original guest failure and P3 acceptance
remain pending. New readback still requires this correction's own review/CI,
immutable promotion and one fresh no-guest job.

## PR126 actual diagnosis and first publication failure

PR126 merged as `832a2b45e9b1a48dd8e243cde19376da2c3fa49f` after a clear
exact-head review, seven green head/main checks and identical trees. The limited
operator promoted it without a password. No-guest job
`985e9a4ec2fe4abf92d72ef04f5f3e48` passed and its protected reader confirmed nine
extra historical deployment entries, all Python bytecode, with no missing
manifest entries. The original traceback reaches the exact inventory predicate
during post-boot context revalidation. This confirms the owner `-B` correction's
reproduced cause; the dirty old deployment remains inadmissible and untouched.
Current host/network snapshots matched, with no VM, I08 or real-source grant.

The ordinary reader initially asserted `maintenance.changed == false`, which
misinterpreted the reviewed field. It means the refreshed receipt differs from
the fixed historical receipt, even if that refreshed receipt already exists;
it does not attest whether this invocation created a file. A separate read-only
reconciliation checked the exact old/new receipt and inventory hashes, protected
output inode, current budgets and terminal host state without repeating the job.
The original reader failure remains preserved.

One fresh no-NIC Python owned job `b36cc5f61e20495dad73eae21f5fe7a6` then reached
the first source-mode smoke's publication, after the six validation scenarios
and its smoke execution/verification. It failed with `FileNotFoundError`, errno2,
at `publish()` opening `/var/lib/paw-s14-representation-exports`; that fixed root
does not exist on this host. The earlier round-trip test precreated its temporary
equivalent and therefore missed first deployment. Removing that setup reproduces
the same failure without Root or VM. No source sidecar or installed-mode smoke
completed, no acceptance was published and HTML did not run. The recipe's failure
path revokes its newly installed readiness; independent terminal readback found
no service/client, cgroup, QEMU, domain, active network or network namespace.
These observations do not turn this failed job into P3 acceptance.

Publication now initializes only the fixed export leaf through its protected
parent descriptor. A new Root-owned0700 directory is pinned with `O_NOFOLLOW`,
validated and assigned Root:1000/0750; each result remains0700 until the existing
reader publisher seals its440 files/750 tree. Existing parents must already have
the exact trusted owner/group/mode and are never repaired. Links, regular files,
foreign ownership and unexpected modes refuse without changing existing data.
The real-authority inert round trip now starts with the root absent; separate
tests check idempotence, preserved receipts and negative inode/permission cases.
This correction needs its own clear exact-head review, head/main CI and immutable
promotion before another synthetic guest attempt. P3, P4 and P5 remain open.
