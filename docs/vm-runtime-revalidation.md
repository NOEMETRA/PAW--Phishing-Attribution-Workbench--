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
installed. Root-owned reader evidence is published through the existing
descriptor-based exporter as750 directories/440 files for the enrolled owner;
ownership remains root. The caller cannot mint a PASS using workspace JSON.

20 inert tests replace every administrative command, libvirt interaction and
privileged storage operation. They cover refusals, exact finite commands,
idempotence, guard reobservation, failed starts, private exports and failed or
out-of-scope results. Existing90 operator/release and44 browser regressions
also pass. These tests do not establish actual restart acceptance: that still
requires completed exact-head review, green head/main CI, immutable promotion
and one real invocation of this no-guest recipe with independent readback.
P3 remains open for its separate representation authority, adapter, scoped I08
and benign no-NIC execution/PAW sidecar matrix. New runtime tests live outside
the privileged lab inventory; its existing128-source cap is preserved.
