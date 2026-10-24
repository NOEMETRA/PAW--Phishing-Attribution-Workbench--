# Offline adversarial synthetic isolation checks

24 October 2026. The user authorized missing hostile-code gate checks on this
PC using only harmless synthetic samples. No new Internet connection, actual
malware, browser or arbitrary attachment execution is part of this work.

The current general gate remains **OPEN**. The fixed benign marker and HTTPS
probe do not implement an arbitrary-input execution contract. This separate
matrix adds concrete missing measurements to a **no-NIC, unprivileged Linux
fixture profile**; a PASS is finite evidence, not a VM-escape certification or
automatic authorization to run unknown code.

## Existing evidence preserved

The [closed gateway matrix](s14-gateway-validation.md) already covers its named
host/L2/DNS/redirect/failure/reboot cases. The [controlled probe](s14-controlled-uplink.md)
retains the real HTTP200/TLS observation, refused oversized body and fixed
networkless benign execution. Those datasets keep their frozen source hashes
and dispositions. This work does not reopen scoring, original-byte, seal,
parser or consumer audits, and changes no `paw/` module.

## New executable checks

`lab/s14/synthetic_gate.py --synthetic-matrix` is an operator-only bounded PID1
service harness, not a privileged application API. It accepts no payload, URL or
command argument. Two fresh verified KVM overlays have no NIC, shared filesystem
or hostdev; QEMU retains non-root DAC, AppArmor, seccomp, 512 MiB guest RAM,
768 MiB host cap, 64 host tasks, zero swap and an eight-worker I/O pool.

The host installs a 256 MiB per-file QEMU file-size limit and disables QEMU core
dumps before resume. This bounds overlay growth independently of guest behavior.
No guest filesystem is mounted on the host and no host filesystem quota/network
policy is reconfigured. At least 10 GiB host free space is required; the
existing 2 GiB aggregate lab cap remains in place.

| Boundary | Finite synthetic expectation |
| --- | --- |
| Privilege and host separation | Actual uid/gid65534, no effective capabilities, no-new-privileges; positive local read works while an owned host canary, host socket paths, setuid, mount and cgroup writes refuse. No real host secret is read. |
| Network | XML and guest contain no NIC; owned benchmark IPv4/TCP, IPv4/UDP and IPv6 attempts cannot route. No ordinary LAN peer is scanned. |
| Task/memory/file budgets | A guest-only root-owned job cgroup limits to 16 tasks/64 MiB/no swap. Fixed bounded forks hit the PID controller; one bounded allocation triggers its actual OOM counter; a file write hits RLIMIT_FSIZE. The trusted controller is outside the job group. Injections without counter/result evidence fail. |
| Host storage | A separately lowered QEMU file cap, followed by a bounded write in the second VM, must stop/pause then stop the VM near the cap, without filling the host disk. A failed injection cannot pass. |
| Host-facing protocol | A separate bounded channel rejects non-object, non-finite, excessive-complexity, wrong/unsolicited response frames. The trusted-fixture channel is not silently promoted to an adversarial ABI. |
| Lifecycle | A fixed parent/grandchild ignore termination and plan a late write; malformed guest protocol triggers owner loss and external stopped UUID/PID oracles before that late-write deadline. Unknown stop blocks publication. |
| Reset | A second fresh overlay must not see the first VM's marker. Base, owned host canary and prior admitted artifacts remain unchanged. |
| Output custody | Actual guest-supplied traversal, duplicate, digest and oversized records refuse. Live publication refuses before creating a directory. After all writers stop, bounded valid bytes become ordinal opaque `.bin` files; HTML is never rendered. |

`verify_synthetic_gate.py` independently reconciles the named result inventory,
frozen sources, effective domain confinement, kernel limit observations, stop and
reset records, host snapshots and quarantine byte hashes. CI runs inert channel
tests and compilation only; local KVM results must be recorded separately with
the exact effective sources. Earlier FAIL evidence is retained.

## What is still required to close an operational hostile-code gate

1. Select a real supported profile and its input contract: e.g. an offline Linux
   process, rather than silently accepting every executable/document/browser.
   Current tools accept fixed synthetic cases only. An arbitrary sample's
   immutable bytes/hash, type/size, provenance and single-job authorization need
   a separately reviewable admission adapter; no such launcher is enabled here.
2. Exercise the **same eventual adapter and publication path**, including failed
   input, cancellation, descendant escape attempts within the defined profile,
   unknown-stop refusal and data-only extraction. The matrix does not validate
   arbitrary guest filesystem parsers or claim compatibility with all binaries.
3. Independently review effective image/kernel/QEMU/libvirt/mitigation/resource
   and protocol/storage policy plus the failure results, freeze their hashes and
   explicitly disposition platform update status. Any material isolation change
   invalidates the affected evidence. A test suite alone cannot satisfy I08.
4. Keep live browser/collector/gateway acceptance, real-target authorization,
   Windows/other architecture profiles and R08 separate. A no-NIC PASS does not
   authorize reattaching networking during hostile execution.

Recorded outcomes and exact-head CI belong in the PR and the local evidence
report. No general-hostile gate closure is inferred from a scheduled run or
from the presence of these test sources.
