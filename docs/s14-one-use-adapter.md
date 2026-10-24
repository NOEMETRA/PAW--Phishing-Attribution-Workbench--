# Owned one-use offline adapter and I08 review boundary

This acceptance runs only explicitly owned harmless synthetic fixtures on the
current Linux PC, with no NIC, host filesystem share or real target. It does
not enable hostile code, arbitrary Python or a production PAW detonation route.
The candidate inspector remains data-only. Original analysis/scoring/case seals
and the existing fixed-fixture PAW prepare/import contract are unchanged.

## Authority and lifecycle

The new operator adapter takes exact candidate bytes plus an installed I08
freeze. `one_use_authorization.py` walks the fixed root-owned directory
`/var/lib/paw-s14/authorization-v1` with no-follow descriptor-relative opens.
Policies/grants/consumption records must be regular root-owned files without
group/other write permission. There is no caller-selected authority directory,
HTTP endpoint, privileged daemon or grant creation during ordinary PAW analysis.

The freeze binds image SHA256, all lab source hashes, running kernel, installed
QEMU/libvirt/microcode versions, effective guard fingerprint, SMT/AppArmor state,
mitigation status/boot policy and actual aggregate cgroup limits. Policy expiry
is at most 24 hours. Any changed context refuses; restarting/rebooting/upgrading
requires a new effective review where affected evidence changed. Versions and
hashes establish measured scope, not absence of vulnerabilities.

An explicit root operator issues a <=15-minute grant for a single candidate ID,
exact frame/canonical candidate/source/parent-reference hashes and policy hash.
The candidate lease also bounds the grant. Candidate/provenance/parent hashes
alone confer no authority or PAW custody/authenticity. This revision additionally
requires exact membership in `owned_grant_fixtures.SOURCES`; neither a policy
boolean nor a matching digest can admit an unknown source. The policy requires
`hostile_code_authorized=false` and a synthetic-only maintenance disposition.

A nonblocking root-protected global flock prevents concurrent adapter callers.
Before creating any VM, an exclusive O_EXCL file in the global `consumed/`
namespace records the grant/frame/policy hashes and consumption time. Files and
directory metadata are fsynced. Any later startup failure/cancellation consumes
the grant permanently; retrying with another output directory cannot replay it.
Failed writes also fail closed. There is no automatic ledger reset/garbage
collection. Busy/locked/expired/missing/changed/untrusted grants refuse before
VM creation. Scope IDs are not passwords or remote signatures.

Both the legacy catalog and granted adapter use `_run_admitted_job()` for the
same seed/start/revalidate/execute/stop/quarantine/finally lifecycle. The granted
adapter rechecks the installed grant, consumption record and effective context
after boot, before source execution. Input is never compiled/imported/executed
on the host. The existing guest controller verifies source/job hashes, executes
as UID/GID 65534 with no capabilities/no_new_privs/null stdin, confines the whole
job cgroup and returns bounded opaque stdout/stderr only. Unknown stop never
publishes. This local synchronous API supports one owned gate/caller at a time.

## More restrictive effective CPU policy

The granted gate disables AVX, AVX2, FMA/F16C and XSAVE-related features in its
libvirt CPU definition, and checks their disable policies in effective XML
before resume. The positive harmless guest asserts AVX/AVX2/XSAVE are absent
from its visible CPU flags. This is separate from earlier host-passthrough
fixtures. The [kernel GDS documentation](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/gather_data_sampling.html)
describes the host's AVX-disabled fallback; host/guest CPU policy still requires
review. This probe is not an exploit test or certification against guest kernel
compromise or all microarchitectural attacks.

Inherited limits remain guest 512 MiB, host QEMU 768 MiB/64 tasks/zero swap,
CPU 50%, eight I/O workers, no core dumps, 256 MiB per-file cap and aggregate
2 GiB/128 tasks/zero swap. Guest jobs retain 64 MiB/16-task and CPU/file/FD
limits. No extra memory or network capability is granted for this acceptance.

## Acceptance and I08 disposition

`granted_offline_matrix.py --synthetic-acceptance` is a separate explicit root
PID1 operator command with bounded output/export paths. It creates fresh
transient AUTODESTROY domains/overlays for positive completion, expected failure,
timeout with a stubborn descendant, cancellation, output overflow, paused-startup
refusal, owner loss and real serial protocol failure. It retries every grant
under a new output directory and checks unknown-stop publication separately.
Unknown-stop is an inert publication-state check, not a claim to have made a
real VM unkillable. No untrusted guest filesystem is mounted on the host.

The independently invoked read-only `verify_granted_offline.verify()` reconciles
all eight cases, global/local ledgers, hashes/leases, frozen sources, UUID/PID
identities, effective XML/DAC/AppArmor/seccomp/CPU/memory/I/O limits, stopped
writers, known fixture outcomes, ordinal quarantine and host/base/canary
restoration. An audit copy is user-owned and not an authority grant. Root grant
and consumption files remain protected; passing an audit reader does not create
a remote attestation. CI uses inert filesystem/owner-role substitutions and
stub VMs only; it must never be described as actual root/KVM isolation evidence.

I08 must review the captured effective context, actual acceptance/failure results
and maintenance record independently. Refreshing APT indices is not a security
certification, and no upgrade/mitigation change is silently accepted. Actual
results, producer heads, CI and review receipts belong in the PR and local
hash-inventoried evidence. Source review alone cannot close I08. A synthetic-only
I08 disposition does not authorize hostile inputs; broader input authority,
maintenance acceptance, actual PAW noncatalog custody and other interpreters or
browser/egress remain separate material contracts.

## Measured eight-case repeat, 24 October 2026

Producer `a3ae0d655a7e96f5c18a6980ea80e31990b44e24` completed the actual
same-PC root PID1/KVM matrix: eight cases PASS, 71 frozen lab sources, stable
pre/post effective context, max stop 1.001 seconds, unchanged host/base/canary,
global replay refusal for all eight grants and no residual domain/QEMU/netns.
The root store contained one policy, eight grants, eight consumption records and
one execution lock, all root-owned with no group/other write. The driver refreshed
APT indices successfully with Error-Mode=any and installed/upgraded no packages.
Independent local read-only reconciliation also passed. The original PAW case's
34 files remain byte-identical. These are runtime measurements, not CI fixtures.

The sanitized [effective review record](s14-i08-effective-record.json) binds
policy/context/cases/authority hashes, actual resource/CPU/DAC controls, fault
witnesses and maintenance status. Full raw local evidence is retained separately.
This documentation-only follow-up does not change any of the 71 measured lab
source bytes. No additional runtime result is inferred for a different source
revision. The record explicitly requests independent I08 review; its existence
and the passing matrix do not themselves complete that review or authorize
hostile sources. Hostile-code authorization remains false.
