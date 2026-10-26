# Separate representation authority (P3 foundation)

`representation_authorization.py` supplies Root-only policy, grant and durable
consumption functions for `paw-s14-representation-request-v1`. It has a distinct
scope and store, `/var/lib/paw-s14/representation-authorization-v1`. Existing
attachment/browser/Python authority schemas and stores are unchanged. This
module is not a launcher, CLI or new delegated administrative command. The
ordinary operator still accepts only its finite named owned recipes; this
increment does not add a call to these functions in those recipes.

The exact full canonical request hash binds parent case/seal, original source,
graph and interpretation hashes, selected node/ancestor DAG, profile and exact
selected bytes. The grant also retains the candidate, selection, original,
graph and selected-node hashes explicitly. Approval is an exact request/source
pair; another request with the same payload bytes requires its own approval.
Only the existing finite Python and HTML execution profiles are recognized.
Unknown or future profiles refuse instead of inheriting a backend.

Context capture verifies the active immutable release using the protected
operator state and existing snapshot verifier. It binds the canonical files
inventory from that release, preserving source equivalence for documentation
changes. The underlying backend still checks its existing image, QEMU, CPU,
guard, resources and source predicates. Context also binds an existing protected
maintenance record whose hash/name and current platform binding validate.
Missing, stale or mismatched maintenance or a damaged/foreign snapshot refuse.
No vendor update or new maintenance approval is inferred from this module.

Policies bind the canonical context and its hash, preventing bool/int/float
coercion from making distinct JSON contexts equivalent. They contain1–32 exact
request/source approvals and expire within24 hours. Input request collections
are bounded before inspection. `owned-validation` requires a separate owned
manifest hash and carries no readiness. `explicit-source-analysis` permits only
one request and requires this namespace's protected, context-bound I08 receipt.
Readiness binds the actual matrix digest and review/CI references, with a
maximum24-hour lease. A well-shaped receipt supplied by an unprivileged caller
is not installation or authority.

Only Root may initialize the fixed private store, install policy/readiness,
issue or consume. Installation and issuance reobserve the actual active
context. Policy files must already exist with exact bytes in protected storage;
caller JSON alone cannot issue a grant. Root-only analysis readiness still
requires its actual matrix and reviewed producer integration, which this
increment does not enable. There is no automatic real-source approval.

Grants bind all request/context/policy/profile/source fields and expire within
the request/policy leases, at most900 seconds. Consumption rechecks actual
context, reads the installed grant and writes an exclusive, fsynced durable
ledger before a future adapter may create a guest. A duplicate consumption
refuses across calls; the adapter must also hold the existing global execution
lock and revalidate authority after boot/before publication. Those adapters and
their actual no-NIC normal/fault acceptance are still missing in this increment.
Root publication remains a local trust boundary, not remote attestation,
origin authentication, payload benignness or attribution.

16 unprivileged tests cover exact request binding, real temporary-file
grant/consumption/replay, uninstalled policies, changed actual context,
canonical type distinctions, old namespaces, lease/approval budgets and
readiness refusals. New capture tests use real immutable-file/source/hash
verification on ordinary temporary snapshots while explicitly substituting
Root ancestors/ownership and hardware/maintenance boundaries. They are not
Root runtime or I08 acceptance.48 client bridge,18 old-authority and90
operator/release regressions pass. The module imports using the system Python
without installing new system packages; case/seal fixtures run in the existing
clean dependency environment. New tests stay outside the privileged lab
inventory, which now has122 supported files within the existing128 cap.

The maintained runtime prerequisite itself passed on reviewed/promoted
`a6712a0c6fd872dc81ca4db3599df60b0b5a5fa3`: job
`97c17c15f99c4652a70c6e525fb76285` restored the inactive services in8312ms
without password, guest, active libvirt network, rule/route change or new
readiness. Root-owned reader evidence, independent cgroup/read-only libvirt
readback and terminal worker state were reconciled. The archive SHA256 is
`fb8a14436b6f302e998035b0177cee04fe3b43147460bdaf4d588cb7c317de23`.
The prior failed attempt remains preserved. This prerequisite does not close
P3; representation adapters/verifiers, actual owned PAW/VM handoff and scoped
I08 remain required, followed by P4/P5.
