# Finite representation acceptance (P3)

The existing reserved ordinary recipe `python-owned-v2` now implements staged
acceptance of the two existing representation profiles. It takes no source,
profile, path, interpreter, command or service property from its caller. One
pending profile runs per bounded job: Python first, then the HTML companion on
the next call. Each has six validation vectors and two source/installed PAW
smokes. Both current acceptances make a later call start no new VM. The old
`browser-owned-v1` nine-case recipe and the no-guest `vm-acceptance-v1` recipe
retain their behavior. No static polkit/entrypoint policy changes are required.

This is implementation for review and subsequent owned acceptance, not proof
that either new live matrix or I08 has passed. The active Root snapshot remains
unchanged until independently gated promotion. It supersedes the producer
contract's earlier statement that no recipe called the new libraries.

Before runtime changes, the recipe verifies its exact active physical release
and the existing full merged release contract against protected enrollment
policy. Clear full-head review, all required head/main CI, ancestry, owner and
lease remain mandatory. A native candidate proof cannot authorize this recipe's
readiness. The client is fixed to this PC's enrolled UID/GID1000. Maintained
runtime revalidation then checks guards, resources, images and zero work before
starting only the existing fixed daemon/slice prerequisites.

Client code is a complete verified Root snapshot copy under a separate protected
reader tree. Mutable acknowledgment metadata stays outside that copied runtime
inventory. Client workspaces are new UID1000-owned directories below a protected
Root parent. Root never writes caller-owned paths after handing them over.
Requests are later read through bounded descriptor-relative no-follow access;
caller paths and PASS claims are not authority. Root independently matches the
fixed owned nonce/original/selected bytes and profile, exact request hashes,
parent manifest/index/root and original byte file, and fingerprints the complete
original case before/after the VM and client collection.

Each client runs in a fixed transient service bound to its parent owned unit.
The native `env -i` and `setpriv` prefix clears inherited environment and drops
real/effective/saved/filesystem UID/GID to1000, supplementary groups and all
capabilities including bounding/ambient sets before the user-writable venv.
No-new-privileges is mandatory. The client itself checks these kernel fields and
waits before importing PAW. Root independently observes its actual service PID,
start identity, kernel status, separate network/mount namespaces and applied
cgroup limits, then writes a protected nonce/tag/PID-bound acknowledgment.

The child has a private network and temporary directory, IP deny, readonly
system/home, inaccessible host session/libvirt/system buses and only its owned
workspace writable. Its limits are256MiB, zero swap,32tasks,50%CPU,180seconds
and8MiB per file. It belongs to the existing2GiB/128task laboratory slice. Root
stops the whole dedicated service cgroup, verifies its removal and absence of
the observed process before another client/VM. No client overlaps a guest.
The parent remains within its existing512MiB/64task/1800second limits; guests
retain their existing budgets, images, no NIC and mandatory controls.

The validation sequence explicitly selects parser/original, partial Base64 and
quoted-printable representations, then tests paused startup refusal, owner loss
and protocol loss using fresh one-use requests. Fault injection subclasses the
same low-level backend without substituting old authority. Root records actual
VM/admission/owner/serial and stop witnesses. The failed-execution verifier
reconciles the full request/grant/ledger/source/snapshot/job inventory, image and
VM controls, known external stop and absence of quarantine. A failed owned
fault is never mislabeled successful execution. Normal vectors require the
expected completed output, not just an infrastructure PASS.

The live global busy lock, changed-parent/digest refusals, durable replay and
unknown-stop publication refusal also pass before the immutable validation
record is saved. Only its verified digest and the protected current full release
review/CI proof may create the context-bound24hour I08 receipt. Two fresh owned
analysis-mode requests then exercise actual source and installed PAW collection
into separately sealed sidecars. They must complete with the expected output;
Root checks the exact published request/receipt/artifacts and unchanged original
case. Failure revokes only this attempt's new receipt and writes a durable FAIL.
No new acceptance checkpoint is installed until both smokes and reader
publication finish. Root checkpoints bind context, readiness, validation and
acceptance hashes; expired/revoked readiness cannot authorize cached reuse.

Only immutable-generated harmless bytes receive automatic grants. Analysis-mode
grants in the final smokes are still for owned fixtures: real-source grants
issued remain zero. Readiness is local scoped operational evidence, not remote
attestation, source authenticity, classification accuracy or generic escape
resistance. Real input keeps its explicit hash approval and applicable gate.

Unprivileged suites cover serialized fault custody, real PAW case/request phases
and sidecar seals with explicit inert reader substitution, fixed commands,
kernel identity shape, atomic acknowledgment/terminal failure, full release
proof, staged recipe ordering/rollback and readiness revocation/expiry. Root,
systemd, physical hardware and VM boundaries in these tests are explicitly
substituted. A harmless ordinary-UID child tests only NNP and correctly fails
the complete privilege-drop predicate. Actual Root/KVM/namespace/resource,
source/installed handoff and I08 acceptance remain mandatory after review/CI
and promotion. P3 cannot close on these unit results; P4/P5 remain open.

The lab inventory stays126/128 files. New logic is consolidated in existing
producer/client/verifier/worker modules; tests stay outside the privileged
inventory. Scoring, originals and consolidated bridge/audit contracts remain
unchanged. The serialized test fixture's grant/consume clock now follows policy
creation, correcting a reproduced second-boundary fixture race without changing
the actual authority's lease checks.
