# Explicit representation adapters and opaque custody (P3)

`lab/s14/representation_adapter.py` adds Python and HTML adapters for the
separate representation authority. The input is a validated full forensic
request: parent case/seal, original source, graph/derivation, selected node and
exact selected bytes remain bound. It does not masquerade as an unambiguous
MIME attachment or accept existing attachment grants. Guest jobs carry
`root-representation-grant-v1` and the selection binding as their parent hash.

Both adapters require Root before acquiring the existing global execution
lock. A busy host, insufficient existing memory/disk admission or mismatched
profile refuses. The separate authority reobserves the maintained immutable
context and consumes an exclusive durable grant ledger before creating a VM.
Authority/context are checked again after boot and before private quarantine.
The admission clock is retained so a job that finished after grant expiry is
checked against its actual admission, rather than silently renewed. HTML also
checks the seeded job, source length/hash and immutable media before/after use.

The Python adapter reuses the established low-level Python VM lifecycle;
the HTML adapter uses the existing BrowserVM and browser outcome validator.
The existing images, trusted guest brokers, no-NIC XML, nonroot identities,
AppArmor/seccomp, VM/cgroup limits, output budgets and external stop remain
unchanged. The aggregate laboratory remains2GiB with zero swap. A requested,
closed supervisor is required for publication; Python binds its existing
two-field supervisor result to the protected VM-ready UUID, while HTML's
existing result directly includes its VM UUID. Failed/protocol/unknown-stop
paths stop the active VM and cannot publish normal output.

The resulting quarantine is private intermediate data. It is not yet the
trusted external Root export or a sealed PAW sidecar. A future reviewed
producer must independently verify it before publishing. No operator recipe,
new command, Root store initialization, readiness installation or actual guest
activation is added by these libraries. The no-guest runtime revalidation
recipe retains its original meaning.

`verify_representation.py` independently reads the serialized audit, full
request/policy/grant/ledger, guest admission, owner result and bounded ordinal
quarantine. It reconciles exact request/parent/context hashes, one-use
consumption and admission clocks, VM/process identity, known external stop and
unchanged host/source/image observations. Existing physical Python VM checks
and HTML XML/image/sandbox checks are retained. For Python the ready PID and
process start identity must also match the recorded QEMU identity. Output is
opaque; successful integrity or execution is not an origin, risk or
attribution verdict.

The audit includes a complete release manifest/proof and exact selected PAW
and lab source copies, not just a lab digest asserted by the report. Their
canonical inventory binds the authority context. Extra directories, changed
files/proof, symlinks, hard-linked files and malformed relative paths refuse.
New reads use bounded descriptor-relative regular-file access. Lab source
copies are independently bounded and checked against this inventory. The
offline copies prove custody consistency, not independent Root provenance or
remote attestation. Root provenance still requires the future controlled
publisher. Analysis-mode verification additionally requires this namespace's
context-bound readiness; owned-validation never substitutes for it.

The unprivileged tests use synthetic forensic cases, real temporary grant and
snapshot serialization, byte hashing and opaque quarantine. VM channels,
privilege, Root ancestors and physical hardware/image checks are explicitly
substituted. They exercise both profiles and refusal of busy/unprivileged
calls, bad seed, owner/protocol loss, unknown stop, wrong parent/grant/ledger,
damaged/extra snapshot data, output changes and filesystem substitution.
They do not establish actual VM acceptance or I08. Mandatory CI runs these
tests without Root or VM access; existing authority/client and VM controls
remain covered separately.

The new authority-copy parent originally inherited permissive caller umask
through recursive directory creation. An owned filesystem regression reproduced
mode0777 under umask000 before correction. Creation now uses the existing
descriptor-relative protected subdirectory primitive for both levels, producing
mode0700 independent of umask and refusing substituted/writable existing paths.

P3 remains open: the reviewed finite owned producer and fault matrices,
actual PAW-to-VM-to-PAW source/installed handoff, one-use replay and scoped
I08 acceptance are still required. P4/P5 follow. This increment adds two lab
files, bringing the supported inventory to124 within the existing128 cap;
new tests are outside that privileged inventory. It changes neither scoring
nor original evidence, existing bridge contracts, host privilege delegation,
automatic real-source authorization or network policy.
