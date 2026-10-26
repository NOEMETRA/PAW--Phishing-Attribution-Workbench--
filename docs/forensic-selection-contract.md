# Explicit forensic selection custody (P3 client boundary)

`paw lab-representation prepare --case CASE --node EXACT_NODE_ID --profile
python|html --output NEW_DIRECTORY` prepares a request from a completed,
externally stopped and verified `paw-forensic-case-v1` case. The caller must
choose a graph node and a profile. There is no implicit preferred recovery,
extension-based profile choice, launch, grant issuance or origin authentication.
`lab-offline` retains its existing strict attachment contracts unchanged.

The new `paw-s14-representation-request-v1` binds the case manifest, Merkle index
and root, original source length/SHA256, exact graph and interpretation-report
SHA256, case coverage, selected node ID and its complete ancestor DAG. Each node
retains transformation name/version/parameters, parents, completion/notes and
byte digest/length. Node IDs use the existing graph canonical JSON without a
newline; the enclosing request uses the existing bridge canonical JSON with a
newline. Repeated payload bytes under different interpretations still have
different selection bindings. The selected bytes are copied exactly as opaque
hex. No transformation, parser, interpreter, browser or guest is run by prepare.

The candidate schema and custody statement are distinct from both attachment
profiles. It states `operator-selected-forensic-representation`, no verified
origin, no authenticated interpretation and `execution_authority: none`.
Partial candidates can be selected explicitly; their partial ancestry and the
case's interpretation coverage remain bound. A successful integrity check is
custody evidence for these claims, not a proof that a transformation is correct,
that the source is authentic or that the selected bytes are safe.

Limits remain finite: eight MiB original,64 graph/ancestor nodes, depth8,
8192 metadata bytes per node,24 MiB aggregate representation lengths,768 KiB
graph file, four MiB interpretation report and two MiB request. Selected HTML
is at most512 KiB; Python is at most16384 bytes, strict UTF8 and without NUL,
matching its existing finite execution profile. These checks do not compile or
execute Python. Empty selections and other execution profiles refuse. The
request has a unique ID and a lease of at most900 seconds. A seal, explicit
selection or lease alone grants no execution authority.

All case reads recheck the existing live-writer/known-stop contract and complete
seal. Graph canonical identities, topology, exact original and selected blob
are checked; blob paths are generated from digests, never caller input. The
request directory is private0700 and request/candidate files0400 even under
caller umask000. Case/scoring/old MIME files are never written. Unsupported,
stale, changed, live, unknown-stop or cross-parent inputs refuse before creating
the destination. These are bounded library/CLI checks, not OS isolation.

`paw lab-representation import --case CASE --request REQUEST --output
NEW_DIRECTORY` accepts only this contract's root-protected export namespace,
`/var/lib/paw-s14-representation-exports/REQUEST_ID`. Root-owned, non-group/other
writable directory ancestors/files, exact request bytes and a finite opaque
inventory are required. The receipt binds profile, selected-byte hash, full
selection/request/candidate hashes, separate grant/consumption/readiness/policy,
image/context/source inventory and contract hashes. It requires an empty guest
NIC inventory, known stopped writers, a finite stop time below12 seconds and
execution admission inside the request lease. Historical imports retain their
original admission time. Execution failure/timeout/cancel/resource statuses are
evidence, never verdicts. At most four opaque artifacts,1024 bytes each, enter a
separately sealed private sidecar; no output is executed, rendered or treated as
instructions. The original case is reverified before publication and unchanged.

The client validator checks the receipt's shape and bindings; actual producer
trust depends on root-protected publication. User-created JSON cannot establish
that trust. Old Python/HTML receipt/grant namespaces do not authorize this
contract. Root publication is a local trust boundary, not remote attestation.

This increment does **not** implement or enable the representation-scoped root
grant issuer, producer or I08. The namespace is absent on the development host;
import refuses until a separately reviewed producer/gate exists. Source and
installed CLI tests cover six owned original/parser-selected/recovered HTML and
Python cases, exact bytes and17 refusals per mode. Inert receipt tests exercise
sidecar sealing and unknown-stop rejection with deliberately substituted test
fixtures; they are not root, VM, replay or isolation acceptance. P3 remains open
until its independent one-use authority, actual no-NIC adapter, scoped I08 and
owned normal/fault/replay acceptance pass. Current libvirt restart/readiness is
also still required before new guest work. No password or new privilege rule is
needed for this client increment. Real inputs remain excluded from automatic
development/acceptance.
