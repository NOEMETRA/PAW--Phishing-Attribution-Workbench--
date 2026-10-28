# Finite Linux source custody

P4 adds `paw lab-native prepare/import` for an explicitly selected sealed
forensic shell or AMD64 ELF representation. This client transports bytes and
imports opaque evidence. It starts no process in a guest, invokes no host
interpreter/ELF loader/ldd/compiler, issues no grant and installs no readiness.
The existing `lab-representation` Python/HTML schemas, implementation and limits
remain unchanged. Both namespaces reject each other's request/receipt frames.

## Request and admission

`prepare --case CASE --node NODE --profile shell|elf --output NEW_DIRECTORY`
requires a completed sealed forensic-representation case with externally known
writer stop. It binds its case ID, manifest/Merkle references, original byte
length/hash, graph/interpretation digests and the selected node's complete
ancestor chain. It never guesses a node from extension, shebang or media type.
Original files and scoring are unchanged; output must be outside the case.

The distinct `paw-s14-native-request-v1` contains a
`paw-s14-native-candidate-v1`, a fresh request ID and a lease of at most900seconds.
Its source is exact opaque hexadecimal bytes: no UTF-8 rewrite, shebang
substitution, ELF relocation or extraction occurs. Structural admission uses
the [finite Linux profiles](vm-linux-profiles-contract.md): shell at most64KiB,
strict UTF-8 without NUL; ELF at most1MiB with the declared AMD64/ABI/segment
checks. A recognized header does not promise guest loadability or safe behavior.
The new request limit is4MiB to accommodate1MiB hexadecimal source plus bounded
lineage. Existing P3 limits are not increased. Shared lineage parsing retains
its64nodes, depth8 and24MiB aggregate limits; JSON is bounded by size, depth and
node count with duplicate keys/nonfinite numbers rejected.

`bridge_contract_sha256` covers this implementation, the reused P3 lineage
validator, the finite native admission implementation and shared file/JSON
helpers. A future Root authority must additionally bind the complete immutable
runtime inventory and maintained image/context. Custody and structural metadata
claim no authenticated origin, approved execution, classification or attribution.
Preparation writes a new0700 directory and exclusive0400 request/candidate files.

## Separate opaque result

`import --case CASE --request REQUEST --output NEW_DIRECTORY` requires a matching
`paw-s14-native-result-v1` with producer kind
`local-root-verified-native-no-nic-v1`, under the distinct fixed
`/var/lib/paw-s14-native-exports/REQUEST_ID` namespace. Every ancestor and file
must be Root owned and not group/world writable; symlinks and arbitrary export
paths are refused. No client-supplied JSON is sufficient to create that authority.
The future producer must create this anchor securely and publish only after its
independent verifier has established the complete stop and custody chain.

The receipt binds exact request/candidate/selection/source/profile identities,
VM UUID, image/certificate and runtime inventory, job/raw-result/policy/grant/
readiness/consumption/context/contract digests, admission/completion times and
known writer stop with zero VM network interfaces. Unknown outcomes, nonfinite
or excessive stop times, missing authority digests and mismatches refuse.
At most4 opaque artifact-NN.bin files, each at most1024bytes, are accepted;
extra files, traversal names, changed request bytes or artifact digests refuse.

Import may occur after request expiry; the protected receipt must prove admission
inside the original lease. This does not renew a grant or authorize another
execution. The case is rechecked before and after collection and sealing. Output
is a separate sealed sidecar with private directories/files, including under a
permissive caller umask. It does not execute or reinterpret output, modify the
original case or authenticate the source. Local Root protection is a deployment
trust assumption, not remote attestation. Failed collection is not published as
a result.

## Validation and remaining gates

19 inert unit tests passed, including upper-size byte round trips, MIME-derived
lineage, cross-namespace/profile refusal, malformed/foreign/oversize input,
unknown stop, changed seals/blobs, link/path/refusal, lease/canonical JSON,
receipt bindings, corrupt/extra exports, historical import and a separate sealed
sidecar under umask000. Root custody is explicitly substituted for the positive
import fixture; this is not actual producer or KVM acceptance.20 existing P3
bridge tests also passed.

The actual source and installed CLI integration each passed10owned cases
(6existing Python/HTML plus4native: full-size shell, MIME-derived shell,
full-size ELF and PIE) and29expected refusals. The installed run used `-P`,
no PYTHONPATH/PYTHONHOME, PYTHONNOUSERSITE=1 and a directory outside the checkout.
The actual built wheel, installed package and source match across111Python
files; pip check passed. This local virtualenv copies the previously accepted
dependencies without a download; clean dependency resolution remains the four
required installed CI jobs. The fixed accepted Root-client venv is untouched.

P4 remains open. Native Root hash policy/grants/readiness, opaque ingress,
trusted guest/controller/adapter/verifier, actual normal/fault matrices and
source/installed VM handoff are still required. JavaScript's explicit HTML view
also still needs its actual browser handoff test. P5 operational acceptance
remains required. No Root release promotion, VM, real source or egress is enabled
by this increment.
