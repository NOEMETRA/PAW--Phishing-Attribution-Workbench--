# P3 actual acceptance checkpoint

The representation handoff passed actual owned acceptance on28 October2026,
on Root release `5884889ad5d08e1333197c5b12a219587815b5ba` (PR127), with reviewed
head `d6986252715e05672f92eda24fca91808464fbb9`. Its completed structured code review
had no findings or unresolved findings; all seven required head checks and all
seven main checks passed, and both commits have the same source tree. The
installed limited operator independently verified promotion without a password.
This documentation-only checkpoint closes P3 when its own review/head+main CI
and maintained source-equivalence checkpoint pass. P4 and P5 remain open.

## Actual execution and custody

Each profile completed six validation cases and two fresh PAW smokes through
`python-owned-v2`, one profile per call. All inputs were immutable-generated
harmless fixtures. No real specimen, real-source grant or egress was used.

| Evidence | Python | HTML/browser |
| --- | --- | --- |
| Engine profile | `linux-python-offline-v1` | `linux-chrome-html-offline-v1` |
| Root job | `fcb56e9c5e1f4cff819c9bfc63cdaac9` | `e14cc91636e947a4bcb2511d9bdd6bae` |
| Selected parser payload / original | PASS | PASS |
| Partial Base64 representation | PASS | PASS |
| Quoted-printable representation | PASS | PASS |
| Paused startup refusal | PASS | PASS |
| Owner loss | PASS | PASS |
| Protocol loss | PASS | PASS |
| Source PAW→VM→sealed sidecar | PASS | PASS |
| Installed PAW→VM→sealed sidecar | PASS | PASS |
| Maximum observed fault stop, seconds | 1.071973 | 0.712809 |
| Source / installed smoke stop, seconds | 1.500819 / 1.001308 | 1.000104 / 1.000471 |

The intentional fault executions remain failures. Their verification PASS means
the expected refusal/fault, exact custody, known external stop and absence of
publication were verified; it does not mean the specimen completed successfully.
The fault and smoke timings above are the published observations, not a claim
that an independent ordinary reader measured every private VM audit. Normal
execution and fault verifiers also enforce the existing stop bound below12s.

For each profile the actual live busy-lock refusal, changed-parent/digest
refusals, eight durable replay refusals and unknown-stop publication refusal
passed. Root reconciled the exact source/request/grant/consumption/job and the
preserved runtime inventory, image and VM controls. Domains had no NIC, shared
filesystem or host device. No client overlapped a guest.

The independent ordinary reader reconciled the published Root validation and
acceptance records, complete immutable client snapshot, ten stored kernel and
terminal client observations per profile, four actual source/installed sidecars
and their opaque artifacts, seals and bindings. All client observations retain
UID/GID1000, no supplementary groups, zero capabilities including bounding,
NNP, separate network/mount namespaces and256MiB/zero-swap/32task/50%CPU limits.
The Root recipe separately requires these observations and whole-cgroup stop
before every client phase can succeed. Raw per-VM audits remain Root-private
and are verified by that reviewed Root code; they were not independently read
by UID1000. This trust distinction is part of the acceptance scope.

A separate final audit rechecked all12 original source/installed forensic cases:
exact original bytes, complete initial file inventories, known writer stop and
Merkle seals remain unchanged. All108 actual installed Python sources equal
the source checkout. Four separately sealed sidecars completed with the expected
output; their imports did not replace a parent case or modify its scoring.

## Scoped readiness and maintained state

Each24hour representation I08 receipt binds its profile/context, validated
matrix and verified full-head review/CI proof. The two final analysis-mode
grants per profile were still for owned fixtures. Acceptance checkpoints were
installed only after both smokes and reader publication completed. Existing
revocation/expiry predicates continue to reject missing or stale readiness.

| Binding | Python | HTML/browser |
| --- | --- | --- |
| Validation SHA256 | `d6ce908de4f9079f85fe6fc4a91cbfda0eecf5755ef49029ecff38804ef096b2` | `40fc152ead8f9865b50bc266e2eed877b564531bcc4f30e955b37c168c884a83` |
| Acceptance SHA256 | `0c34d1fb7f98dd0896767ad7753ef22905c7da7858febf6cec3b90904828a9d2` | `8c5b94268d8e4046f2886c5a15974ff2cac602c55d2d7e999833fd7dcaf52047` |
| Readiness SHA256 | `d35dff7278bfc1e7a987d265579827c51cf2c16fe787d016b6149e8cf8596ffa` | `066387f283afac434ecad3a765bc8a0af8106b7c993b897e9a76bda75eac6472` |

The accepted runtime has234 manifest files:108 PAW sources and126 lab files.
Its source inventory SHA256 is
`de655f554129c52190ab234c62710490314997b56836a2a66d57e4323bda3eb6`;
the promoted Root manifest SHA256 is
`a08d391d55f85cfd532bf4099ecc56f2f3d2b19c1e776abd0b7d51537b223db9`.
The lab remains at2GiB, zero swap and128tasks; parent and guest budgets,
mandatory controls and trusted images were not expanded.

Fresh job `c6977ef6727a40dba02b9df7e06bb390` then checked current cached acceptance
through the same fixed recipe. The reviewed Root code returned PASS with
`profile:null`, identifying its explicit already-accepted/no-VM branch.
55 independent readonly domain/QEMU observations were empty. The job service
and its cgroup were gone; final domains, active libvirt networks and network
namespaces were empty.
The sampled observations are not described as continuous independent tracing.
Protected operator status and the active release were unchanged.

The private194-member archive `S14-VM-P3-acceptance-5884889.zip` contains the
gate/promoter records, published Root attestations, actual original cases and
sidecars, independent audits and cache observations. SHA256:
`217e2c18b4731aac724126099645aa34bab12ba8a9197862e3e6ba71fc7a4d3f`.
It stays outside Git alongside `vm-p3-closure-audit.json` and the durable project
state. Failed earlier attempts and their archives remain preserved; see
[the owned recipe](representation-owned-recipe.md) and
[runtime diagnosis](vm-runtime-revalidation.md). No dirty historical snapshot
was repaired, admitted or deleted.

## Remaining scope

This closes the selected-representation handoff for the two existing profiles;
it does not establish generic safety for hostile or arbitrary software, source
authenticity, classifier accuracy or attribution. Real input still needs explicit
approval for its hash and a current applicable gate. Automatic recipes continue
to accept only their generated harmless fixtures.

P4 must add the declared POSIX-shell and native x86-64 ELF profiles, plus
standalone JavaScript only through an explicit browser representation, with
their own finite normal/fault acceptance. P5 must consolidate current installed
integration for every supported profile, batch/cancel/crash/recovery/replay,
cleanup, revoke/rollback/restart and passwordless operational acceptance. The
review monitor and long-term goal stay active until the complete P0–P5 contract
is satisfied; this P3 checkpoint is not project completion.
