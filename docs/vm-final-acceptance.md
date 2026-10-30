# Finite VM project: P4/P5 acceptance checkpoint

All declared runtime profiles and the bounded operational checks passed on
30 October2026, using only generated harmless inputs and no-NIC guests. The
active immutable Root release is `19d88876e8e2d452dc12df5daa42b847eeb63429`
(PR138), reviewed at exact head `fdf866ae2465a20a221e3c99ead162e9565f7b6d`.
Its authenticated structured review completed without findings or open threads;
all seven required head checks and seven main checks passed, with identical
trees. The limited operator independently verified promotion without a password.

This documentation-only checkpoint closes P4 and P5 only after its own clear
exact-head review, seven required head/main checks and source-equivalence
verification. Until then both phases and the monitor remain open. The239
selected runtime files must remain byte-identical to active PR138; no new Root
promotion, readiness or guest run is inferred from a documentation commit.

## Current execution and custody matrix

| Declared capability | Validation cases | Source/installed smokes | Final Root job |
| --- | --- | --- | --- |
| Existing Python | 6 PASS | 2 PASS | `c787708ad5fd4fc5ab05b9d8d4b6ab33` |
| Existing HTML/browser | 6 PASS | 2 PASS | `a8a0439e71904bf0bbedf6662df42166` |
| JavaScript through explicit browser representation | Uses HTML runtime validation | 2 maximum-size PASS | `0581fd62452c4cd3b7bf332d2192f22c` |
| POSIX shell | 12 PASS | 2 full64KiB PASS | `60a9594952c74099859808f65a4a7841` |
| Native Linux x86-64 ELF | 14 PASS | 2 full1MiB PASS | `1acd70dfaeb3486fa4b35ba1449d9c87` |

Python/HTML validations cover selected parser bytes, partial Base64,
quoted-printable, paused refusal, owner loss and protocol loss. Native validation
covers positive and explicitly derived inputs, nonzero exit, loop, fork/task
limit, output, memory, file limit, cancellation and the three fault cases.
ELF additionally tests static PIE and dynamically linked fixtures against the
declared trusted guest ABI. Shell has12 validations plus two smokes, not14
validations plus two. Native validation was partitioned into groups of at most
three VMs, with independently revalidated protected stage receipts and a separate
two-smoke call. No caller-selected source/path/command enters these recipes.

The JavaScript input remains exactly262144 bytes; its explicitly derived
Base64 HTML wrapper is349676 bytes. It is a browser representation, not a Node
or host JavaScript profile. Root regenerates both bytes and derivation before
grant issuance. A fixture-only correction removes the current script element
after setting its marker, avoiding a reproduced349676-byte URL echo into the
unchanged256KiB DOM budget. The fixed no-VM historical diagnosis first confirmed
that old job `ca8b61fc0c7b4d4f8288fe9ff63f131b` actually hit `output_budget`.
The former failed result stays preserved; it is not relabeled PASS. A separate
reproduced request-decoder boundary uses the already declared request limit
only for request-specific decoding; the generic decoder remains unchanged.

Every smoke passed the real source or installed PAW handoff, one-use grant,
known external stop, opaque export and sealed-sidecar import. Parent original
bytes, score/case state, manifest and Merkle seal remain unchanged. Wrong-parent,
changed-digest, replay and unknown-stop-publication refusals passed in the
applicable matrices. An expected error/fault gets verification PASS for its
correct refusal and cleanup; that does not describe successful specimen output.

Root verified each private VM audit, image/context/source binding and guest
controls. The independent UID1000 reader reconciled the protected published
attestations, complete immutable client copies, actual original cases and sealed
sidecars/artifacts, client kernel/terminal observations and terminal host state.
Raw per-VM audits remain Root-private; UID1000 did not independently reread them.
This acceptance relies on the reviewed Root producer and configured GitHub
review/governance authority. Hashes establish binding/integrity, not authenticity
or attribution accuracy.

## Controls and maintained readiness

Guests had no NIC, shared filesystem or host device. Nonroot guest execution,
fixed trusted interpreter/ABI, reset, private input media, bounded files/output,
wall/CPU/memory/tasks and external whole-tree termination remained mandatory.
Known external stop must be below12s. The aggregate remains2GiB, zero swap and
128tasks; Root512MiB/64tasks/1800s and UID client256MiB/32tasks are unchanged.
Native QEMU is768MiB with a512MiB guest. Browser QEMU is1536MiB with a1024MiB
guest; browser child/DOM/input limits remain the declared finite controls.
No available host RAM was used to enlarge privileged budgets.

The immutable manifest contains128 lab files and111 PAW files. Independent final
readback verified all239 source hashes and the actual installed111-file parity.
All five fixed privileged modules remain Root-owned0444 and byte-identical to
accepted P0. The active Root manifest SHA256 is
`793b1b3ef720ac8b6d9bd907ccb594f251fb5b13ec52d1b518bcbb2ffadcfae5`.

| Scoped acceptance | Readiness SHA256 |
| --- | --- |
| Python | `6f0657a2f4a6a4f5903e25bfeb6d0a2631224c4807dc09d14da211c3dd3e729f` |
| HTML and explicit JS representation | `88583f50536c068f69f14aa98dbfc99c00d234e1af1c8246a37ba6c0ac1d547f` |
| Shell | `31c29a5d9e3499257c70b33db4f4122bebdb34c725728b6d883c978cb2fc680b` |
| ELF | `b0b1dab3e7183811830dac12514f8f3f7bb878921974ad59f4cb591c109fa0cd` |

These24hour receipts are scoped to their measured contexts, not permanent
authority. Context drift, expiry, revocation or missing protected acceptance
invalidates reuse. JavaScript also depends on the current HTML readiness.
Historical releases do not supply current-context readiness. Maintenance
revalidation continues to check the installed images, QEMU/packages, kernel,
guard and effective platform; no maintenance predicate was disabled.

## Operational P5 matrix

| Requirement | Actual evidence and bounded interpretation |
| --- | --- |
| Full installed/source integration | All ten current source/installed VM smokes and sealed exports above;111-file installed parity and239-file immutable source proof. |
| Batch and partial accounting | Consolidated supervised CLI/API queue and partial batch evidence from P1/P2, retained with current required CI. VM recipes remain serial; this does not introduce bulk detonation. |
| Cancel/crash/recovery | Fresh current source and installed forensic runs each pass cancel, deadline and worker-loss on generated4MiB malformed quoted-printable bytes. Known tree stop, exact source and sealed partial results pass. Current VM matrices separately cover owner/protocol loss, paused refusal and Native cancellation; stage receipts allow bounded continuation without replay. |
| Replay and cleanup | Actual matrix/smoke replay refusals, busy lock and unknown-stop refusal; terminal services/cgroups, QEMU, domains, active libvirt networks and network namespaces were independently absent after final acceptance. |
| Rollback/revoke | P0 transactional failed-install recovery, revoke/refusal and native-authorized restore are retained. Fixed five-module parity preserves that implementation. Arbitrary old-release downgrade or a new destructive revoke/restore cycle is not claimed. |
| Restart and no-prompt use | Reviewed PR138 no-VM job `4caa222bbe3947f4814b69c3fb5cfccb` activated inactive local libvirtd and revalidated fixed daemon/slice/image/context. Final job `4a1458150c9d4af6a7aa8d74a6a7e4f5` found both units active and revalidated them; it did not restart them. No OS reboot is claimed. |

Final current-cache calls, each with stdin closed and no administrator prompt:

| Fixed recipe | Root job | Result |
| --- | --- | --- |
| `python-owned-v2` | `9c82fa13c9fb4757a26a1a4d0d784d9e` | PASS explicit all-accepted/no-VM branch |
| `shell-owned-v1` | `f95a7ad975564465bc7e06ed406b10e0` | PASS current protected cache/no-VM branch |
| `elf-owned-v1` | `da532938ab614ea680713ef40a81dfa9` | PASS current protected cache/no-VM branch |
| `vm-acceptance-v1` | `4a1458150c9d4af6a7aa8d74a6a7e4f5` | PASS maintained no-guest runtime |

The Root cache predicates recheck current context, unexpired/unrevoked readiness
and protected matrix/acceptance hashes. Ordinary sampled domain/QEMU observations
were empty, followed by independent terminal readback. Sampling is not continuous
independent tracing. An ordinary observer initially expected an empty diagnostics
object where the reviewed Native cache branch returns null; its failed observer
record is retained, the successful Root job was independently reconciled, and
only remaining calls continued. No completed job was replayed or product code
changed for that observer correction.

The same narrow polkit entrypoint, immutable Root code and finite recipe allowlist
remain installed. No login password, generic passwordless sudo or user-writable
code running passwordlessly as Root was introduced. Existing P0 installation
authentication and revocation/restore evidence remain historical, not repeated
authentication requirements for normal fixed operations. Operator enrollment is
leased; expiry or changes outside the reviewed scope may require intervention.

## Evidence preservation and closure gate

Private archives remain outside Git with original failures and positive proofs.
They contain only owned fixtures, published attestations and ordinary evidence;
Root-private audit files retain their existing protection. Current archive CRC,
file hashes, ownership/mode and case inventories were checked.

| Archive | SHA256 |
| --- | --- |
| `S14-VM-P4-PythonHTML-JS-PASS-19d8887.zip` | `4d130126b00000ad68687e89bff16cddf73d18a65ab8f31183a5488681e585ad` |
| `S14-VM-P4-SHELL-PASS-19d8887.zip` | `968f3798c8d22ca91fc85568d5ad33b67a4a0bfd3a355d66c433319ac084237c` |
| `S14-VM-P4-ELF-PASS-19d8887.zip` | `28e9e3f9118c17b7359736e3641fecf4fc12b389eddc939cf1934016867c7c3d` |
| `S14-VM-P5-consolidation-19d8887.zip` | `e8d166235d16922eaa94dd2b3d1bf357f9f60ae0009bb1c7ef9fd2ed518d5e62` |

The durable workspace records are `vm-p5-current-consolidation.json`,
`vm-p5-evidence-preparation.json` and `vm-project-state.json`. P0–P3 and all
intermediate review/head/main proofs remain preserved. This closure PR changes
only this document and the plan disposition. Its final main gate must verify
the documentation head/merge trees and all239 selected source hashes against
active138, plus current no-prompt status; it must not overwrite the Root release
or treat its own document as a new source-changing admission.

Once that documentary gate passes, record P0–P5 closed, stop the review monitor
and complete the goal. Until then the goal remains unfinished.

## Honest unsupported and future scope

The finite supported execution set is Python, HTML/browser, explicit JavaScript
through HTML, POSIX shell and Linux x86-64 ELF against the trusted guest ABI.
P1 still acquires other regular byte sources within its limits; P2 retains the
finite malformed MIME/HTML observations, errors and separate derivations.
Ambiguous/recovered bytes are never silently substituted for the original or
called authentic. Engine scoring and established contracts remain intact.

Windows PE/Office, other interpreters/architectures, unrestricted archives,
real egress, UI completion, classifier calibration and universal escape
resistance remain unsupported by this project's acceptance. No new real
specimen was executed or authorized. Future real input requires explicit
approval for its exact hash and an applicable unexpired scoped isolation gate;
neither project closure nor an HTTP success grants that authority.
