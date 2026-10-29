# PAW VM project: executable plan and closure contract

Owner instruction,25 October2026: advance both forensic analysis of malformed
sources and additional isolated execution profiles, using PR/review/CI, and
check progress every10 minutes until the finite VM project is accepted.
All work stays on this Linux PC. This plan supersedes the earlier VM deferral
for these explicitly authorized increments; consolidated engine audits remain
closed unless a defect is reproduced.

## Starting point

PR110 merged as `bbf7f643b6f415c4df961660c0f5bf7585eb5c71` after exact-head
review and7/7CI, with main7/7CI. The fixed no-NIC HTML profile passed nine owned
normal/fault scenarios and actual installed PAW→root→VM→PAW custody/privacy smoke.
Python is a separate existing profile. Neither readiness nor an HTTP success
means generic hostile-code safety. Real malformed MIME is currently preserved
and partially analyzed; ambiguous attachment bytes cannot enter the existing
HTML bridge. This is the concrete investigative need for the next capability.

## Automation and authority

The current chat heartbeat `paw-vm-review-e-avanzamento` is active every10 minutes.
PC and desktop app must remain running for local work. Scheduler delivery is
not proof that a job finished or authorization to bypass a gate. State lives
outside the checkout in `work/s14-local/vm-project-state.json`, relative to the
shared task workspace. Each continuation reads that state and this plan first.
No concurrent checkout mutation or change to frozen sources during a root run.

Administrator automation must not store a login password, consume a password
from chat, install generic passwordless sudo, or execute user-writable workspace
scripts as root. A one-time native admin installation is needed only after its
implementation is reviewed/tested. The mechanism uses a specific polkit action,
fixed root-owned entrypoint, explicit user identity and immutable root snapshots.
Authorization in polkit is not argument validation: the entrypoint validates
every command and value itself; `command_line` is not a security boundary.

Automatic promotion is a distinct privileged operation: independently verify
repository identity, immutable full commit, completed review, required exact-head
CI, merged/main state and a bounded release manifest. User-supplied local JSON
claiming that review passed is not authority. Automatic promotion requires the
bot's authenticated structured review state with a full40-character commit and
clear code/security disposition. A shortened prose receipt is insufficient.
Trust in GitHub/repository governance and the configured reviewer remains an
explicit deployment assumption, not remote attestation. Installation/update and
revocation must be auditable and fail closed on missing or stale proof.

Only finite named benign recipes may run unattended. They generate owned inputs
inside the reviewed snapshot; callers cannot choose host commands, paths,
interpreters, URLs, arbitrary systemd properties or arbitrary source bytes.
The existing global one-job lock, known external stop, root private input media,
resource budgets, image/context checks and opaque publication remain mandatory.
No automatic real-source grant issuance, egress or new real specimen execution.
Source-changing releases need their own maintained context and readiness.

## Ordered phases

| Phase | Deliverable | Required acceptance |
| --- | --- | --- |
| P0 | Credential-free narrow operator, immutable releases and independently gated promotion; review heartbeat and durable work journal. | Inert privilege/confused-deputy tests; root snapshot cannot be modified by the caller; generic pkexec/shell/workspace execution stays unauthorized; one native installation; no-prompt status and finite owned job; tampered/stale/foreign proofs, concurrent run, unknown recipe and revocation refuse. No password stored. |
| P1 | Bounded acquisition/inspection of any local regular byte source, independent of extension or text decoding. | Preserve exact bytes/hashes, unsupported/empty/binary input gets structured coverage, no lossy coercion or execution; finite input/output/CPU/memory limits; source-change/FIFO/network-path/error checks; actual source and installed CLI/export. Specialized interpretation is explicit, not promised for every format. |
| P2 | Forensic representation graph for malformed MIME/HTML. | Original wire, parser-selected bytes and explicitly derived candidates have separate identities, parent hashes, transformation version/parameters, errors and omissions. Handle a finite tested set of invalid Base64/QP, charset, duplicate-header/boundary and truncated-HTML cases. Never silently replace the original or label a recovered candidate authentic. Budgets bound expansion, count/depth and aggregate work. |
| P3 | PAW handoff for an explicitly selected forensic representation. | New versioned binding includes parent case/source, representation/derivation and exact executed bytes. Existing bridge contracts stay strict. Separate hash grant and no-NIC execution; untrusted output imported into a sealed sidecar, original score/MIME/case unchanged. Actual harmless variants, wrong-parent/digest/replay/unknown-stop/refusal tests and scoped I08. |
| P4 | Finite additional Linux execution profiles: POSIX shell and native x86-64 ELF; standalone JavaScript only through an explicit tested browser representation. | Separate trusted interpreter/ABI/profile and opaque ingress; nonroot guest process, reset/no NIC/no sharing, wall/CPU/memory/tasks/output/file budgets, tree termination and one-use authority. Owned normal/error/loop/fork/output/memory/owner/protocol tests per profile; no host ldd/interpreter/archive extraction or execution. No privilege or budget expansion inferred from available host RAM. |
| P5 | Installed PAW integration, maintained operational acceptance and final consolidation. | Full source/installed CLI handoff and sealed exports for every supported profile; batch/cancel/crash/recovery/replay/cleanup; immutable reviewed versions, current scoped readiness, rollback/revoke and restart/no-prompt checks. All phase PRs merged with required review and green head/main CI; honest PASS/FAIL/unsupported matrix and saved evidence. |

The declared execution set for this project's closure is existing Python and
HTML plus the P4 Linux profiles. Windows PE/Office execution, arbitrary other
interpreters/architectures, unrestricted archives, real egress, UI completion,
classifier calibration and universal escape resistance are separate future
projects. Such inputs remain acquirable as bounded bytes with explicit missing
interpretation/execution coverage; they are not mislabeled analyzed or safe.
Windows execution would additionally need a trusted/licensed guest image and
independently validated resources/isolation. These exclusions are not hidden
successes or a claim to support all possible software.

## PR and continuation protocol

1. Reconstruct actual state, take the next unclosed phase and reproduce the
   concrete boundary on owned inputs. Use a dedicated branch and coherent PR.
2. Implement only that increment. Preserve scoring, originals, evidence and
   existing supported/unavailable contracts. Do not publish real mail in GitHub.
3. Run meaningful unit/integration/installed checks. Request Codex review of the
   exact head. Every10 minutes check review and CI; queued review is not approval.
4. Reproduce actionable findings, fix only confirmed defects and request fresh
   review/CI for changed code. Never auto-resolve a finding without evidence.
5. Native root installation or finite privileged acceptance requires a concrete
   reviewed plan and green required checks. Use the installed limited operator
   when its trust/scope covers the action; do not invent broader authorization.
6. Merge only after phase criteria, review and all required checks pass. Verify
   main CI and immutable source equivalence; update evidence and work state.
7. Continue with the next phase. At actual P0–P5 closure, write the final matrix,
   disable the heartbeat and complete the goal. No completion merely because a
   turn ends, an input is unsupported, a CI job is queued, or work is difficult.

Native authentication, unavailable trusted images, external review/service
outages and resource limits must be reported accurately. Never infer approval
from elapsed time. Real samples keep explicit source/hash authorization and
their current scoped isolation gate even after unattended benign acceptance.

## Current disposition

PR137 merged as `d0a9dbd78f0170b85e3a5516337908ec5809e3cc`, after clear
review of exact head `54e3a8817563c34ff1edc2123fadfb748f12bf4d`, seven green
head/main checks, identical trees, installed111-file parity and independent
passwordless promotion. Current Python and HTML each completed six validations
and two source/installed smokes, independently reconciled. Their respective jobs
are `fcb4f9dd8e04447580c2e5239e27a49e` and
`d562829aaa7f4ddea77d63d4258d1fe2`; these PASS results are preserved.

The first JS smoke, job `ca8b61fc0c7b4d4f8288fe9ff63f131b`, stopped at the
expected-completion oracle. No JS acceptance was published. Independent terminal
readback found no active worker/client/VM, networks, namespaces or QEMU, and the
protected enrollment/release stayed unchanged. The full private guest outcome
is not yet claimed: the public diagnostic establishes the failed oracle only.

An ordinary-pipe regression using the actual guest drain/poll/finish code
reproduces the fixture's349676-byte script-URL echo exceeding the unchanged
256KiB DOM cap. Only the owned fixture now removes its own script element after
setting the title, retaining the full256KiB input and existing wrapper size.
This is not an increase in output budget or a change to arbitrary HTML handling.
A second real maximum-size request regression reproduces a generic256KiB JSON
decoder rejecting the valid roughly700KiB request before publication verification.
Only request-specific decodes use the already declared request-contract limit;
the generic decoder and independent schema/custody checks remain strict.

The same follow-up adds one fixed historical read to the existing no-VM recipe.
It pins that job/request/release/manifest and request digest, verifies the complete
protected audit and exports only typed outcome/status/counter/hash/flag metadata.
No raw DOM/script/console, caller-selected paths, guest start, grants or I08 are
introduced. Review/head+main CI and immutable promotion must precede this read.
Confirm the actual historical guest outcome before any new JS VM attempt; other
causes remain possible until that protected evidence is available. Final current
profile acceptance and P4/P5 closure remain outstanding.

PR136 merged as `644bb45ca8e29f85fa11803aed440a27911cdb34` after clear
exact-head review of `84f1c739dde0a77733df5a9ea0e5d3f9f59ed645`, seven green
head/main checks, identical trees, installed111-file parity and independent
passwordless promotion. Actual ELF acceptance completed all14 validation cases
and both full1MiB source/installed PAW smokes with sealed sidecars, unchanged
originals, monouse/replay checks and independently reconciled terminal cleanup.
The final job is `48ba8dec31d64735b8342eaeac8a03a0`. Its private194-member
archive SHA256 is
`41c265dbbc6778ec38945fa590b379d4aa15debb79357ea5b2ba01c178db08f6`.
Root-private VM audits remain protected; the ordinary observer verifies the
reviewed producer's protected attestations, exported custody and terminal host.
This is current-release ELF acceptance, not P4/P5 closure or generic code safety.

The next increment adds the finite maximum256KiB owned JavaScript→explicit HTML
handoff to the existing `python-owned-v2` recipe, after current Python and HTML
acceptance. Two source/installed smokes occupy a separate bounded call; no new
interpreter/profile, command, I08 authority or larger budget is introduced.
Root regenerates the exact source/wrapper/derivation before each grant. Its
separate protected acceptance marker depends on current unexpired HTML readiness;
missing/revoked readiness invalidates reuse. Review/head+main CI and immutable
promotion precede actual no-NIC browser acceptance. Final current-context
Shell/ELF/Python/HTML validation and the P5 operational matrix remain required;
Root source changes cannot inherit historical readiness. Historical Shell14/14
and ELF136 results remain preserved while JavaScript is implemented first to
avoid repeatedly refreshing contexts that will change again.

PR135's independently promoted no-VM job
`930ea9d87b5747fb8273c5a43b651b09` passed the strict integer diagnostic consumer
and found the exact historical readiness object. Its private archive remains
preserved. PR136 separately reproduced an emitter/decoder defect with the actual
trusted emitter, a byte pipe and unchanged strict Serial decoder: unterminated
console text hides the first frame. The native producer now starts every frame
on a new line, including partial writes; guest budgets and the strict decoder
are unchanged. The historical boolean alone did not establish its exact timing
cause; the fresh full ELF runtime acceptance above is the execution evidence.
An unrelated test fixture explicitly sets its intended0755 mode under022/077;
installer behavior is unchanged. No consolidated engine audit was reopened.

PR134 exposed a concrete producer/consumer mismatch: its no-VM worker exported
decimal boot times, then the unchanged static operator refused them as
`operator_proof_scalar`. The next correction encodes exact integer microseconds
and tests the actual strict private-result consumer. It does not relax the
decoder or start a guest. Boot facts read from the protected export show
cloud-init finalization near the deadline and a schema marker; they still do
not prove a particular underlying execution fix. P4/P5 remain open.


PR133's fixed historical no-VM diagnosis passed and confirmed an initial guest
readiness deadline, failed-service log marker and revoked receipt. It does not
yet distinguish a guest service/config failure from slow initialization. The
next finite addition extracts only bounded structured boot timings and fixed
service statuses from the same log; no new VM or budget change. P4/P5 remain
open and the underlying behavior is not patched on assumption.


Actual PR132 bounded acceptance completed Shell14/14 with source/installed sealed
exports and independent reconciliation. ELF completed all14 validation cases,
but its first final1MiB source smoke failed inside the backend; full ELF/I08
acceptance is not claimed. The next increment preserves missing public smoke
diagnostics and adds one fixed historical diagnostic to the existing no-VM
recipe. It cannot run a guest or choose arbitrary Root files. Review/head+main
CI and immutable promotion precede that read; only a reproduced underlying
cause will be corrected. JavaScript browser handoff/current-context acceptance
and the full operational P5 matrix remain open.


The first actual PR131 native Shell matrix reproduced the1800s parent runtime
limit during case8, with no full acceptance/I08 and verified terminal host
cleanup. The follow-up partitions the unchanged finite matrix into at most
three validation VMs per call, protected independently revalidated stage
receipts, then a separate two-smoke final call. It expands no budgets or caller
authority. This scheduling correction still requires exact review, head/main
CI, immutable promotion and actual staged acceptance; P4/P5 remain open.


The coherent [native runtime increment](vm-native-runtime-contract.md) adds
separate Root authority/controller/producer/verifier and fixed owned recipe
implementations. It retains the existing operator and budgets. Its local
inert/CLI evidence does not close P4: review/head+main CI, immutable promotion,
current installed client and actual no-NIC matrices/I08 remain required before
acceptance. JavaScript browser handoff and P5 operations remain open.

The next P4 [native custody client](vm-native-custody-contract.md) adds a
separate shell/ELF request/result namespace and CLI, with19inert boundary tests,
20legacy regressions and10source/10installed owned CLI preparations each with
29refusals. It issues no grant, launches no VM and leaves the P3 bridge intact.
Native authority/runtime/I08, actual VM acceptance and P5 remain open.

P4 starts with the [finite Linux admission and explicit JavaScript view](vm-linux-profiles-contract.md).
The first increment adds supervised CLI/HTTP forensic modes, bounded shell/ELF
structural metadata and a byte-preserving JavaScript→HTML candidate. It is not
native execution or a new grant issuer. Fifteen new unit tests,121 existing
representation tests and40 source/40 installed actual CLI/HTTP cases passed.
Distinct native custody/Root authority, guest runtime, actual normal/fault/I08
matrices and operational P5 acceptance remain mandatory. No Root snapshot or
VM is activated by these ordinary tests; P4 and P5 remain open.

P3 actual owned acceptance passed on28 October2026 on PR127 main
`5884889ad5d08e1333197c5b12a219587815b5ba`, after clear exact-head review,
seven green head/main checks, identical source trees and independently gated
passwordless promotion. Python and HTML each passed six validation cases and
two fresh source/installed PAW smokes; independent readback verified all four
sealed sidecars, unchanged original cases and terminal host state. A final audit
checked all12 original forensic cases and108 source/installed Python files;
current cached acceptance also passed through the explicit no-VM branch.
The [P3 acceptance checkpoint](vm-p3-acceptance.md) records exact jobs, hashes,
timings, the private evidence archive and the distinction between Root-private
verification and ordinary-reader evidence. This documentation-only checkpoint
closes P3 after its own review/head+main CI and maintained source-equivalence
checks. P4/P5 remain open, with only harmless fixtures and no NIC; no automatic
real-source execution or generic hostile-code safety is authorized.

P1 closed on26 October2026 after PR112 merged as
`172f0f2db5cc59a5a28bbb042475dccef1491b2b` and the reproduced private-ZIP
follow-up PR113 merged as `d8fb865ae8164026b69d39cf0419482e1dd870e7`.
Both exact heads had completed clear reviews and7required checks; both main
commits passed7checks. The dedicated source worker sets0077 before writing,
with a real regression failing before correction under caller umask000 and
passing after it in a pre-existing0755 case store. Source and installed CLI/API
acceptance, original/hash/ZIP/known-stop checks and P1 privacy evidence remain
preserved. The closure archive SHA256 is
`335f4ae32a1d32a3b4fcdd907794d91ec4e739b7a014a92cd33fc286a11c1ee2`.
No root snapshot, guest readiness, score or real input changed. See the
[forensic representation contract](forensic-representations-contract.md).

P2 closed on26 October2026 after PR114 merged as
`f22580a21e057f1efb0c2b40c0475cf44d8444fd`. Exact head
`9634c7e18afcd7a4469596df94f9355516e43665` had a completed clear review and
seven green required checks; main also passed all seven and has the identical
source tree. The review's structured-header defect was reproduced on duplicate
charset/unterminated declarations and fixed without changing parser choice.
32 module tests,26 source plus26 installed CLI/HTTP cases and three actual
owned lifecycle faults per mode passed, preserving original bytes, private ZIPs
and externally known stop. The closure archive SHA256 is
`56a06609a38316b03599a9db1a2991bb88b0f5104592c8ee785ecbc719421002`.
No root snapshot or VM changed. P3–P5 remain open. P3 starts with the
[explicit selection client contract](forensic-selection-contract.md); separate
root authority, no-NIC runtime and scoped I08 acceptance remain required.

P3 client increment PR115 merged as
`a17be7b51331deb376632e7df41bb349e1e2f619`, after exact-head clear review on
`34338578043737139efdb3c573e5483b1b942929` and7/7head checks. Main passed7/7
checks and its tree is identical.20 new boundary tests and28 bridge regressions,
six source/six clean installed CLI cases and17 refusals per mode passed.
The new client grants no execution; P3 remains open. Next is the separately
reviewed [maintained runtime recipe](vm-runtime-revalidation.md), because the
daemon and aggregate slice are inactive after reboot, then representation-scoped
one-use authority and actual owned adapter/I08 acceptance. No privileged
snapshot or service was changed by the client increment or inert preparation.

The maintained runtime prerequisite subsequently passed on reviewed/promoted
PR117 main `a6712a0c6fd872dc81ca4db3599df60b0b5a5fa3`, with clear exact-head
review and7/7head/main checks. Actual job `97c17c15f99c4652a70c6e525fb76285`
restored the two inactive services in8312ms, without password or VM. Protected
reader evidence and independent cgroup/read-only libvirt checks confirmed
unchanged rules/routes, zero domains/active networks and existing budgets.
No I08 or grant was enabled. The archive SHA256 is
`fb8a14436b6f302e998035b0177cee04fe3b43147460bdaf4d588cb7c317de23`.
The initial prestart failure and reproduced caller-normalizer fix are retained
in [the runtime contract](vm-runtime-revalidation.md). The daemon can idle-exit
and reactivate through its local socket; future guest work must still validate
its maintained context. P3 now advances to the separately scoped
[representation authority](representation-authority-contract.md), then actual
adapters/verifiers, owned matrices and I08. P3–P5 remain open.

The next [adapter and opaque custody increment](representation-adapter-contract.md)
adds separate Python/HTML representation libraries and an independent serialized
audit verifier. Its tests substitute hardware/Root boundaries and do not activate
a recipe, issue a grant or install I08. Actual finite owned producer/matrix and
source/installed PAW handoff remain required before P3 can close.

That adapter/verifier increment merged as PR119 main
`786e844d067a43c0681b0a80a2511e100b0c06d0`, after a completed clear exact-head
review on `bdad7b18d441ba99475f45e62e5bf75b9c374f23` and7/7head checks.
Main passed7/7checks and has the identical source tree. Both review findings
(unaccounted jobs and inherited HTML descriptor naming) have reproduced
negative-before/positive-after regressions.67 representation,44 browser,18
legacy-authority and90 operator/release tests passed. No Root snapshot, new
grant, readiness or actual VM was activated. The next
[producer and owned client increment](representation-producer-contract.md)
adds separately reviewed libraries; actual owned recipes/matrices and scoped
I08 remain required before P3 closure.

The producer/client increment PR120 subsequently merged as
`76975b7de828d068a7d2455cba18ddfe718e2699`, after a clear full-head review on
`2a8e76845ed09f20f9e7d8173deafa717d97cb47` and7/7head checks. Main passed7/7
with the identical tree.231 related tests and six source/six installed actual
owned client preparations passed, without Root activation or a VM. The next
[finite owned recipe](representation-owned-recipe.md) must complete actual
Root/no-NIC normal/fault/PAW acceptance and scoped I08 before P3 closes.

P0 closed on26 October2026 after the owner-authorized same-head review retry
completed clear on `e63ab29a10f2a5b8c561c1fc0ea370b60ec893f6`, all seven required
head checks and all prior threads were clear, and PR111 merged as
`6b9039c82659b1cf01e920f179fc16a6c4a71fda`. Both main workflows/seven jobs passed.
The actual fixed operator independently collected its remote proofs and promoted
that merge with no password; background protected status confirmed enrolled,
complete and a valid lease. All219 selected runtime files remain identical to
the accepted runtime below. New manifest SHA256 is
`a22eb7bbb02e48b72b6a63059446fa51ef9985f1feaa8deb85c428e0ed5822d0`.
The five-member promotion archive SHA256 is
`4e0cc1d3c573bb14bb35960e3593d2141c89b7bd486e82aaa8d66aa3b74e14c9`.
No new VM or real input was run. Libvirt service/socket are currently inactive:
domain enumeration is unavailable, no QEMU/netns was observed, and maintained
VM restart/runtime readiness remains to be checked before further guest work.
This does not invalidate the independently completed immutable promotion, nor
does promotion confer guest readiness. At that P0 checkpoint, P1 integration
was next and P1–P5 remained open. See [the byte inspection contract](source-inspection-contract.md).

The following25 October records retain their historical scope and ordering.

P0 native acceptance completed on25 October2026 at22:44CET on reviewed runtime
`7b476c86509b83303759f66adc34109a4d5fe90e`. The first failed installation and
five preceding successes remain preserved; native recovery retained its old
snapshot, failed receipt and consumed grant in protected history. A fresh
one-use admission then passed all nine owned HTML scenarios: normal execution,
script error, timeout, cancellation, output overflow, memory, paused refusal,
owner loss and protocol loss. Memory produced15 guest `oom_kill` events with
the unchanged512MiB/15s limits; maximum measured VM stop was1.001519s.
Replay, busy-lock refusal, unknown-stop publication refusal, revoke/refusal and
native restore all passed. Zero real samples/connections were recorded; no
production grant or I08 real-source readiness was enabled.

Independent UID1000 reconciliation verified every case with the existing
custody/fault verifier, exact source copies, no-NIC XML and root-owned read-only
reader evidence. The fixed installed helper now reports `enrolled`, a valid
lease and `enrollment_complete=true` from a background call with stdin closed
and no password. No QEMU/domain/netns remains. Native terminal authentication
was used once for recovery; ordinary finite operations use the narrow helper.

The1242-member `S14-VM-operatore-P0-collaudo-PASS-C.zip` evidence archive has
SHA256 `2570a294e51ac496f4af41f19d1486f43fdf38b945b9633e956f46715af55fbc`.
Runtime manifest SHA256 is
`24bfd6bb01b281ac33cc1beac5a584de10b9387baa28c328ad557043f27f52dc`.
Current inert checks remain136:44 release/admission/archive,46 operator/setup,
44 browser and2 private-input tests. This documentation-only consolidation
preserves all219 selected runtime source files.

At that25 October checkpoint P0 still needed final exact-head review/CI,
merge/main CI and ordinary passwordless promotion; those completed above.
At that earlier checkpoint P1–P5 were incomplete. P1/P2 completed above. The
then-external bounded P1/P2 prototypes were not installed features or phase
acceptance; their later integration/acceptance is recorded above.
Historical PR110 readiness does not
authorize new real inputs or profiles without their corresponding context,
review and runtime acceptance.


### Historical P0 implementation evidence

The first P0 draft contains strict pure release admission and immutable snapshot
verification, plus a bounded read-only GitHub adapter.33 new inert tests pass;
the existing38 browser and2 input-media privacy tests also passed after adding
the initial contract/storage modules. Early review6400146782 found no major
issues on12e5253; it does not cover the later adapter until fresh review/CI.

An actual read-only collection for PR110 verified the full reviewed df103af
head, merge bbf7f643, all resolved review threads and four exact head/main
workflow runs, using13 API requests. Nothing was installed/promoted/executed.
The first collection failed closed because GraphQL Bot.login omits REST's
`[bot]` suffix. The adapter now checks GraphQL Bot identity plus REST's enrolled
numeric actor ID. Automatic proof uses the bot's structured full-commit state;
legacy abbreviated prose alone cannot authorize promotion. Pending/findings
security review, changed observations, incomplete thread enumeration, queued or
failed latest CI, redirects, arbitrary queries and mutations refuse.

The caller's GitHub credential is used only in process memory for fixed HTTPS
read queries; it is not an Ubuntu administrator password and is never saved or
included in evidence. The then-pending dispatcher had to acquire proofs
itself with the fixed client, sanitize its environment, validate fixed root
ancestors and hold the deployment/execution locks. Accepting a local proof file
or an injected client is not an implementation of that authority boundary.

That early draft did not establish archive installation, the fixed polkit
entrypoint or actual no-prompt owned work/revocation/source freezing. No host
privilege configuration was installed by those inert tests. The subsequent
failed native attempt and successful recovery are distinguished above.

Next P0 draft adds bounded archive/manual snapshot staging and fixed installed
entrypoint/dispatcher/owned-worker code, with inert tests. Real public archive
bytes were checked against the independent API Git tree without staging or
execution. The [operator contract](vm-operator-contract.md) details installed
paths, finite commands, native bootstrap, residual work and the reproduced
CI-stability review correction. This earlier draft evidence alone did not
establish installation or acceptance; the subsequent native attempt is recorded
above and failed closed at the memory-fault witness.
