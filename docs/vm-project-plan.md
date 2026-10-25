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

P0 is being implemented on `codex/vm-project-automation`. The heartbeat exists;
the privileged helper and promotion mechanism are not installed or accepted.
P1–P5 are not complete. Historical PR110 readiness does not authorize these new
capabilities without their corresponding review, context and runtime acceptance.

The native-only bundle validator/installer, committed-source builder,
digest-approved launcher and native acceptance batch are implemented and
inert-tested. Actual setup remains pending exact-head review, CI and native
authentication; no polkit or host authorization has been installed. Current
tests:44 release/admission,31 entry/dispatcher/installer/setup and42 browser contracts.
The latest browser count includes four export-race regressions following a
reproduced review finding; reader exports remain root-owned and read-only.


### P0 implementation evidence, current draft

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
included in evidence. The future installed dispatcher must acquire proofs
itself with the fixed client, sanitize its environment, validate fixed root
ancestors and hold the deployment/execution locks. Accepting a local proof file
or an injected client is not an implementation of that authority boundary.

P0 remains open: bounded remote archive acquisition/installation, the fixed
polkit entrypoint, actual no-prompt owned work, failure/revocation and source
freezing acceptance are still required. No host privilege configuration has
been installed by these tests.

Next P0 draft adds bounded archive/manual snapshot staging and fixed installed
entrypoint/dispatcher/owned-worker code, with inert tests. Real public archive
bytes were checked against the independent API Git tree without staging or
execution. The [operator contract](vm-operator-contract.md) details installed
paths, finite commands, native bootstrap, residual work and the reproduced
CI-stability review correction. These additions do not mean polkit is installed
or native runtime acceptance has passed; the installer is still required.
