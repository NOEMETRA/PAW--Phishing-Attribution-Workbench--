# Credential-free VM operator: P0 implementation contract

This is the narrow administrator boundary for the P0–P5 plan. The installed
runtime passed native recovery and all nine owned acceptance cases on
25 October2026; merged/main ordinary promotion remains to be demonstrated.
It stores no Ubuntu password, installs no generic
NOPASSWD sudo and does not authorize root execution of workspace scripts.

## Fixed installed paths and trust

| Path | Role |
| --- | --- |
| `/usr/local/libexec/paw-vm-operator` | Root0755 fixed pkexec entrypoint; isolated Python, exact enrolled caller, self/module hashes, minimal environment and resource limits. |
| `/usr/local/lib/paw-vm` | Exact root0444 static verifier/dispatcher module set; not automatically replaced by payload promotion. |
| `/var/lib/paw-vm` | Root0700 enrollment, bootstrap digests, active pointer, operation lock, revocation marker and protected job results. |
| `/opt/paw-vm/releases/<full-commit>` | Root-owned source snapshots, exact immutable inventory, proof and manifest. No user-writable code or symlink/hardlink/special file. |
| `/var/lib/paw-vm-exports/<job>` | Benign acceptance evidence for the enrolled reader. User-readable copies are never root authority. Original producer audits remain protected in `/var/lib/paw-s14/control`. |

The polkit action must match the fixed entrypoint path and the enrolled local
account UID1000/name. Arguments are validated by code, not polkit command-line
string matching. The same enrolled account can use the finite helper from its
local service/automation processes; an active desktop-session flag is not the
authority boundary. Generic shells, Python and other programs retain normal
administrator authentication. Native initial enrollment/repair is a distinct
administrator action and is never exposed through the passwordless entrypoint.

The installed entrypoint walks fixed root ancestors without symlinks, checks
the exact static module set/digests before importing it, rejects workspace
invocation and ignores user Python paths. It clears the environment, disables
bytecode writes/core dumps and bounds descriptors/address space/CPU/file output.
Root static helper upgrades or enrollment renewal require native authorization;
ordinary reviewed payload releases do not replace the static trust verifier.

## Commands

- `status`: reads protected enrollment/active state and reports lease/revocation;
  it neither starts a VM nor confers readiness on a profile.
- `promote <PR-number>`: independently obtain a merged project's full-head clear
  review, resolved threads and exact required head/main CI. Read a GitHub API
  credential as one bounded stdin pipe frame, never an argument/file/log. Use
  fixed read-only HTTPS queries with no redirects or caller-selected endpoint.
  Download only the verified full commit from the fixed codeload host, bound
  gzip/tar/member/source budgets, copy supported source files manually, and bind
  every byte to the GitHub API commit/tree/blob identity. Repeat remote proof
  observations, reject revocation/changes and stage/verify before activation.
  The ancestry anchor is the protected current release, so promotion cannot
  silently roll back to an older version.
- `run <finite-recipe>`: verify the active snapshot before and after a fixed
  PID1 job. Caller cannot supply bytes, host paths, URLs, systemd flags or code.
  Recipes generate fresh owned fixtures in the snapshot. A separate operator
  lock serializes promotion/run; existing VM code retains its global job lock.
- `revoke`: atomically prevents new promote/run operations, including after
  lease expiry. It does not silently force-kill already admitted jobs; those
  retain their bounded deadline and known-stop obligations. A native admin
  enrollment is needed to re-enable, not an unprivileged resume argument.

Ordinary run/promotion additionally require a protected successful native
acceptance receipt bound to the enrolled initial anchor, the four core phases,
nine harmless cases, integer zero real inputs and the protected job digest.
Missing/failed/foreign receipt means `enrollment_incomplete`, including after
SIGTERM/SIGKILL where no Python cleanup handler runs. Status/revoke remain
available; status does not invent completion from an installed polkit rule.

Initial native testing is distinct from ordinary authority: the administrator
arms one root0600 grant for the exact browser recipe/release, a live root native
PID/start identity and a60s admission lease. A random256-bit capability travels
only through stdin pipes to the UID1000 client/entrypoint; only its hash is
stored. The entrypoint durably consumes it once under the operation lock before
starting the same bounded owned worker. Expired/incorrect/replayed capability,
dead/reused native owner or another recipe refuses. Already admitted work keeps
its existing bounded lifetime and known-stop obligations if the installer dies.
After core acceptance the root receipt enables ordinary authority; a final
unprivileged status confirms it. No unprivileged command can manufacture the
grant, write the receipt or re-enable a revoked enrollment.

The implemented worker currently supports `browser-owned-v1`. Other finite
recipe IDs are reserved for reviewed later phases and refuse until implemented.
The unit uses512MiB/64tasks/swap0/CPU100%,1800s lifetime,20s service stop bound,
no host IP networking and explicit isolated/no-bytecode Python. Existing QEMU,
guest, aggregate, stop and opaque-publication contracts remain unchanged.
Controller service limits are distinct from the VM stop budget.

The worker finds the one newly created protected producer directory, verifies
its exact generated manifest and validation-only nine-case result, compares
host/image/source context and checks QEMU/domain/netns absence. Host dispatcher
accepts only a protected successful result matching job/recipe/release and an
integer zero real-sample count. A failed job or changed snapshot is not success.

## Initial enrollment and remaining implementation

Initial installation must remain one concrete native-authenticated batch after
the exact code has clear review and required head CI. Since P0's runtime proof
must precede its merge, this initial snapshot is explicitly native-enrolled,
not mislabeled an automatic merged/main release. Required initial evidence is:

1. A short-lived canonical approval bundle built from committed source bytes,
   with its full digest pinned in the native command; no credentials in it.
   The installer itself and all bootstrap dependencies must be hash-checked
   before import/execution. No unverified workspace imports as root.
2. Independent exact-head code/security review and head CI re-observation for
   that PR, and commit/tree/blob agreement for all approved source bytes.
   This native bootstrap proof has a distinct schema/authority from automatic
   release promotion; it cannot be submitted to the passwordless promoter.
3. Fixed-root ancestor/ownership checks, refusal to overwrite an existing
   operator, exclusive immutable staging and a rollback journal for newly
   created artifacts. Publish polkit permission only after installed entrypoint
   and state self-checks pass. No partial broad permission on failure.
4. Actual unprivileged no-prompt status, unknown command refusal and finite owned
   job. Check generic pkexec authorization noninteractively so a negative test
   cannot create another password prompt. Verify private state/code cannot be
   changed by UID1000. Exercise revoke/refusal and native-authorized re-enable
   during the same explicit enrollment acceptance batch.
5. Preserve the approved snapshot/freeze and all failures, then merge only after
   actual phase acceptance. Verify main CI and test automatic promotion of this
   now-merged phase via the protected entrypoint. Source changes require their
   corresponding maintained context; no automatic real-source/I08 grant issuer.

The native installer now validates a short-lived digest-approved bundle,
copies approved bootstrap modules into a root-private temporary directory,
independently rechecks the native candidate and exact Git source tree, and
installs fixed paths transactionally. Permission is published only after the
installed status self-check. Existing installations refuse; failures roll back
only newly created artifacts, including a stage that failed after rename.

The distinct `paw-vm-native-candidate-v1` proof permits an unmerged exact reviewed
head with its seven head jobs only for this native-admin initial enrollment.
It is rejected by automatic release admission, which still requires a merged
project PR, reviewed head and both head/main CI. Native authority is explicit;
the candidate JSON alone cannot enter the passwordless promoter.

`vm_operator_setup.py` builds the one-hour approval bundle from full-commit
`ls-tree`/`cat-file` blobs, checking regular modes, object identities, source
inventory and budgets; uncommitted and untracked workspace changes cannot enter
it. Enrollment lasts at most30 days. The native launcher passes only the data
path and full bundle digest to a literal isolated Python bootstrap, which checks
the complete bounded regular file and installer hash before compiling that
installer. Root independently binds every approved source to the GitHub tree.
The GitHub credential is obtained from the existing `gh` provider and passed as
one stdin pipe frame; it is absent from bundle, argv, environment and logs.

The same native batch now contains the acceptance orchestrator: noninteractive
polkit checks, actual UID1000 status/refusal calls, one finite nine-case browser
recipe, protected root job reconciliation, revoke/refusal and native restore.
Generic shell/Python authorization must deny with1/2, not merely fail with127.
On this host an unprivileged `pkcheck` with details returns127/NotAuthorized;
that is not a negative authorization witness. Instead the native administrator
queries fixed details for an actual dropped-UID child identified by PID, start
time and UID. These checks never request user interaction. The actual helper
calls then run as UID1000 with its real supplementary groups and a minimal
environment. No generic shell/Python command is executed as a negative test.

Native setup is a2100s/512MiB/64tasks/swap0/core0/file64MiB PID1 unit; fixed
worker and VM budgets remain separate. Acceptance logs are streamed to fresh
root0600 files. Acceptance failure revokes the helper, removes its new
passwordless rule and retains immutable sources/protected results; it does not
delete code under a possibly running bounded job or infer a known VM stop.
The source tree stays frozen during the native batch.

Two inert fault reproductions failed before correction: acceptance-directory
creation failure and final proof persistence failure left the new rule enabled.
Both now enter the failure boundary, which removes the rule before attempting
revocation storage. A preexisting acceptance directory is never overwritten;
final proof persistence is inside acceptance, so its failure cannot report PASS.

Review4371817603 found default signal termination bypassed exception cleanup.
The old dispatcher was reproduced accepting an ordinary run without acceptance
in an owned fixture; it now refuses. A real owned fork/SIGKILL regression stops
native acceptance at its authorization probe, leaves the rule present without
any cleanup/receipt, and verifies ordinary run remains denied. Further tests
cover receipt failure/identity, dead/reused owner, expiry, wrong capability and
durable one-use consumption. No root or VM is involved in these regressions.

Review4371861898 reproduced native-owner loss while waiting for the capability
pipe: the earlier pre-wait liveness observation still allowed admission. Two
regressions failed before correction (real owner terminated/reaped during wait,
and lease expiry during wait). Owner/start identity and admission clock are now
re-observed after authenticating the frame, immediately before consumption and
after its fsync. Lost/expired pre-admission authority refuses; post-consumption
loss refuses without launching and leaves the attempt consumed. Already
admitted jobs keep their separate lifetime/known-stop contract; these checks
do not claim an atomic guarantee about a native process's future survival.

Review4371784558 reproduced another immutable-snapshot failure without a VM:
the browser owner `--help` import path generated18 `.pyc` files because a new
`python -I` interpreter does not inherit its parent's `-B`. The actual owner
command now passes `-B` explicitly. A real subprocess regression imports the
owner from a private copy of all committed Python sources and verifies the
exact source inventory/hashes remain unchanged, with no `__pycache__` entries.
The native client, installed worker and browser matrix already pass `-B`;
the fixed entrypoint disables bytecode before importing protected modules.

These implementation tests use private owned files and simulated UID/process
checks. They do not substitute for the separate measured native disposition.

## Measured native attempt and recovery

Native21c988 installation and UID1000 probe succeeded after one Ubuntu
authentication. The delegated recipe passed positive, script-error, timeout,
cancel and overflow. The memory case instead reached the unchanged15s timeout
with guest memory.max hits172 and zero oom/oom_kill/oom_group_kill. The matrix
correctly failed instead of claiming an OOM witness; the final three fault
scenarios were not run. The failed VM had known stop1.000091s, no live writers,
unchanged host/base/browser/source context and no real connections. Independent
post-run checks found no QEMU, domains or network namespaces. Native acceptance
removed its rule/revoked new work; its durable receipt is FAIL, not readiness.
The host static operator remains installed and initial enrollment is incomplete.

The836-member failure archive has SHA256
`e8a3c872833a10559fa1076182cd50ac5d2541f0a2055c35007dd28b3f908fab`.
The exported root-owned reader tree is evidence, not privileged authority.

The old repeated64MiB JavaScript allocation could spend its deadline reclaiming
without an OOM kill. The new owned probe makes one retained1GiB typed allocation
and writes one byte per page. This changes only the synthetic input; production
512MiB memory/15s deadline/QEMU/aggregate limits and the strict oom_kill witness
remain unchanged. The new full matrix subsequently produced15 guest oom_kill
events and passed this case. A timeout remains FAIL; prior9/9 evidence was not
substituted for the new runtime's actual execution.

Native bundle v2 explicitly binds `repair_from` to the previous full release
and manifest digest; v1 data remains decodable for historical evidence. Repair
is never exposed by the passwordless entrypoint. It requires fresh exact-head
review/CI/Git source proof and native admin authentication. It verifies previous
protected state, prior snapshot, unchanged static bootstrap/entry/module bytes,
failed/incomplete acceptance and a dead prior native owner. Accepted enrollment
or a static boundary upgrade refuses this path. No QEMU/domain/netns/owned job
or other enrollment service may be active; the current native PID must be the
main process of its fixed PID1 unit. These are re-observed before staging.

Recovery removes delegated permission first, preserves old snapshots and moves
prior acceptance logs/one-use authority into root-private history, then updates
only native policy and the active snapshot. Revocation and incomplete state stay
closed during mutation. Only after installed status self-check does this native
batch rearm a fresh one-use acceptance context and recreate the same narrow
rule. Failure retains history and snapshots and leaves revocation/rule removal.
It cannot turn the previous failed run into PASS or resume a consumed grant.
The full nine-case retest and replay/revoke/restore checks subsequently passed;
the separate post-merge ordinary-promotion demonstration remains required.

## Native recovery acceptance,25 October2026

Exact runtime `7b476c86509b83303759f66adc34109a4d5fe90e` passed the native batch
at22:44CET. All nine scenarios and the protected receipt/revoke/restore/final
status checks passed. Independent UID1000 reconciliation of the root-owned
read-only reader exports verified source/image/context bindings, one-use
consumption, actual no-NIC XML, all six normal/resource outcomes and all three
fault witnesses. Maximum VM stop was1.001519s; guest memory evidence contains
oom1/oom_kill15/oom_group_kill1. No QEMU/domain/netns remained.

A background UID1000 call to the installed fixed entrypoint, with stdin closed,
returned `enrolled`, `lease_valid=true` and `enrollment_complete=true` without
administrator interaction. The1242-member local evidence archive
`S14-VM-operatore-P0-collaudo-PASS-C.zip` has SHA256
`2570a294e51ac496f4af41f19d1486f43fdf38b945b9633e956f46715af55fbc`.
Its runtime manifest is
`24bfd6bb01b281ac33cc1beac5a584de10b9387baa28c328ad557043f27f52dc`.
This is benign operator enrollment acceptance; production grants/I08 remain
disabled and the complete P0–P5 project is not closed. See the
[phase disposition](vm-project-plan.md#current-disposition) for consolidation.

Upstream semantics used by the acceptance checks:
[pkcheck](https://www.freedesktop.org/software/polkit/docs/latest/pkcheck.1.html)
and [pkexec](https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html).

Review4371671325 identified a path-following ownership race newly reachable
through the delegated browser recipe. An inert owned-canary reproduction
confirmed the legacy handoff follows a substituted child symlink. Publication
now retains root ownership, changes descriptor-pinned inodes without following
links, rejects writable/linked/special entries and keeps the top directory0700
until all changes finish. Final directories are0750 and files0440 for the
reader group; no privileged path operation follows publication. Four inert
regressions cover substitution, visibility ordering and refusal cases. This
correction covers the browser recipe currently delegated; other recipes still
refuse and need their own acceptance before implementation/delegation.

## Measured development evidence

Real read-only archive acquisition of PR110's bbf7f643 downloaded2466265 bytes,
selected200 source files/1691299 bytes and matched every selected Git blob
against API tree `7619a8b71f5f398717956b9ba47dc6442afb9b03`. No staging or
execution was performed. The archive hash is
`bd9c00e8fb3eaa09fcf2591e09b527238191727773cb0a5719e4ca31d87067d0`.

Review finding4371556571 was reproduced: changing CI to in_progress or a new
attempt during the final GraphQL query still returned the earlier green proof.
The regression failed twice before correction. Collection now fetches jobs by
run-attempt identity and re-observes all four runs/jobs before returning. Either
change refuses; the proof binds positive native run_attempt values. Remote
request budget is48 (two collections plus commit-tree checks fit within it),
with the existing8MiB response and120s time bounds. This is bounded re-observation,
not an atomic lock against future changes on GitHub.

GitHub/repository governance and the enrolled reviewer are explicit trust
dependencies. Read-only credential use is transient; the software must never
return it in proof data or errors. Local proof JSON alone is not authorization.
