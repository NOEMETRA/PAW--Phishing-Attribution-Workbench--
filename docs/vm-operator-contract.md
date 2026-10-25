# Credential-free VM operator: P0 implementation contract

This is the narrow administrator boundary for the P0–P5 plan. The current draft
is not installed or accepted. It stores no Ubuntu password, installs no generic
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

The native installer and its acceptance orchestrator remain to be implemented.
The present tests use private owned files with simulated UID checks; they are
not a claim of actual root installation, polkit behavior or VM acceptance.

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
