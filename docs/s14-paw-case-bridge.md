# PAW sealed-case attachment bridge

This is the noncatalogue custody layer over the accepted
[single-hash offline profile](s14-hash-pinned-profile.md). It does not broaden
the guest formats, network access or existing resource/stop boundaries. The
historical fixed synthetic bridge remains separate and unchanged.

## Explicit operational flow

1. Analyze the original email with `paw quick ORIGINAL.eml` (offline) or explicit
   `--no-egress` on supported analysis commands. Preserve original MIME bytes.
2. Verify the completed case. Choose an exact `evidence_path` from its
   `attachments.json`, with a declared `.py` filename, unambiguous decoding,
   UTF-8 bytes without NUL and size 1..16384. Filename is an ingress declaration,
   not independent file type detection or a benignness judgment.
3. `paw lab-offline prepare --case CASE --attachment-path attachments/part-…bin
   --output NEW_REQUEST` reads only that sealed attachment. It creates immutable
   request/candidate bytes outside the case. Their binding includes the case
   seal/manifest/index, exact attachment path/part/source hash and bridge contract
   hash. Candidate inspection/preparation creates no execution authority.
4. The explicit root administrator captures the current host/source context,
   verifies maintained I08 readiness and review/CI, installs a one-hash
   `sample-analysis` policy and issues an exact-frame one-use grant. Changing the
   case/part/contract binding changes the frame and requires a new approval.
5. A root PID1 service invokes `lab/s14/paw_hash_bridge.py --request REQUEST
   --expected-sha256 EXACT_REQUEST_SHA --policy-sha256 INSTALLED_POLICY_SHA`.
   It uses only the frozen approved frame, not caller-supplied case paths,
   through the existing execution-only hash operator. Global consumption,
   effective controls, post-stop context and independent verification still
   apply. No ordinary PAW CLI/API analysis launches this service or grants itself
   privileges. Root runs only trusted, reviewed administrative code; a request's
   contract hash binds its bytes but does not attest arbitrary Python imports.
6. Only after known stop and full independent single-job verification does the
   operator atomically publish a fixed root-owned export under
   `/var/lib/paw-s14-case-exports/REQUEST_ID`. The receipt binds the exact outer
   request, candidate, source, parent, policy/grant/readiness/consumption hashes,
   VM identity, source inventory, admission time and raw result hash. Unknown
   stop, failed infrastructure, revoked authority or changed context publishes
   no case export. A payload may fail, time out, cancel or exceed output budget;
   those are preserved execution outcomes, never malware verdicts.
7. `paw lab-offline import --case CASE --request REQUEST --output NEW_RESULT`
   re-verifies the case, source and root-owned no-follow export, all digests and
   bounded ordinal artifacts. It publishes a separately sealed result sidecar.
   Existing case bytes, seal, score, attribution, reports and original remain
   unchanged. Guest output is opaque data: no render, archive expansion,
   import/evaluation or score interpretation. The result is available through
   the same stopped-case `paw verify`/ZIP evidence tools.

The local Python API is `paw.core.offline_bridge.prepare/import_result`, both
unconditionally inside application offline policy. This is not a privileged HTTP
API or an OS sandbox for the development host. Root export ownership is local
producer trust, not a remote signature or sender/content authenticity proof.
Historical imports are allowed only if admission was inside the original lease;
new execution is checked against current root readiness, context and spent ledger.

## Validation and limits

Unit tests use inert sealed cases and mutation/refusal oracles. Actual CLI tests
analyze a constructed multipart original email and exercise preparation, missing
or untrusted exports, successful and failed payload receipts, unknown-stop,
symlink/digest corruption, repeat import and original/seal preservation. CI root
fixtures call only the export writer with a distinct simulated-result witness;
they never launch a VM or evaluate an attachment and cannot count as KVM evidence.
Installed-wheel acceptance runs separately on Python 3.11–3.14.

Actual PAW→VM→PAW acceptance must run with a fresh owned harmless attachment
through the same operator after exact-head review/CI, with a newly captured
readiness context (adding this operator changes the lab source freeze).
Measured root/KVM evidence and final disposition are retained separately; source
presence and synthetic fixtures alone are not acceptance for unknown inputs.

The profile does not execute HTML/JavaScript in a browser, Office/PDF documents,
archives, PE/ELF or other interpreter ingress. Such mail still receives the
supported offline static PAW analysis with dynamic work explicitly unavailable.
No live sample URL lookup/visit, sender contact or automatic detonation is added.
R08, classifier accuracy and labels remain separate; no consolidated engine
audit is reopened here.
