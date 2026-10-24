# PAW-linked fixed synthetic pilot

This pilot connects a completed sealed PAW case to the existing fixed harmless
Python marker fixture. The CLI and local Python functions prepare/import data;
they never launch a guest, invoke a privileged service or execute email content.
No HTTP endpoint is added. `paw detonate` and analysis presets are unchanged.

## Flow and authority

1. Analyze a constructed local EML with `paw quick` or `--no-egress`, wait for
   supervised worker shutdown and verify its modern case seal.
2. `paw lab-synthetic prepare --case CASE --output NEW_REQUEST_DIRECTORY` emits
   request.json and its exact SHA256. It binds the canonical `case-...` ID,
   manifest/index SHA256 and Merkle content root, with a fifteen-minute lease.
   It contains a fixed fixture ID/hash, not source code, URL, shell command or
   attachment path. Preparation is read-only with respect to the case.
3. An explicitly authorized root PID1 operator runs
   `lab/s14/paw_synthetic_bridge.py --request REQUEST --expected-sha256 SHA`.
   This separate manual operation checks the exact approved request, rechecks
   expiry after boot and uses the unchanged `run_job()` API and trusted catalog
   success fixture. The lab's internal synthetic parent remains distinct from
   the external PAW case reference; neither hash authenticates an email's claims.
4. After confirmed VM stop and independent fixed-positive reconciliation, the
   operator publishes exactly request.json, receipt.json and two ordinal opaque
   files under `/var/lib/paw-s14-exports/REQUEST_ID`. The directory/files remain
   root-owned without group/other write permission; private full runtime evidence
   stays under `/var/lib/paw-s14/control/paw-request-REQUEST_ID`.
5. `paw lab-synthetic import --case CASE --request REQUEST --output NEW_RESULT_CONTAINER`
   verifies the unchanged case and exact request, walks the fixed trusted export
   root with descriptor-relative no-follow opens, rejects writable/user-owned,
   missing/extra/symlink/special/oversized or mismatched producer data, and checks
   the completed status, known stop, lease, image/contract hashes and fixed marker.
   Only then does it write a separate pending sidecar, seal/reverify it, recheck
   the original case and publish the already sealed `NEW_RESULT_CONTAINER/result`.

Both package entry points always enforce the existing application no-egress
policy. The lab operator is a different explicit process: no subprocess escape
or privilege request is hidden in normal PAW analysis/prepare/import. The root
wrapper admits one fixture only and exposes no generic source/command option.
Request IDs are consumed by an exclusive fixed control-directory namespace;
failed requests retain their private failure evidence and cannot be silently
re-executed under a different output path.

## Trust and scope

The importer trusts a local administrative producer assertion protected by Linux
filesystem ownership; it is not a remote signature, independent attestation or
content-authenticity proof. Receipt hashes establish byte linkage/integrity.
Producer and importer must use the same synthetic bridge contract source hash.
The original case, scoring, MIME, notes and seals are never updated. The new
sidecar is an independent integrity inventory with explicit synthetic-only scope,
not a risk verdict or a successful analysis of an attachment/website.

Requests with expired execution admission refuse. Historical import is allowed
only when the recorded actual admission occurred inside the original lease.
Partial/cancelled/unknown-stop outcomes are not accepted by this first fixed
positive pilot. The existing four-job acceptance verifier remains strict for
four jobs; its single-positive entry point independently checks this narrower
case and PAW request link.

CI performs real no-egress PAW analysis, console preparation/import, original/seal
preservation and separate-sidecar verification, using explicitly simulated root
receipts with no KVM or payload execution. It also checks missing producer data,
wrong case, unknown stop, repeated output and symlinks. The Linux operator/KVM
pilot is a separate measured acceptance on this PC, with frozen code/image,
host restoration and actual root-produced receipt provenance. A simulated CI
receipt is never reported as a real VM run.

Linux is required for the local root/no-follow trust contract. Other platforms,
noncatalog inputs, browser/egress, generic command/attachment execution and I08
effective configuration/maintenance acceptance remain unavailable/separate. This
pilot neither closes the hostile-code gate nor changes previously consolidated
engine audits.
