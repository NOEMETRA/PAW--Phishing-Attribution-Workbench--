# Next hostile-input boundary: review candidates, no execution authority

PR105's PAW → fixed no-NIC fixture → PAW pilot is merged at
`06c664fb8bc3affa7e0dd0952730b3214567cddb`. Its tree equals reviewed/tested
`88439515d4eeecd5c7bd8dd754563a40c27afb2f`. The first actual installed-wheel
pilot preserved all 34 original case files and verified the original/sidecar
seals. That functional result is not acceptance of unknown code.

## Reproduced CPU evidence defect

I08 inspection found that `Gate.start()` recorded the initial owner scope's
`cpu.max = 75000 100000`, then called `systemctl set-property CPUQuota=50%`
without refreshing the record. Both synthetic/offline readers omitted CPU
validation. Historical raw result SHA256
`947e78b788120ec9c5fe02dd2645ac5a2ea7e7cd2b6e44dec6ae6d1e832dafd5`
contains this stale observation. It does not establish that the applied limit
was wrong; it does not prove the claimed final 50% limit either. Historical
archives remain unchanged. Their CPU claim needs a corrected runtime repeat.

The controller now reads the actual owned scope's cpu.max after set-property
and requires `50000 100000` before guest resume. Both readers require that
recorded quota. Missing, unlimited, larger or differently parameterized limits
refuse. The frozen profile deliberately uses this exact quota/period pair.
New readers consequently reject older exports with missing/stale CPU data;
keep original producer/verifier pairs for historical evidence, not rewritten
inventories. No image, scoring, original email or existing seal changes.

## Candidate data contract

`lab/s14/offline_candidate.py --inspect-stdin` inspects one bounded JSON frame
and returns metadata only. This is a review candidate, **never admission to
execution**, and no runner or PAW endpoint consumes it. The old runtime still
independently refuses noncatalog sources and this new schema.

Fields are exact: schema `paw-s14-offline-candidate-v1`, profile
`linux-python-offline-v1`, a 32-hex request ID, case_reference_sha256, source,
provenance, integer created_at/expires_at and purpose `offline-single-job-review`.
Source contains media_type `text/x-python`, encoding `utf-8`, positive bytes
at most 16384, SHA256 and lowercase data_hex. Bytes/hash/UTF-8/NUL are checked
without compiling, importing or interpreting the content. Syntax, compatibility,
benignness and authenticity are not established. Provenance contains kind
`operator-supplied` and a 1–256 visible-ASCII reference, treated literally and
never resolved. Parent/provenance are claims; no PAW custody proof is inferred.

The lease is at most fifteen minutes, request fields/duplicate keys/nonfinite
JSON/oversized/deep frames refuse. The output binds both the exact input-frame
SHA256 and canonical candidate SHA256 (stable across JSON formatting). It
contains hashes/size, not source content, and always reports
`execution_authorized: false` and `runtime_adapter: unavailable`. A digest or
self-authored boolean cannot create operator authority. Actual single-use
consumption must be implemented and reviewed in the eventual adapter.

## I08 disposition on this PC

The read-only inventory on 24 October 2026 captured kernel 7.0.0-38, QEMU
1:10.2.1+ds-1ubuntu3.2, libvirt 12.0.0-1ubuntu5.6, microcode
3.20260210.1ubuntu2, SMT off, AppArmor enabled and the 2 GiB/128-task/zero-swap
lab slice. The host's ordinary swap is separate and was not disabled globally.
APT currently lists QEMU ubuntu3.3 as candidate, phased at 20%; installed and
candidate equality for other packages alone does not prove security currency.
The locally cached APT index is not a fresh security audit.

The [official Ubuntu candidate changelog](https://changelogs.ubuntu.com/changelogs/pool/main/q/qemu/qemu_10.2.1+ds-1ubuntu3.3/changelog)
records packaging, s390x hardening and block-mirror startup-race corrections.
The maintenance disposition remains pending, rather than declaring it irrelevant
from the architecture/version string. No host package upgrade was performed.

The kernel reports GDS `Mitigation: AVX disabled, no microcode`. The
[kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/gather_data_sampling.html)
recognizes disabled AVX as a fallback mitigation; the string alone is not an
unmitigated-vulnerability finding or acceptance of guest CPU exposure. Effective
host/guest CPU policy and the complete platform mitigation state still need
independent I08 review. No blanket requirement for extra RAM can replace it.

Remaining required acceptance:

1. Independent review of effective platform/image/policy/version evidence,
   corrected CPU observation, update status and maintenance disposition.
2. A separately reviewed root-protected, exact-hash, expiring single-job grant
   and replay ledger for noncatalog inputs. This candidate inspector provides
   neither a grant nor a launcher.
3. A harmless runtime/failure matrix through that same eventual adapter and
   publication path: completion, failure, cancellation, descendants, malformed
   control/output, owner loss, stop refusal and reset.
4. A separate noncatalog PAW request/result contract, preserving originals,
   custody, opaque outputs and partial/unknown-stop states.

Until these pass, arbitrary Python, ELF/PE, scripts of other interpreters,
attachments, browser/egress and general hostile-code execution remain
unavailable. No hostile sample was executed by this change.
