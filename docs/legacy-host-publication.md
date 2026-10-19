# Legacy host/IP/ASN case publication

`util/derive_host_ip_asn.py CASE_DIR [--out OUTPUT]` and
`advanced/derive_host_ip_asn_advanced.py CASE_DIR` explicitly report
unavailability before case or output access. Accepted arguments exit 1, exact
help exits 0, missing/unsupported arguments and long-option abbreviations exit 2.
The base keeps the exact `--out` syntax for honest rejection without creating or
overwriting the named path. Import is inert, both support `main()`/`main(argv)`,
and direct invocation uses only the standard library. The advanced `enrich` API
raises `RuntimeError` before inspecting its argument.

Actual sealed filesystem/JSON/CSV fixtures reproduced both entry points returning
success after overwriting saved outputs and invalidating their seals. More
seriously, base `--out CASE/hunt_enrichments.json` replaced its own just-read JSON
source with CSV. An advanced header-only CSV fixture also overwrote prior notes
with empty results. These are declared stored fixtures; supplied host/IP/ASN,
provider and HTTP values are not authenticated observations or classification
ground truth.

Only the main publication paths and the advanced writing API change. Ordinary
`load_json`, `build_ip_index`, `provider_type` and `compute_risk` implementations
remain unchanged and unvalidated. No tracked production consumer outside this
pair invokes them. Their returned labels are not a supported enriched-evidence
contract, verified host/IP/ASN binding or calibrated risk assessment. The 90
package Python sources remain unchanged; no collector, replacement CSV publisher
or versioning protocol is introduced.

Original JSON/CSV, analyst notes and prior products remain literal saved sources.
Existing case verify/export can check and preserve bytes for their documented
scope; they do not authenticate these claims or replace this unavailable CSV
pipeline. Future publication requires justified source/output admission,
provenance and versioning. Live enrichment remains S14 after stabilization.

Five unit contracts check sealed/missing cases, exact `--out` directed at a
source, outside file or missing parent, opaque advanced API arguments, inert
imports and help/error/prefix behavior. The actual original-EML integration runs
full no-egress analysis and confirms stopped supervision, then probes both
writers on completed/sealed/unsealed/malformed/missing/outside/ownership-state
fixtures. Guarded processes reject before observed source/output I/O; direct
stdlib invocations run outside the checkout without PYTHONPATH. CLI verify and
ZIP preserve every original case file. File hooks do not cover every metadata
syscall; fixture owner states are not live workers, and these checks establish
neither OS containment nor host/IP/ASN authenticity or classifier accuracy.

Observed local Windows/Python 3.13 validation: five new contracts pass after
failing before repair (13 failures and eleven errors including subtests). The
actual original-EML integration passes 41 fresh guarded processes, fifteen
direct stdlib invocations, one full no-egress analysis and CLI verify/ZIP with
exact source preservation. The serial general suite passes 754 tests: 746 passed
and eight platform skips (97.265 seconds). An actual offline wheel matches all
90 unchanged package Python sources, metadata, entrypoint and both review
templates. These checks do not close final installation/platform acceptance.
