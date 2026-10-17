# Legacy abuse-template boundary

`util/make_abuse_templates.py CASE_DIR` is explicitly unavailable. It exits 1
with a reason before reading or writing the supplied case. The positional case
argument and `main(argv=None)` invocation shape remain accepted for rejection;
missing/invalid arguments exit 2, help explains the boundary and import is inert.
The script uses only the standard library and works outside the checkout without
host `PYTHONPATH` or an installed PAW package.

The old generator inserted fixed historical domains, HTTP statuses and claimed
evidence paths into every English/Italian template. It asserted a phishing
campaign, described unavailable request/kit/flow artifacts and made unsupported
collection/probing assertions. It also overwrote analyst notes inside `derived/`
without checking ownership or the existing seal. Actual local sealed files
reproduced successful template publication with cited files absent, prior notes
overwritten and a failed seal, under the Python no-egress guard. This filesystem
fixture was not a real message analysis or observation of the claimed sites.

The supported supervised `paw full INPUT --no-egress` path continues to create
local review drafts during a new analysis, before sealing. Its text distinguishes
sender/header claims and heuristic assessment from independent findings, with no
automatic recipient or sending. English and Italian drafts remain available.
The legacy duplicate is not replaced by another case writer or reporting
capability. Future standalone publication needs an explicit source/provenance,
output/ownership and versioning contract. Broader S08 report/diagram/export review
remains open; this does not attest every artifact in the package or ARF/X-ARF
format conformance.

`tests/integration_legacy_abuse_draft_real.py` runs two actual supervised full
analyses of the same original EML, one per draft language, with no-egress and
confirmed stopped worker trees. It checks original bytes, existing local-draft
status/recipient/conformance fields and valid seals. Thirteen cold guarded legacy
processes cover completed/sealed, unsealed, malformed, blocked-owner metadata,
missing and outside paths, import, explicit `main(argv)`, help and invalid inputs.
An additional audit hook rejects source-path filesystem operations; guarded
processes have no collector/CLI import, new threads or blocked operations.
Two direct stdlib-only invocations run outside the checkout without `PYTHONPATH`.
All source trees, original EML, draft files, saved analyst notes and seals remain
unchanged after the legacy calls.

Sealed-file and ownership-state fixtures are not analyzed messages or live
processes. Direct calls are separate from guarded assertions. These tests prove
bounded execution/source preservation, not authenticity, attribution, accuracy,
external reporting or OS isolation. The package implementation and templates are
unchanged; this dispositions one S12 legacy entry point while preserving the
current supervised review-draft path.
