# Legacy tracker case publication

`util/analyze_trackers.py CASE_DIR` and
`advanced/analyze_trackers_advanced.py CASE_DIR` now explicitly report
unavailability before inspecting or accessing a case. Accepted paths exit 1,
exact `-h`/`--help` exit 0, missing/unsupported arguments and long-option prefixes
exit 2. Import is inert; both support `main()` and explicit `main(argv)`, using
only the standard library. The base `analyze` API and advanced `write_outputs`
API raise `RuntimeError` before inspecting any argument.

Before repair, actual sealed filesystem/request/CSV fixtures reproduced both
entry points overwriting saved outputs and returning success with invalid seals.
The advanced launcher also created a missing case directory and three reports.
The base ID map has identifier-to-count entries, while the advanced reader
expects domain-to-object entries: a supplied nonempty ID map became an empty
campaign-ID list. Role-count rules produced audience/identity categories without
independent audience evidence. These are declared stored fixtures, not actual
captures, original-email findings or authenticated tracking/audience conclusions.

Only the publication boundary changes. Ordinary prototype parsing/interpretation
helpers retain their implementations and remain unvalidated; their declarations
are not a supported evidence pipeline. No tracked production consumer outside
this two-script family calls them. Existing sources, notes and prior products are
preserved literally; their claims are not authenticated or silently migrated.
Future case publication needs a justified source/output admission and versioning
contract. This patch does not introduce a replacement exporter or tracker.

The separate package [supplied tracker-pattern extractor](tracker-static-evidence.md)
remains available for its bounded source/offset/omission and unverified-candidate
contract. It does not automatically read or validate these legacy case products,
observe a browser, prove tracking, identify an audience or establish attribution.
The 90 package Python sources are unchanged by this patch.

Five unit contracts cover sealed sources, opaque writer arguments, existing and
missing paths, exact help/errors/prefixes and inert imports. The integration runs
an actual full original-EML no-egress worker and confirms stopped supervision,
then exercises both scripts on completed/sealed/unsealed/malformed/missing/
outside/ownership-state sources. Cold guarded execute/main/import/API/help/error
processes preserve source bytes, notes and seals without observed source I/O or
blocked network attempts. Direct stdlib invocations run outside the checkout
without PYTHONPATH. Actual CLI verify and ZIP export preserve every original case
file. The file audit hook does not cover every metadata syscall; owner/log
fixtures are not live workers/captures, and a matching seal is not authenticity,
classifier accuracy or OS containment.

Observed local Windows/Python 3.13 validation: all five new unit contracts pass
after failing before repair (11 failures and nine errors including subtests).
The actual original-EML integration passes 34 fresh guarded processes, twelve
direct stdlib invocations, one full no-egress analysis and CLI verify/ZIP with
exact original case bytes. The serial general suite passes 749 tests: 741 passed
and eight platform skips (104.063 seconds), including the separate package
tracker-observation contracts. A real offline wheel matches all 90 unchanged
package Python sources, metadata, entrypoint and both review templates. These
are bounded checks, not final installation/platform or classifier acceptance.
