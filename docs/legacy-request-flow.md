# Standalone request-flow publication boundary

`util/build_flow_mermaid.py CASE_DIR` is explicitly unavailable. Accepted case
arguments exit 1 before accessing the source or writing output; help exits 0,
invalid/missing arguments exit 2 and import is inert. `main(argv=None)` retains
its invocation shape and `build(case_dir)` raises `RuntimeError` before inspecting
the supplied object. Direct invocation needs only the standard library.

The former writer overwrote `derived/flow.mmd` inside existing cases. An actual
guarded run on sealed synthetic files replaced analyst notes, returned success
and invalidated the evidence seal. Distinct `a-b.invalid` and `a.b.invalid` labels
also produced the same node identifier. These are local filesystem/syntax
observations, not an actual email analysis, network capture or rendered graph.

Saved `detonation/requests.jsonl` observations and prior diagrams remain intact.
This change makes the unsafe standalone publication unavailable; it does not
discard captured data, collect requests or introduce a replacement publisher.
Any future request-flow publication needs bounded source/error accounting,
unique/literal labels, unverified request/Referer semantics, stopped-source
admission and output versioning. Those contracts remain open with controlled
capture/detonation work. Integrity seals do not authenticate request claims.

The supported supervised analysis still creates its Received-attribution and
domain diagrams before sealing. Those are separate products and do not replace
request-flow interpretation. `integration_legacy_flow_real.py` runs one actual
full original-EML analysis under no-egress, confirms stopped owners, original
bytes, both saved graphs, valid seals and their actual CLI ZIP bytes. Fifteen
cold guarded legacy paths and two direct stdlib invocations check case, log,
notes and seal preservation across completed/sealed/unsealed/malformed/missing/
outside inputs, import, arguments and direct `main`/`build` calls. A source-file
audit hook rejects observed source operations; an opaque path rejects direct
path inspection. Owner-state and log fixtures are not live workers or captures.
No browser, renderer, collector, network authenticity, attribution accuracy or
OS containment is established. Package graph/analysis/export code is unchanged.
