# Literal CSS URL argument boundaries

Baseline: merged PR89, `d387ddbc4673bc40f7f4e5e80c9c554e9f298d49`,
23 October 2026. Its corrected head has a clean Codex review; all three head
and merge CI checks pass, and the merge tree matches the reviewed tree.

## Reproduced family

Generic text scanning of `<style>a{background:url(https://one.invalid/a)}</style>`
reported `https://one.invalid/a)}` as a destination. A style attribute similarly
included the closing parenthesis. In `url(data:text/plain,https://embedded.invalid/a)`
and `url(/relative?next=https://embedded.invalid/a)`, scanning promoted an embedded
HTTP substring into an outer network candidate. These are three manifestations
of one missing CSS argument boundary, not evidence of a resource visit.

Both style attributes and style-element raw text now share a literal `url(...)`
scanner in candidate extraction. Source inventories reconstruct the same view.
Only complete arguments beginning with a recognized HTTP or recoverable textual
URL are admitted to the existing URL interpreter. Data/relative arguments do not
contribute an embedded substring. Quoted resource parentheses, commas,
apostrophes, percent escapes and case remain unchanged. HTML attribute entities
are parsed once; style-element raw text keeps literal entity spellings.

Malformed or unterminated literal functions containing recognized candidates
remain whole textual expressions, with no valid-looking prefix substituted.
They cannot pass absolute HTTP admission. Invalid HTTP arguments and recognized
raw arguments with CSS escapes remain original non-target evidence. Existing
whole-URL refanging/Base64/percent recovery is separate from CSS escape decoding.
The shared URI validator, srcset grammar, scalar attributes, JavaScript, comments,
ordinary CSS strings and non-url function text keep their existing contracts.

The HTML derivation is now `paw_html_url_candidate_views_v3`. Original EML,
decoded body payloads and persisted per-part text retain their bytes/hashes.
The source catalog identifies parser input and the derived candidate method,
not raw occurrence offsets or a persisted derived view. Historical v1/v2 cases
and seals are not rewritten. Source retention/omission accounting is unchanged.

## Bounds and remaining interpretation

The scanner is iterative and uses existing MIME text/byte limits and worker
budgets. CSS escapes are traversed to locate boundaries but not decoded into
destinations. Escaped function names, full CSS tokenization/conformance,
stylesheet imports, relative resolution, cascade, layout, browser resource
selection and execution are not evaluated. Other CSS text retains generic
lexical candidate extraction; those candidates are not claims of resource use.
Standalone CSS/kit helpers and attached/embedded HTML are outside this repair.
The URL coverage names these limits; a completed source catalog covers current
URL records, not complete CSS resource discovery or authenticity.

Boundary reference: [CSS Syntax, URL tokens and bad-URL recovery](https://www.w3.org/TR/css-syntax-3/#consume-url-token).
This limited literal scanner is not a conforming CSS parser. No dependency,
browser, sample-domain lookup or resource fetch is added.

## Verification

Nine new unit contracts cover the three cases, quoted resource identity,
entity/raw-text distinctions, malformed/invalid/escaped/recovered inputs,
unchanged lexical contexts and exact source-budget accounting (10 total links,
four retained, six omitted). On an isolated copy of the actual baseline, the
two core contract methods fail in six subtest assertions. These are regressions,
not independent defect or accuracy counts. Two 2 MiB supplied CSS probes also
terminate without recursive parsing, including one malformed expression.

The Windows Python 3.13 suite runs 920 tests: 906 pass and 14 platform exclusions
remain. Five actual integrations pass serially: new CSS (eight full no-egress
CLI cases/three loopback HTTP workers), existing HTML lists (11 CLI/five HTTP),
URL sources (nine CLI/five HTTP), URL identity (11 CLI), and the actual wheel
with 93 Python sources. CLI/API/ZIP checks include exact targets/original
candidates, per-part body bytes/hashes, independent MIME state, source v3,
coverage, stopped owners and seals. The wheel check was rerun after adding the
new helper to the Git index; its first tracked-only build did not cover that
helper. Runtime/test/workflow contents stayed unchanged: all 243 frozen hashes
match after validators stop. Three existing package sources change, 89 remain
unchanged and one helper is added. Documents are updated afterwards.

Constructed fixtures establish execution contracts, not classifier accuracy.
Fresh exact-head GitHub Codex review and CI are required before merging.
Platform/install acceptance, independent holdout, isolated egress and UI retain
their separate gates; application no-egress is not OS containment.
