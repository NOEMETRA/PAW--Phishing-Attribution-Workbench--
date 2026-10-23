# Whole scalar HTML URL fields

Baseline: merged PR90, `7d97746bc645b3c67fcff3f1921fc3044a9c8d7a`,
23 October 2026. Codex reviewed exact head `0a3b9fac953c29a8d0eb14dfc72694c46dffe64d`
without findings. All three head/merge CI checks pass; the Git trees match.

## Reproduced family and shared boundary

The existing href/src/action/formaction/poster fields and object.data were
scanned as generic prose. For example, an img src value
`data:text/plain,https://embedded.invalid/a` or an a href value
`/relative?next=https://embedded.invalid/a` promoted the inner HTTP substring
into a network target. A javascript action had the same problem. Whitespace or
entity-decoded quotes truncated malformed values into valid-looking prefixes;
legal apostrophes also truncated otherwise valid resource paths and queries.

MIME observations, candidate recovery and reconstructed source views now share
whole-field boundaries for these existing scalar names. A recognizable HTTP or
encoded/refanged candidate causes the complete supplied attribute value to be
retained. MIME HTTP observations must begin at the field boundary. Nonnetwork,
relative and script envelopes remain complete non-target textual candidates;
their inner HTTP strings are not outer destinations. Invalid HTTP values remain
invalid evidence without a substituted prefix. Valid resource punctuation,
percent octets, case and one-pass HTML entity interpretation retain identity.

Object.data is qualified by its element name. Arbitrary data/data-* metadata,
title and other lexical attributes retain the existing generic extraction.
The srcset/imagesrcset and CSS argument grammars, visible text, comments and
JavaScript contracts are unchanged. Distinct refanged/encoded originals retain
separate provenance even when their recovered network destination is shared.

Source derivation is now `paw_html_url_candidate_views_v4`. Original EML/body
payloads and per-part text retain bytes/hashes; the catalog identifies parser
input and the versioned derived view, not raw occurrence offsets or persisted
derived candidates. Historical v1/v2/v3 cases and seals are not rewritten.

## Scope and limits

This is a supplied-value boundary contract, not browser URL parsing or a full
attribute inventory. Fields without recognizable HTTP/textual-URL markers remain
in original body evidence, without an invented URL record. All six names have
the same boundary contract; tag/DOM conformance beyond the object.data distinction
is not evaluated. Original whitespace is preserved: no browser-style trimming,
normalization, base-URI/relative resolution, navigation, script execution or
resource selection is claimed. The existing conservative HTTP syntax validator
determines network admission; unavailable interpretation is not safety or risk.
Existing MIME byte/text/part limits, URL decoder bounds, source retention budgets
and supervised worker limits still apply. No dependency or network access is added.

References: [HTML URL parsing terminology](https://html.spec.whatwg.org/multipage/urls-and-fetching.html#urls),
[object.data resource field](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-object-data).
HTML browser parsing can normalize values; PAW retains supplied forensic values
and explicitly does not implement that normalization in this contract.

## Verification

Nine new unit methods reproduce 81 failed assertions including subtests on the
baseline, not 81 independent defects. They cover all six fields, envelopes,
invalid/space-delimited values, legal punctuation/entities, colliding recovered
sources, ordinary metadata and exact source-budget accounting (10 total links,
four retained and six omitted). The Windows Python 3.13 general suite runs
929 tests: 915 pass and 14 platform exclusions remain.

Six actual integrations pass serially: scalar fields (eight full no-egress CLI
cases/three loopback HTTP workers), CSS (8/3), HTML lists (11/5), URL sources
(9/5), URL identity (11 CLI), and actual wheel parity (93 Python sources).
Checks include exact targets/original candidates, body bytes/hashes, repeated
MIME views, source v4, coverage, stopped workers, seals and CLI/API/ZIP parity.
The scalar HTTP budget case verifies 5,000 links/4,096 retained/904 omitted.

The first scalar integration exposed an overly strict shared-checker assumption:
three original encodings can share one destination. Its comparison now deduplicates
only the target list; original source/provenance assertions remain exact. All six
integrations were run after that expectation change. Runtime and collected unit
sources stayed unchanged after the general suite; all 245 final frozen Python/
workflow hashes match after validators stop. Four existing package sources
change and 89 retain their contents. Documents are updated afterwards.

Fixtures establish regression contracts, not classifier accuracy or authenticity.
Fresh exact-head GitHub Codex review and CI remain required before merging.
Full HTML/CSS/browser interpretation, platform/install acceptance, independent
holdout, isolated egress and UI retain their separate gates.
