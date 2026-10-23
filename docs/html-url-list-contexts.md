# HTML URL-list candidate boundaries

Baseline: merged PR88, `418f8aa6985e7b3ee18c83648048ab414b0a25ee`,
23 October 2026. Its exact-head Codex review is clear; all three head and merge
CI checks pass. This family repairs the shared srcset/imagesrcset candidate
boundary, not all HTML/CSS/browser resource semantics.

## Reproduced defect

For `<img srcset="https://one.invalid/a, https://two.invalid/b 2x">`, MIME and
candidate extraction previously reported `https://one.invalid/a,` as a network
target. The separator became part of the resource path. Generic attribute
scanning also promoted HTTP substrings in descriptors, data URLs and relative
URL query values into outer candidates. The same defect affected imagesrcset.
Original HTML was preserved, but the derived URL inventory could misstate it.

The common tokenizer follows the URL-token/descriptor-boundary states in the
[HTML srcset parsing model](https://html.spec.whatwg.org/multipage/images.html#parse-a-srcset-attribute).
It uses ASCII whitespace boundaries, removes syntactic trailing separator commas,
preserves commas within URL tokens, and skips descriptor text with its parenthesis
state. Recognized candidates begin at the URL-token boundary. Unsupported
nonnetwork/relative tokens cannot contribute an embedded HTTP substring; an
invalid recognized whole token is retained rather than a truncated valid prefix.

MIME observations and candidate extraction share this helper; source catalogs
reconstruct the same views. `imagesrcset` HTTP literals now also have observed
MIME provenance. Encoded/refanged URL tokens still use the existing bounded URL
interpreter, with original tokens and transformations retained. Scalar attributes,
visible text, scripts and comments keep their existing literal comma behavior.
There is no global punctuation trimming or CSS/JavaScript grammar change.

HTML source derivation is now `paw_html_url_candidate_views_v2`. Persisted paths
and hashes identify the per-part parser input, not literal URL positions. Entity
references are interpreted once; derived views are not persisted. Historical v1
artifacts and sealed cases are not rewritten. The technical JSON, URL records,
source links, API and ZIP expose the same current evidence.

## Scope, limits and unavailability

This is descriptive URL-token extraction. List conformance, descriptor validity,
image choice, relative URL resolution and browser fetching are not evaluated.
Invalid descriptors can therefore accompany retained unverified URL tokens;
they are not claims that a browser selects those resources. The URL interpretation
coverage now names these limitations. CSS grammar, Content-Location/base URI
resolution, other list grammars and attached/embedded HTML analysis remain
separate audit work. Their original content remains in its existing inventories.

The scanner advances through each bounded MIME text once, with one descriptor
parenthesis state and no recursive parser or new dependency. Existing MIME
byte/part/depth limits still apply. The existing URL interpreter retains invalid,
unresolved or overlong recognized inputs as non-target evidence. Source retention
limits still count omitted links; absence of a supported candidate is not proof
of complete resource discovery, execution, authenticity or safety.

## Verification

Eight new contracts reproduce the boundary errors on the baseline and cover both
attributes, separators/internal commas, entities/case/percent escapes, descriptor
and nonnetwork substrings, encoded/refanged tokens, invalid/limited whole inputs,
unchanged scalar/text/script/comment commas and source-link accounting.
The baseline has 15 failed assertions including subtests, not 15 independent bugs.

`tests/integration_html_url_lists_real.py` runs nine actual full no-egress CLI
cases and three loopback HTTP workers. It checks exact targets/original candidates,
independent MIME document state, source v2, input/body hashes and byte views,
coverage/API/ZIP parity, stopped owners and seals. Its 100-URL/50-part list fixture
has exactly 5,000 links, 4,096 retained and 904 omitted, including an actual HTTP
run. Constructed fixtures are not classifier ground truth; no sample resource
is fetched and no browser is used.

## Review correction: whole-token admission

The initial exact-head review found that entity-decoded `"`, `<` or `>` inside
a retained list token could pass the shared HTTP URL check outside the hostname.
For example, `srcset="https://host.invalid/a&quot;tail,"` preserved the whole
token but incorrectly admitted it as a network destination. The additional
contracts reproduce this defect before the correction (20 failed subtest
assertions, not 20 independent defects).

The shared URL validator now rejects those unescaped characters in every URL
component, including recovered whole URLs and embedded candidate admission.
Original tokens, source links and decoding attempts remain available as
non-target evidence; no valid-looking prefix is substituted. Percent-encoded
resource delimiters remain unchanged. Apostrophes remain legal sub-delimiters
in paths, queries and fragments under [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.2),
so an entity-decoded apostrophe alone does not invalidate the complete URL.
This is a syntax-admission correction, not browser selection or risk assessment.

Five additional unit contracts cover both list attributes, original/recovered
inputs, path/query/fragment/userinfo admission, embedded candidates and legal
resource identity. The final Windows Python 3.13 suite runs 911 tests: 897 pass
and 14 platform exclusions remain. The expanded actual no-egress matrix runs
11 full CLI cases and five loopback HTTP workers, including invalid entity
tokens and valid apostrophe/percent-escaped resources through source inventories,
coverage, stopped ownership, seals and ZIP publication. That matrix, existing
URL identity (11 CLI cases) and the actual wheel (92 sources) pass serially on
the corrected source. All 240 frozen Python/workflow hashes match after those
validators stop. Five existing package sources now differ from the baseline;
87 retain their contents. The preceding five-integration evidence above records
the initial head; it is not a new run of unchanged source/report integrations.
Fresh exact-head review and CI are required before merging the correction.

The Windows Python 3.13 general suite runs 906 tests: 892 pass and 14 platform
exclusions remain. Five real integrations pass serially: the new list matrix,
existing URL identity, URL sources (9 CLI/5 HTTP), literal reports (3 CLI/1 HTTP)
and the actual wheel (92 Python sources). Four existing package sources change;
88 retain their contents. Runtime/collected unit sources remain unchanged after
that suite; an existing integration's v1 expectation was updated to v2 and the
full flow rerun. Final 240 Python/workflow hashes match before docs.

```text
python -B -m unittest discover -s tests -p 'test_html_url_lists.py' -v
python -B tests/integration_html_url_lists_real.py
```

Exact-head review/CI remains required. Final platform installation, independent
accuracy/holdout, isolated egress and UI retain their separate gates. The
application no-egress guard is not an OS sandbox.
