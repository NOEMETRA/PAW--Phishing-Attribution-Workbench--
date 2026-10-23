# CSS token names and quoted URL function evidence

Baseline: merged PR93, `64d2796a0b6f8d9ae22d6c457c871c8043b0b5c5`,
23 October 2026. Codex reviewed `cde605a9847b9d1c8dc3cca08dea6b3e51d85adc`
without findings or open threads. All three head and merge checks passed
(`39982245068` / `39984028748`), with identical Git trees.

## Reproduced family

The existing literal CSS scanner confused hash/at-keyword names with functions:
`#url(https://literal.invalid/a)` lost its literal closing parenthesis, while
`#url(url(https://actual.invalid/a))` swallowed the real inner function. An
invalid backslash/newline escape also joined an identifier to the next url()
token, changing its candidate boundary.

A quoted argument followed by a comment, such as
`url("https://actual.invalid/a"/**/)`, lost the resource candidate. Unsupported
quoted functions were recovered as unquoted bad-url tokens: a parenthesis in
a comment or nested string truncated their original textual evidence.

An independent local tinycss2 1.4.0 tokenization probe confirmed the distinction
between function, hash, at-keyword, block and invalid-escape boundaries. That
package is neither a runtime nor test dependency of this change. References:
[CSS tokenization](https://www.w3.org/TR/css-syntax-3/#consume-token),
[quoted URL grammar](https://www.w3.org/TR/css-values-4/#url-value).
The scanner below remains deliberately limited rather than a conforming parser.

## Shared boundary and provenance

Hash/at-keyword names now remain outside function recognition; their block
contents can still contain actual url() functions. Invalid identifier escapes
end the name. Valid escapes are traversed without decoding function names.
Ordinary nonfunction text retains its generic lexical URL behavior.

Quoted arguments admit whitespace/comment separators before the closing
parenthesis. A URL-bearing separator span is retained in full, including its
comments and whitespace, as non-target textual evidence. The inner HTTP,
refanged or encoded mention is not promoted into a resource destination.
The valid resource argument and this opaque span have separate source records.
Data/relative arguments still do not contribute embedded HTTP targets.

Unsupported or incomplete quoted functions retain their complete function
boundary through strings, comments and nested parentheses/brackets/braces.
This boundary traversal is iterative, without recursive parsing. URL modifiers
remain uninterpreted: a complete wrapper is evidence, not a substituted valid
resource prefix. Unquoted bad-url recovery and leading-comment behavior remain
separate and unchanged. Outside these separators, existing CSS comment/string
lexical observations keep their original contract.

Only `css_urls.py`, the URL source derivation and the coverage explanation change
in the package: three existing sources, 92 unchanged, no new runtime dependency.
Candidate extraction and reconstructed source views use the same helper.
Derivation becomes `paw_html_url_candidate_views_v6`; prior v1-v5 cases,
inventories and seals are not rewritten. Original EML and per-part body/text
bytes remain authoritative. Catalog links describe per-source presence, not
raw occurrence offsets, browser use or authenticated destinations.

## Actual verification

The first 12 contract methods fail on the baseline in 34 subtest assertions;
these are manifestations of a boundary family, not accuracy/defect counts.
The final 13 methods also exercise 20,000 nested component blocks without
recursion, whole recovered origins and source retention (10 total links,
four retained, six omitted).

The frozen Windows Python 3.13.5 / BeautifulSoup 4.13.4 suite runs **990 tests:
976 pass, 14 expected exclusions**. The 13 new methods and the same new full
integration also pass on actual Python 3.13.15 / BeautifulSoup 4.15.0.

Seven distinct integration/build scripts pass serially on the final runtime:

| Contract | CLI / owned-loopback HTTP cases |
| --- | --- |
| New CSS token/function family | 11 / 4, repeated on both actual runtimes |
| Existing CSS argument contract | 8 / 3 |
| HTML URL lists | 11 / 5 |
| Scalar HTML URL fields | 8 / 3 |
| URL source inventories | 9 / 5 |
| HTML text and independent MIME documents | 15 / 6 |
| Actual wheel | Metadata, entrypoint and all 95 Python sources |

The new budget fixture has 50 target arguments and 50 opaque separator spans
per part, across 50 HTML parts: **5,000 links / 4,096 retained / 904 omitted**,
not 5,000 resource destinations. Tests assert exact target/original-candidate
lists, mapped sources and omissions, raw/body hashes, coverage/report equality,
stopped owners, seals and CLI/API/ZIP parity. All 254 runtime/test/workflow
hashes stay unchanged through the serial matrix. Documentation is updated after
validators stop; the four public static contracts pass again afterwards.

### Copilot review correction

Copilot found that quoted-function recovery interpreted punctuation inside a
nested unquoted URL/bad-URL token as enclosing component syntax. Both
`url("https://outer.invalid/a" url(https://nested.invalid/a[))` and
`url("https://outer.invalid/a" url(data:text/plain,/*))` absorbed a following
independent function. Local tinycss2 tokenization independently confirmed that
the bracket/comment spelling belongs to the nested token, not the wrapper.

Recovery now consumes literal nested unquoted URL/bad-URL tokens with the same
nonrecursive helper as top-level arguments. Quoted functions and ordinary
component blocks retain their own boundaries; other names, hash/at-keyword
names and undecoded escaped names are not substituted for literal `url`.
The complete wrapper remains non-target evidence, with the following target
and its source mapping retained separately. The pending v6 contract remains
v6; historical evidence is not rewritten.

Three added methods cover valid/bad tokens, escapes, quoted/name controls and
20,000 repeated nested tokens. The final frozen suite runs **993 tests: 979
pass, 14 expected exclusions**. All 16 CSS token methods and **13 full no-egress
CLI / 6 owned-loopback HTTP cases** pass on both real Python runtimes. The same
cases are repeated, not independent classifier samples. After this correction,
four distinct integration/build scripts pass serially: the expanded CSS token
family, existing CSS arguments, URL source inventories and the 95-source wheel.
The earlier HTML list/scalar/text integrations in the table record the initial
revision, not additional reruns of this correction. All 254 runtime/test/workflow
hashes remain unchanged throughout the final matrix.

## Remaining scope

MIME text/part limits, decoder bounds, source retention budgets and supervisor
deadlines remain applicable. This does not implement full CSS tokenization,
input normalization, escape decoding, escaped function names, URL modifiers,
imports, custom-property evaluation, declaration/selector grammar, cascade,
relative/base resolution or browser resource selection. HTML5 tree construction,
foreign content and scripting interpretation retain the separate limitations
of the integrated HTML context contract.

Constructed fixtures establish execution/evidence contracts, not classifier
accuracy or authenticity. No sample URL/domain was visited/resolved, no
attachment executed and no Docker started. Application no-egress is not OS
containment. Codex remained running without an actionable result; at the owner's
request Copilot replaced that pending review for this PR. The
[final review](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/94#pullrequestreview-5631910326)
on `b82104c7a166ba245385fba7b496d5b435f33653` recommends approval with no open
issues. All three head checks (`39992858333`) and merge checks (`39994215958`)
passed. PR94 merged as `e7a981131e9898f1c7af6c46db2fd0338fba46b0`, with the
same tree as the reviewed head. The [finite HTML/CSS perimeter](html-css-scope.md)
now distinguishes supported contexts, exclusions and concrete residual gaps;
this family does not close the entire engine audit.
