# Finite HTML/CSS extraction perimeter

Assessed implementation: merged PR94,
`e7a981131e9898f1c7af6c46db2fd0338fba46b0`, 23 October 2026 (Europe/Rome).
Its tree matches reviewed head `b82104c7a166ba245385fba7b496d5b435f33653`.
[Copilot's final review](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/94#pullrequestreview-5631910326)
recommends approval with no open issues. All three head and merge checks passed
([head](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/actions/runs/39992858333),
[merge](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/actions/runs/39994215958)).

This register closes the **enumeration and disposition of the current HTML/CSS
perimeter**. It does not close extraction completeness, all S04/S05/S06/S09 work,
platform/install acceptance or classifier accuracy. This documentation change
does not change extraction, scoring, schemas, dependencies or source derivation
`paw_html_url_candidate_views_v6`; historical cases and seals are not rewritten.

## Reading the contract

PAW inventories supplied evidence. A `network_target: true` URL has passed the
existing absolute HTTP(S) admission/recovery rules; it is not proof that the
source declares a usable resource, a browser would request it, or the endpoint
was visited or authenticated. Generic lexical observations can pass this check
even in comments, metadata or uninterpreted CSS. The field `provenance: observed`
does not authenticate those strings or establish resource semantics.

There are three separate paths: outer-message URL extraction, optional static
HTML observations, and supplied/captured kit/form helpers. Sharing
`HTMLTextContextParser` does not give them identical attribute, CSS or source
coverage. In particular, the kit CSS regex does not implement the main HTML CSS
scanner. The dedicated form helper's URL joins are not outer-message URL joins.

## Supported contexts

Support below means the named bounded observation, with the linked regression
contract. It does not mean standards conformance or every malformed input.

| ID | Input/context and supported output | Implementation and evidence |
| --- | --- | --- |
| H01 | Independent, parser-selected outer non-attachment `text/html` MIME bodies. Payload bytes and charset-derived text are preserved per part; decoding and inherited MIME-context uncertainty remain explicit. A filename or attachment disposition excludes a part from body extraction, including inline parts with filenames. | [MIME selection](mime-context-evidence.md), [body evidence](mime-body-evidence.md); `analyze_mime` in [mime_analysis.py](../paw/core/mime_analysis.py). Plain text and `text/javascript` are separate lexical inputs, not HTML documents. |
| H02 | Shared lexical text states: `textarea/title` decode character references once; `script/style/xmp/iframe/noembed/noframes` keep raw spelling; `plaintext` runs to EOF. Matching ASCII end names/delimiters and quoted end-token attributes, nonvoid self-closing spelling and unfinished tails retain the documented boundaries. Visible-text derivation excludes actual script/style data; URL recovery separately scans those contexts. | [Text contexts](html-text-contexts.md), [html_contexts.py](../paw/core/html_contexts.py), `test_html_text_contexts.py`. No HTML5 tree is claimed. |
| H03 | Whole supplied scalar `href`, `src`, `action`, `formaction`, `poster`, and `data` on `object`. Recognizable candidates retain the entire value, including malformed or nonnetwork envelopes; inner HTTP substrings in these envelopes are not substituted as destinations. Unrecognized values stay in original text without invented URL records. | [Scalar fields](html-scalar-url-contexts.md); `html_attribute_url_candidates` in [mime_analysis.py](../paw/core/mime_analysis.py), `test_html_scalar_urls.py`. Names are handled lexically; tag conformance beyond `object.data` is not checked. |
| H04 | `srcset/imagesrcset` URL-token boundaries, ASCII separators, internal versus trailing commas and descriptor-skipping state. Complete recognized tokens retain original/recovered provenance; descriptors and embedded HTTP text in nonnetwork tokens do not introduce destinations. | [URL lists](html-url-list-contexts.md), `test_html_url_lists.py`. Descriptor validity, list conformance and selected image are not evaluated. |
| H05 | Actual `style` attributes and style-element raw text use the same literal case-insensitive `url(...)` boundary helper. Quoted/unquoted arguments, quoted separator comments, hash/at-keyword names, invalid identifier escapes and iterative recovery are covered. Recognized malformed/unsupported functions and URL-bearing quoted separator spans remain complete non-target text. | [CSS arguments](css-url-contexts.md), [token boundaries](css-token-boundaries.md), [css_urls.py](../paw/core/css_urls.py), `test_css_url_contexts.py` / `test_css_token_boundaries.py`. CSS escapes are traversed for boundaries, never decoded. |
| H06 | Generic HTTP/refanged/encoded textual candidates in joined visible text, comments, script text and ordinary attributes; namespace declaration attributes (`xmlns`, `xmlns:*`) are skipped by candidate recovery. Non-special attributes, ordinary CSS comments/strings and other CSS text retain generic lexical behavior. Joined text is not rescanned as independent truncated data chunks. | [URL evidence](url-evidence.md), [url_evidence.py](../paw/core/url_evidence.py), `test_url_contracts.py`, `test_html_text_contexts.py`. This is textual discovery, not attribute/JavaScript/CSS semantics; see G03/G04. |
| H07 | Original/final HTML remains unchanged. Optional BeautifulSoup observations describe selected hidden-element patterns, forms, iframes, inline-script markers and bounded Base64 data-URI attributes. Decoded payloads are candidate evidence, not executed content or automatic network destinations. HTML risk is `not_evaluated`, with zero HTML suspicion contribution. | [HTML observations](html-evidence.md), [html.py](../paw/deobfuscate/html.py), `test_html_contracts.py`. Scalar HTML schema 2; independent multi-document schema 3; worker documents bind part/text/hash. Missing optional parser produces unavailable/partial observations. |
| H08 | URL source catalogs link existing records to independent per-part derived views or the selected first Subject/From header views. HTML source v6 binds persisted parser-input text/path/hash. Repeated per-source presence, original candidates sharing a target, unmapped indexes and omitted links remain distinct. | [Source inventory](url-evidence.md), [url_sources.py](../paw/core/url_sources.py), `test_url_sources.py`. Derived views are not persisted; links are not occurrences or byte offsets. |
| H09 | Separate CID inventory: supported simple outer HTML attributes can match captured same-message Content-ID candidates, preserving missing/duplicate/limited outcomes. CSS/style and URL-list attribute markers are observations without parsed-reference relationships. | [CID contract](mime-cid-evidence.md), [mime_cid.py](../paw/core/mime_cid.py), `test_mime_cid.py`. No resource selection, attached/inner HTML, `mid:` or Content-Location resolution. |
| H10 | Supplied/captured kit schema 2 keeps bounded source/hash/observation inventories for HTML/JS/CSS, with unavailable family/risk attribution. Dedicated supplied-form schema 2 records declarations, lexical nesting, limits and separate unverified action joins. These helpers are independently callable; they do not establish offline body-pipeline coverage or active collection. | [Kit contract](kit-static-evidence.md), [form contract](form-static-evidence.md), [kit_static.py](../paw/core/kit_static.py), [form_analysis.py](../paw/core/form_analysis.py), `test_kit_static.py` / `test_form_observations.py`. The full offline worker does not collect a kit or invoke the dedicated collected-page form path. |

## Bounds, omissions and failure meaning

| Path | Current defaults and observable boundary |
| --- | --- |
| MIME admission/extraction | 25 MiB original input, 500 parts, depth 30, 20 MiB decoded payloads, 2 MiB aggregate analyzed text payload bytes. Exceeding extraction budgets raises a limit failure rather than silently analyzing a prefix. Supported charset/transfer/parser defects instead retain their documented partial observations. |
| URL interpretation | 65,536 characters per URL, four default whole-value recovery rounds; embedded token/candidate/JSON budgets are separate in [URL evidence](url-evidence.md). Partial/unresolved candidates stay non-target evidence; valid outer URLs with limited embedded analysis retain that distinction. |
| Source links | 4,096 retained links and 256 retained unmapped indexes by default; total/retained/omitted counts and unmapped counts remain explicit. `completed` means current evidence records map in supported views, not all HTML/CSS strings were recognized. |
| CID inventory | 2,048 observations, 4,096 links, 4,096 bytes per captured value and 262,144 aggregate captured-value bytes. Limited values, complex markers and missing/duplicate relationships remain qualified. Counts cover the documented encountered/retained scope. |
| Optional HTML observations | The Base64 attribute loop has 1,024 nodes, 32 candidates and 16,384 encoded characters per candidate, separately per document. The other observation arrays do not inherit those limits or the dedicated form helper's counters (G06). Worker MIME/deadline/memory bounds remain applicable; direct helper callers must bound their own input. |
| Dedicated kit/form helpers | Independent source/node/value/observation budgets and omission counters are specified in [kit](kit-static-evidence.md) and [forms](form-static-evidence.md). These are not interchangeable with optional HTML observations or MIME admission. |

Body bytes, derived text and source hashes remain distinct. Worker termination
must be confirmed before stable case verification/export/sealing; an interrupted
or failed job is not a successful partial parser result. This scope retains the
existing CLI/API lifecycle contract and does not modify it.

## Intentional exclusions

| ID | Excluded interpretation or operation | Evidence retained / meaning |
| --- | --- | --- |
| E01 | HTML5 insertion modes/tree repair, foreign-content namespaces, scripting-dependent `noscript`, escaped script-data states, browser layout/visibility/form ownership and browser resource selection. | Original source and bounded parser observations remain. An observed node or hidden-style pattern does not establish what a browser displays or submits. |
| E02 | Full CSS syntax/conformance, input normalization, escape/name decoding, modifiers, declaration/selector validity, custom-property evaluation, cascade and stylesheet import processing. | Literal `url()` handling is H05; other text is H06. An import-like or escaped-name string may still yield lexical URL evidence (G04). |
| E03 | Global trimming/normalization, relative/base/Content-Location URL resolution in the outer-message inventory; recursive document interpretation of `srcdoc`, data URIs or attached/embedded HTML. | Supplied values, originals and separate decoded candidates remain. The isolated form helper's documented `urljoin` interpretation does not enable these operations in the email pipeline. |
| E04 | Sample URL visits, DNS/resource fetching, attachment execution, Docker, detonation or active collection on the development host. | All actual email analyses here use `--no-egress`; only owned HTTP loopback is permitted for integrations. Application policy is not OS isolation. Active acceptance remains S14. |
| E05 | Complete occurrence/offset inventories or proof of exhaustive discovery from a `completed` status. | Source completion describes current supported records; omitted/unmapped counts describe that inventory's bounds, not all unrecognized grammar or sources. No per-context completeness map is currently persisted. |
| E06 | Safety, authenticity, actor/payment/C2 identity or calibrated phishing probability inferred from strings, absence, fixture passes or matching seals. | Observation provenance, unavailable interpretation and evidence integrity remain separate. Independent corpus evaluation remains S10. |

## Concrete residual gaps and disposition

This is the finite follow-up list, not a promise to implement a browser. A gap
may close with an explicit unsupported contract. Reopening extraction requires
an investigative need, a reproduced loss/misstatement within a named source,
bounded outputs and failure/omission expectations, then one coherent family
change with actual applicable CLI/API/export evidence and review. Additional
microcases alone do not expand this perimeter.

| ID / owner | Concrete current result and investigative consequence | Disposition / next decision |
| --- | --- | --- |
| G01 — S04/S06 | Attached HTML, `text/css` MIME parts and `message/rfc822` attachments are retained as attachment evidence, not HTML body documents; their inner URLs do not enter outer-body URL extraction/source catalogs. A filename-bearing inline HTML part has the same exclusion. An external stylesheet link may be a URL string, but its contents are not fetched. | The [attachment capability reconciliation](attachment-capability-coverage.md) chooses preservation with explicit unavailable content scopes for the current candidate. Child-document extraction is unsupported; a future inventory needs an investigative justification and independent part/message provenance. Do not silently merge inner document/header identity into the outer email. |
| G02 — S04 | A relative image plus Content-Location yields no resolved target. Only simple direct CID attributes have candidate equality links; `style`/`srcset` markers do not supply parsed CID relationships, and a style element's raw CID text is not an attribute observation. `mid:` and resource selection are unimplemented. | The [attachment capability contract](attachment-capability-coverage.md) keeps resource resolution unavailable and checks existing MIME/CID non-resolution in the combined worker path. Any future relation needs message/part scope, ambiguous/missing/limited outcomes and separate candidate semantics. No browser selection or network request follows from equality. |
| G03 — S05 | `srcdoc`, refresh `content`, `ping`, namespaced attributes such as `xlink:href` (excluding namespace declarations) and other ordinary attributes use generic textual extraction, without their own document/list/navigation grammar. For the examples below, `srcdoc` and refresh return inner HTTP strings; this does not establish nested nodes or a redirect. Relative-only values may yield nothing. | Explicit generic support only (H06). Do not advertise nested HTML, redirect or arbitrary URL-attribute coverage. Add a dedicated grammar only if required by a demonstrated investigation; first assess whether generic discovery plus original source is sufficient. |
| G04 — S05 | Escaped CSS function names, import strings and other nonliteral `url()` contexts remain generic text. An escaped `u\72l` example returns the lexical candidate `https://escaped.invalid/a)}`, including CSS punctuation, which can pass HTTP syntax admission. A quoted absolute `@import` is discovered lexically; a relative import is not resolved. | Accept as an explicit lexical boundary, not a correctly parsed CSS resource. Do not strip punctuation globally or claim these are resolved resources. A later bounded grammar change must preserve original candidate identity and source derivation; full CSS parsing remains excluded. |
| G05 — S09/S14 | Captured/supplied kit CSS still uses its own `CSS_URL` regex, not the main HTML scanner. For `url("https://resource.invalid/a"/* https://comment.invalid/a */)`, kit output has one unverified `css_url` value containing the quoted argument and comment; H05 returns the resource candidate and a separate non-target comment span. The kit status can be `completed` for its narrower lexical contract. | Record the difference before active-kit acceptance. Do not claim v6 main-scanner parity for kit observations or treat its `css_url` values as destinations. Either retain and label the narrower contract, or justify a separately tested shared-boundary repair in S09. Existing inactive no-egress worker tests do not exercise live capture. |
| G06 — S05/S08 | Optional HTML hidden/form/iframe/script observers have no independent omission counters or uniform failure diagnostics: their source code catches parser/observer exceptions and can return empty collections. The outer assessment status follows the Base64 candidate observer, not a combined health result for every subobserver. Only that candidate observer has the node/candidate limits above. | Keep these arrays descriptive; empty does not certify absence or a complete subscan. Carry explicit per-observer availability/failure/limit reconciliation to the evidence-to-report audit. This is a source-inspected diagnostic gap, not a demonstrated browser/parser failure or a claim that the existing bounded worker bypasses its deadline. Dedicated form-helper coverage does not close it. |

The [attachment/capability family](attachment-capability-coverage.md) records the
current unsupported-content/resource decisions for G01/G02; it does not expand
the HTML/CSS parser. G03/G04 have an explicit generic/unsupported disposition; G05
stays a named kit acceptance gap, and G06 belongs to evidence/report diagnostics.
They are not an unbounded request to extend parsers. Final evidence-to-score/
report auditing and candidate acceptance still apply to the supported paths.

## Reproducible observations and validation

The following small constructed inputs were executed against the actual helpers
under `offline_policy()` on the baseline above; no mock parser, browser or private
email was used, and no external endpoint was contacted. `EmailMessage(policy=policy.SMTP)` supplied
`text/html`; `parse_message_bytes`, `analyze_mime`,
`extract_mime_url_candidates`, `DeobfuscationEngine.deobfuscate_url` and
`build_url_evidence` produced the outer-message values. The CID probe additionally
used `preserve_body_parts`, `inventory_mime_headers` and `inventory_mime_cids`;
kit and form rows call their dedicated APIs. These are direct-helper probes,
not additional end-to-end or accuracy samples.

| Supplied input | Actual bounded result |
| --- | --- |
| `<a href="https://scalar.invalid/a?x=1&amp;y=2">text</a>` | One target `https://scalar.invalid/a?x=1&y=2`. |
| `<img srcset="https://one.invalid/a, https://two.invalid/b 2x">` | Two targets without the separator comma. |
| `<base href="https://base.invalid/dir/"><a href="next">text</a>` | Only the absolute base literal is inventoried; no `/dir/next` target. The dedicated form helper given the same base and `<form action="next">` separately reports an unverified `/dir/next` action candidate. |
| `<iframe srcdoc="&lt;a href=&quot;https://inner.invalid/a&quot;&gt;x&lt;/a&gt;"></iframe>` | One lexical HTTP target, without parsing a nested document. |
| `<meta http-equiv="refresh" content="0;url=https://refresh.invalid/a">` | One lexical HTTP target, without refresh/redirect interpretation. |
| `<a ping="https://one.invalid/a https://two.invalid/b">text</a>` | Two lexical HTTP targets; no ping behavior or list-conformance result. |
| `<style>a{background:u\72l(https://escaped.invalid/a)}</style>` | Lexical target `https://escaped.invalid/a)}`; no escape decoding or resource interpretation. |
| `<style>@import "https://import.invalid/a";</style>` and `<style>@import "next.css";</style>` | First gives one lexical target; second gives none. No stylesheet import processing. |
| `<style>a{background:url("https://resource.invalid/a"/* https://comment.invalid/a */)}</style>` | One resource candidate plus whole non-target `/* https://comment.invalid/a */` evidence. The dedicated kit CSS call on the inner `url(...)` string gives the G05 combined value. |
| Plain outer body plus `letter.html` attachment, `text/css` attachment and HTML inside `inner.eml` | Three attachment records (`text/html`, `text/css`, `message/rfc822`), zero HTML body documents and zero targets. Each inner source contains a distinct absolute URL. |
| `<img src="logo.png">` with `Content-Location: https://location.invalid/dir/page.html` | Zero targets; header preservation does not imply URI resolution. |
| Direct `<img src="cid:logo@local.invalid">`, a `style` attribute and `srcset` with the same CID, plus one matching Content-ID MIME part | Three CID observations but only one direct-reference link. Raw CID text in a style element is not separately parsed into an attribute relationship. |

Rechecks on 23 October 2026, performed serially with `-B`:

| Existing verification | This closure's actual result |
| --- | --- |
| Ten contract modules: HTML observations/text/scalar/list, CSS arguments/tokens, URL sources, CID, supplied forms and static kits | 168 tests on each real Windows runtime: 167 passed, one expected POSIX FIFO/symlink exclusion. Python 3.13.5 / BeautifulSoup 4.13.4 and Python 3.13.15 / BeautifulSoup 4.15.0. The same fixtures were repeated, not independent samples. |
| `integration_html_text_contexts_real.py` | 15 full no-egress CLI cases / six owned-loopback HTTP workers. |
| `integration_css_token_boundaries_real.py` | 13 full no-egress CLI cases / six owned-loopback HTTP workers. |
| `integration_url_sources_real.py` | Nine full no-egress CLI cases / five owned-loopback HTTP workers. |

The three integrations used Python 3.13.5 / BeautifulSoup 4.13.4 and checked
original/body bytes and hashes, existing source v6, exact source-link limits,
coverage, stopped owners, seals and CLI/API/ZIP publication. They do not exercise
the active kit collector, every excluded context or G06 exception handling.
All **282 tracked Python/workflow file hashes** remained unchanged through this
matrix, including external operational/test scripts as well as package sources.
The PR94 993-test suite and wheel checks above are prior evidence; they were not
rerun as a new full suite or installation certification for this documentation
change. Four public static contracts, local Markdown file-link checks and the
finite H/E/G row check also passed after documentation edits. Private probe JSON,
frozen hashes and execution logs stay outside Git.

To repeat the selected matrix from a trusted Windows checkout with its installed
dependencies, choose each actual Python environment for the contract command,
then run the integrations serially with the primary environment:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONPATH = (Get-Location).Path + ';' + (Join-Path (Get-Location).Path 'tests')
$modules = @('test_html_contracts', 'test_html_text_contexts', 'test_html_scalar_urls',
  'test_html_url_lists', 'test_css_url_contexts', 'test_css_token_boundaries',
  'test_url_sources', 'test_mime_cid', 'test_form_observations', 'test_kit_static')
python -B -X utf8 -m unittest @modules -v
python -B -X utf8 tests/integration_html_text_contexts_real.py
python -B -X utf8 tests/integration_css_token_boundaries_real.py
python -B -X utf8 tests/integration_url_sources_real.py
```

Freeze source/test/workflow contents before execution and stop validators before
editing them. Only documentation changes in this closure. Constructed probes
and passing contracts establish neither standards conformance nor independent
investigative accuracy. Fresh review/CI on the documentation PR remain gates
before its integration; PR94's completed checks do not substitute for those gates.
That documentation perimeter subsequently integrated in PR95 as
`ce5233a83ac4a859f872a0f5b2628fa64e091133`, with matching reviewed tree,
Copilot approval recommendation/no open issues and green head/merge workflows
`39996864057` / `39997877108`. The measured implementation above remains the
historical PR94 baseline; subsequent attachment coverage is separately recorded.
