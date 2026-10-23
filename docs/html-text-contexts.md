# Independent HTML text contexts

Baseline: merged PR92, `62040da2898acd523bd0513e944f16069de5455e`,
23 October 2026. Codex accepted exact head
`664954fa1612f95a9bbabcc8c6f7079b9b2079fc`; its two earlier findings are
resolved. Head and merge each have three successful checks, with identical
Git trees. Merge workflow: `39974092712`.

## Reproduced boundary family

The MIME and candidate parsers treated markup inside textarea/title and other
text elements as real nodes. A literal style element could remove supplied
text and invoke the CSS argument parser; literal form, iframe, hidden-element,
encoded-attribute and CID declarations could become observations of nodes
which were never present in that lexical context. The optional HTML observation
parser and kit/form consumers disagreed about these boundaries.

All six parser consumers now share `HTMLTextContextParser`: MIME visible-text
derivation, URL candidates, CID attributes, bounded forms, static kits and the
optional BeautifulSoup adapter. Textarea/title character references decode
once. Raw text in xmp/iframe/noembed/noframes and script/style retains literal
entity spelling. Plaintext continues through EOF. Only a matching ASCII end
name and delimiter ends these text contexts; quoted end-token attributes do
not terminate on an embedded greater-than sign. A selfclosing slash on these
nonvoid elements does not expose their contents as markup. Incomplete text is
retained at EOF, without an invented closing event.

HTTP-looking strings in literal text remain lexical URL evidence, not resource
use. For example, a CSS-looking string inside textarea keeps its literal closing
parenthesis; an actual style element continues to use the existing CSS argument
contract. No global URL punctuation stripping or new CSS decoding is introduced.

Source derivation is `paw_html_url_candidate_views_v5`. Original EML, decoded
body payloads and per-part persisted text retain their bytes and hashes.
Historical v1-v4 cases and seals are not rewritten.

## Independent MIME documents and publication

The original joined HTML summary also let an unclosed first document swallow a
real form in the next MIME part. The actual probe returned form counts `[0, 1]`
when parts were parsed separately and zero when joined. The full worker now
passes independent HTML documents into deobfuscation.

A scalar document retains HTML schema 2. Multiple documents use schema 3 with
an indexed `documents` array, individual schema-2 observations and per-document
limits/status. There is no flattened, purported original HTML tree across MIME
boundaries. Each worker-produced document, including scalar HTML, references
its `mime_body_evidence.json` part ID, text path, capture status and SHA-256.
Captured text must match the analyzed original before publication. Aggregate
coverage propagates a partial document/optional-parser result; HTML risk remains
not evaluated and contributes no calibrated score.

## EOF resource regression

A 700,000-byte tail of repeated incomplete end-tag prefixes exposed repeated
stdlib EOF recovery scans in the proposed shared parser on Python 3.13. The
bounded subprocess regression timed out after ten seconds before the final
guard. At EOF, the incomplete remaining token is now retained once without
fabricating an end tag. The regression finishes within its bound, preserving
the complete text, and the same supplied input passes actual full offline CLI
and loopback HTTP workers. This is one resource contract, not a throughput
benchmark or an explanation of historical four-hour analyses.

## Verification and limits

Windows Python 3.13.5 / BeautifulSoup 4.13.4: **976 tests, 962 passed and 14
expected exclusions**, including 18 new methods. Initial boundary regressions
fail against the baseline. Actual independent-document and EOF probes also
precede their corresponding corrections. The first source-binding integration
caught a conditional local hashlib import shadowing the existing module import;
the redundant local import was removed before the successful matrix.

Nine integration/build scripts passed serially during this family:

| Contract | Actual CLI / loopback HTTP cases |
| --- | --- |
| New text contexts, MIME documents, source binding and EOF | 15 / 6 on final runtime |
| Existing HTML URL lists | 11 / 5 |
| CSS argument boundaries | 8 / 3 |
| Scalar URL fields | 8 / 3 |
| URL source inventories | 9 / 5 |
| CID inventories | 13 / 5 |
| Original HTML observations | 5 / 0 |
| MIME declaration/context selection | 16 / 4 |
| Actual wheel | Metadata, entrypoint and all 95 Python sources |

After the final EOF refinement, the full suite and text-context, HTML-list,
URL-source and wheel integrations passed again on 252 frozen runtime/test/
workflow files. The earlier CSS/scalar/CID/MIME rows describe the preceding
family revision; committed CI independently runs the full workflow. Assertions
check exact targets/original candidates, per-part hashes and raw/body bytes,
5,000/4,096/904 source-link accounting, stopped owners, coverage, seals and
CLI/API/ZIP parity. Validators stop before documentation changes. A subsequent
print-only correction names the stress payload as 700 KB rather than 650 KB;
assertions and runtime are unchanged. Four public static contracts pass again.

This is lexical forensic extraction, not HTML5 tree construction or browser
rendering. Insertion modes, foreign content, scripting-dependent noscript,
escaped script-data states, whitespace/layout repair and resource selection
remain outside the supported interpretation. Full CSS grammar, escape decoding,
imports/cascade, relative/base resolution and execution remain unevaluated.
Absence of an observed node is not safety, authenticity or browser behavior.
Reference: [HTML tokenization and text states](https://html.spec.whatwg.org/multipage/parsing.html#tokenization).

Existing MIME byte/part limits, local observation budgets and worker deadlines
remain applicable. Constructed fixtures establish regression contracts, not
classifier accuracy. No sample URL/domain was visited/resolved, no attachment
executed and no Docker started; application no-egress is not OS isolation.
Fresh exact-head GitHub Codex review and CI remain required before integration.
This family does not close the whole engine, platform/install, corpus, egress
or UI audit.
