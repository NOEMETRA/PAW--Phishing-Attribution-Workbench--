# URL identity and derived evidence

The previous URL decoder changed network destinations while interpreting their
content. For example, `https://example.invalid/a%2Fb?x=a%26admin%3D1` became a
different path and query. Base64 tracking containers were substituted into their
enclosing links, and visually similar Unicode hostnames became the imitated
ASCII hostname. The trace pipeline then appended these strings to the URL list
used for reports, enrichment and automatic detonation.

The URL interpreter now preserves existing HTTP(S) URL bytes, including percent
escapes, duplicate query fields, plus signs and fragments. Explicit textual
defanging (`hxxps`, bracketed dots in the hostname) and encoded whole URL strings
can be recovered, with the original string and transformation provenance retained.
Whole URL decoding stops when the scheme is recovered: resource components are
not decoded again. Refanging does not alter user information, paths or queries.

`deobfuscation_results.json` records `embedded_url_candidates` independently from
`final_url` and `network_url`. Candidates carry the source URL, component, index,
encoded value, decoding steps and, for JSON tracking containers, a JSON pointer
to the URL string value. They are `candidate_not_verified`, with
`network_target: false`. They do not establish that a redirect occurs.
Arbitrary prose containing `http` is not treated as an absolute URL.

Hostname metadata includes an observed hostname, IDN display form and a visual
comparison string. The comparison uses a limited character map, explicitly marked
as incomplete Unicode confusables coverage. It does not verify brand ownership
and is never substituted into a network target. The public homoglyph URL API and
the main deobfuscation engine preserve this same contract.

Candidate extraction inspects the original MIME-decoded body representations:
plain/visible text and subject, parsed HTML attributes, all HTML text (including
inline scripts), HTML comments, and non-attached `text/javascript` parts. XML
namespace declarations identify vocabularies and are excluded as network links.
Visible text is scanned after MIME joins it across tags, so individual parser
chunks cannot add truncated URL prefixes. Script/style text is scanned separately. HTML
character references are interpreted once by the parser, matching the ordinary
MIME URL inventory; raw markup containing `&amp;` is not added as another target.
MIME extraction retains `html_parts` as separate decoded body documents. Each
gets a fresh candidate parser, so an unclosed script/style/comment in one part
cannot change attribute parsing or namespace exclusions in a later part. The
joined `html` representation remains available for the other analysis layers.
Base64 candidate recognition probes at most 12 encoded characters (nine bytes),
accepting all case variants of `http`, `https`, `hxxp` and `hxxps`, standard and
URL-safe alphabets, and unpadded inputs. Legacy scheme-like malformed candidates
remain inspectable; full decoding and target validation still apply separately.
Script text remains literal and is never executed. No candidates are extracted
from the rewritten HTML/JavaScript produced by generic deobfuscation or from
attachments/embedded emails. Extracted strings still pass the same bounded URL
interpreter and target validator; hidden invalid inputs produce partial coverage.

`url_evidence.json` and `headers.json.url_evidence` inventory observed URLs and
recovered textual URLs with provenance. Network targets are deduplicated separately
from evidence records: distinct source strings and transformation paths remain
visible even when they recover the same target, while identical records appear
once. Invalid, unresolved and decoding-limited textual candidates also remain in
the inventory, even when no observed HTTP(S) URL exists. Their `url` and
`source_url` retain the original input; `decoding_attempts` records the failed
recovery path, with the outcome in `status` and `reason`. They have
`network_target: false` and never enter `headers.json.urls`. Non-target inputs
already observed by MIME extraction retain observed provenance; other textual
inputs have `provenance: text_url_candidate`. Ports, missing hosts, controls, ambiguous
backslashes, encoded hostname delimiters and malformed percent escapes in any
component are checked locally. Each `%` must be followed by two hexadecimal
digits; complete octets such as `%FF` are retained without UTF-8 decoding of
resource components. These are bounded conservative syntax checks, not a full
browser URL parser or proof of
authenticity. URL interpretation coverage reports invalid/unresolved inputs,
decoding limits and candidate counts.

Decoder limits are explicit: 65,536 characters per URL, 16,384 per embedded token,
four decoding rounds (configuration capped at eight), 128 tokens, 32 candidates,
128 JSON nodes and eight JSON levels. Reaching a limit produces partial coverage.
The generic engine no longer repeats URL decoding through text/homoglyph layers,
which previously multiplied decode budgets and discarded structured indicators.

The change follows the distinction between reserved URL delimiters and encoded
data in [RFC 3986, sections 2.2–2.4](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.2),
and the distinction between visual comparison and identity in
[Unicode UTS #39](https://www.unicode.org/reports/tr39/#Confusable_Detection).
The local comparison map is not presented as a complete UTS #39 implementation.

## Validation

- 42 URL contract tests exercise resource identity, whole URL recovery, Base64,
  nested JSON tracking, invalid UTF-8, IDN/visual comparisons, user information,
  malformed inputs, colliding provenance, all 256 complete resource percent
  octets, deterministic inventories, failed/unresolved/limited source retention,
  HTML/script candidates, character-reference semantics, split visible text,
  namespace identifiers, independent MIME parser state, all 96 supported scheme
  case spellings in Base64, bounded prefix probing, attachment boundaries
  and bounded decoding. They replace
  the old non-failing harness that expected rewritten destinations.
- Real supervised `full --no-egress` CLI regressions use 11 constructed messages:
  plain, ordinary HTML, failed-only candidates, the review's invalid-only HTML
  attribute, hidden HTML attributes, inline script, a JavaScript MIME body,
  uppercase/mixed-case/defanged Base64 attributes, and three multipart cases with
  an unclosed script/style/comment preceding an independent HTML document.
  They preserve original bytes, verify case inventories, and assert that
  malformed URLs, comparison strings and embedded candidates are not network
  targets. These fixtures are not classifier accuracy ground truth.
- The full Windows contract suite passes: 144 tests, five POSIX-only skips.
  Real CLI/API shared-directory and crash-recovery integration also passes.
- A private pilot of 20 distinct original EMLs contains 300 MIME-extracted URLs.
  Before the change, 50 were altered and appended as additional reported URLs
  across three messages. After the change, all 300 retain their bytes and no
  additional rewritten targets appear. Expanded hidden HTML coverage retains
  four more byte-identical URL literals found in the originals, for 304 network
  inventory entries. The previous 50 embedded candidates remain available
  separately (28 in decoded JSON tracking containers), with one more found by
  expanded coverage, for 51. Additional literals are not proof of active redirects
  or authenticity; their syntax and source are inspected offline.
- All 20 real cases complete with verified seals, preserved original bytes and
  explicit no-egress. The run after the review fixes takes 24.00 seconds with a
  peak sampled process-tree RSS of 134.75 MiB, observed every 50 ms. Tests ran concurrently;
  this single run does not establish a performance improvement or reproduce the
  historical four-hour online workload.

Verdicts remain 19 Inconclusive and one Suspicious or compromised account. Three
scores fall by 0.01 because routine link interpretation no longer counts as a
destination transformation; scoring thresholds are unchanged. This does not
establish detection accuracy. Original spam labels need per-message adjudication;
Inconclusive is not a benign classification. Detonation, network enrichment and
DNS-dependent authentication checks remain excluded/unavailable on this host.
Raw emails, account identifiers, tracking values and private run files are not
included in the repository. UI and the separate Linux lab remain deferred.

## Per-part and selected-header source links

The existing inventory preserves original candidate strings and transformation
paths, but deduplication loses the connection to individual body parts. A real
offline regression has the same URL in plain text, HTML and Subject: one URL
record survives, with all three source representations retained elsewhere but
no structured links between them.

`url_source_inventory.json` adds those links without changing any existing URL
record, decoder, target or score. A link contains an ordered `url_evidence_index`
into `url_evidence.json` and a `source_index` into the source catalog. Body sources
reference `mime_body_evidence.json`, part IDs and persisted charset-text
paths/hashes/status. Selected header sources reference the first Subject/From
views in `headers.json`, their original parser field indexes and the availability
of the corresponding `header_inventory.json` field. The full source EML hash
binds the catalog to the existing body/header inventories; inconsistent source
bindings are rejected. The catalog is written after `headers.json` and the other
referenced artifacts. The catalog uses the existing `atomic_json` writer:
serialization and a temporary sibling write precede atomic replacement of the
final path. An interruption before replacement leaves no published catalog;
after replacement it is complete. A killed worker may leave a temporary fragment
as raw partial evidence; it is not exposed as the published catalog. No claim of
power-loss durability is made. An interruption after publication retains the
referenced files before partial
sealing, which still requires confirmed worker-tree shutdown.
The API exposes both inventories, seals/ZIPs include
the artifact, and the technical report and coverage reference it. Historical
cases without it remain readable.

Links mean exact candidate presence in a supported representation, once per
source and URL record. Repeated occurrences within the same part, HTML attribute
versus visible-text positions and original byte offsets are not inventoried.
HTML sources are labeled `html_parser_derived_url_candidate_views`, with a
separate `derived_from` descriptor containing the persisted
`per_part_charset_decoded_text` input path/hash/status. The input file can contain
`&amp;` or markup splitting a URL; the linked candidate need not occur literally
in that file. Derived candidate views are not persisted, as explicitly recorded
by `derivation.persisted=false`.

The derivation method `paw_html_url_candidate_views_v2` re-parses each part using
fresh `HtmlEvidenceParser` state and `extract_mime_url_candidates`: character
references in attributes/visible text are decoded once, visible text is joined
across markup, supported attribute values are inspected, and script/style text
and comments follow the existing literal candidate rules. The MIME observer's
supported URL attributes and HTTP strings in joined visible text are included
too. No JavaScript is executed. This describes the union of candidate views,
not an exact attribute/text position or a literal substring of parser input.
Derived records match their original
`source_url`, so colliding recovered destinations still link to their respective
original candidates. Invalid and unresolved records can also have known sources;
locating their sources does not make them valid targets.

Only supported non-attached body parts and the first selected Subject/From views
are in this scope. Duplicate later headers, other fields, opaque content and
attached/embedded messages retain their separate inventories. Completion of this
catalog is not complete URL discovery, successful decoding, execution,
authentication or verified attribution. Partial charset/transfer provenance and
missing persisted text remain explicit in the referenced body evidence; this
stage describes source linkage separately.

No URL strings are duplicated in links. The source catalog is bounded by the
existing MIME part/depth/input limits plus two selected headers. Default limits
retain an ordered prefix of 4,096 links and at most 256 unmatched record indexes.
All matching pairs are counted, including omitted links. `mapped_evidence_count`
counts located records before retention limits; it does not assert that every
link is retained. Total/inventoried/omitted link counts, unmatched record counts,
omitted unmatched-index counts and issues distinguish completed, limited and
partial linkage. Missing source matches are never invented. The lookup adds no
external access or new decoder, and uses the same bounded source views as the
analysis worker.

Eleven extraction contracts cover repeated parts/header sources, candidate collisions,
invalid/unresolved URLs, HTML entities/split visible text/comments/scripts,
independent parser state, charset/header limits, attached scope, missing source
matches, exact prefix accounting, input binding and no-egress. Nine actual full
CLI cases and five loopback HTTP workers independently check source contexts,
files/hashes, API/ZIP, coverage and seals. Five additional contracts pause a real
no-egress trace after writing headers, during catalog serialization, after a
partial temporary write, before atomic replacement, or after publication.
They cancel the supervised process tree and check the sealed partial cases:
no premature or malformed published catalog, and no dangling references after
publication. Interrupted temporary bytes remain stable raw evidence.
The actual limit fixture has 100 URL
records in 50 independent text parts: 5,000 links, 4,096 retained and 904 omitted.
Constructed inputs test linkage regressions, not classification accuracy.

The [HTML URL-list boundary contract](html-url-list-contexts.md) supplies the
current srcset/imagesrcset tokenization shared by observation, recovery and
source views. Version 2 distinguishes separator commas, resource commas and
descriptor/nonnetwork content; historical version 1 artifacts are retained.
Descriptor/list conformance, relative resolution and resource selection remain
explicitly not evaluated. These changes correct affected list-derived URLs;
source linkage itself still does not modify the URL records it receives.

The [literal CSS URL boundary contract](css-url-contexts.md) extends HTML source
views to v3. Style attributes and style raw text share whole `url(...)` argument
boundaries; malformed expressions remain non-target text rather than truncated
URLs. Data/relative arguments cannot contribute embedded HTTP substrings.
CSS escapes and browser resource selection remain unevaluated; other lexical
contexts retain their prior behavior. Historical v1/v2 artifacts are preserved.

The [whole scalar HTML field contract](html-scalar-url-contexts.md) extends source
views to v4 for href/src/action/formaction/poster and object.data. Complete
recognized values are retained; nonnetwork envelopes and invalid fields do not
contribute inner HTTP strings or valid-looking prefixes. Legal punctuation and
all original recovered-source records remain intact. Browser normalization and
relative resolution remain unevaluated; historical v1/v2/v3 cases are preserved.
