# MIME body evidence

New cases include `mime_body_evidence.json` and separate files under `mime_body/`
for the supported outer-body parts: `text/plain`, `text/html`, `text/javascript`.
Previously these parts had hashes/metadata and joined analysis representations;
their individual byte payloads and text were not saved separately. The original
`input.eml` was already preserved and remains the authoritative byte source.

For each part, the artifact records its parser-tree `part_id`, declared MIME,
disposition/Content-ID, byte source, defects, charset decoding metadata, payload
size/hash/path and separate UTF-8 text size/hash/path. The whole input's SHA256
binds the observations to `input.eml`. Payload `.bin` files retain the already
transfer-decoded bytes **before charset replacement**. Text `.txt` files contain
the derived charset view, before independent parts are joined for analysis.
HTML source and JavaScript source remain text; they are not rendered or executed.
These representations are not exact MIME byte spans or independent authenticity.
Raw transfer encoding, boundaries and original headers remain in `input.eml`.

The [parser-selected MIME context](mime-context-evidence.md) also travels with
new body records. Repeated/defective declarations, known parser structure defects
and inherited uncertainty make the record partial without changing its existing
byte/text view. This is separate from charset/transfer status and completeness
of the bounded header catalog.

Unsupported or empty transfer encoding declarations retain the parser's undecoded
payload with `byte_source: undecoded_unsupported_transfer_encoding`. Failed
base64-length or uuencode decoding uses `undecoded_failed_transfer_encoding`.
An uuencode decoder may return recovered bytes even when its `end` terminator is
missing. Such bytes are retained as `transfer_decoded_incomplete_framing`, with
partial transfer decoding and coverage. The terminator must follow the first
valid-mode `begin` block selected by the parser; an `end` in the preamble or an
ignored invalid-mode block does not complete that stream. This checks framing
without changing the recovered bytes or executing the decoded content.
Duplicate transfer declarations retain the stdlib's first-header interpretation
as `derived_first_transfer_encoding`. These cases record a separate, partial
`transfer_decoding` observation with declarations and reason in MIME metadata,
body evidence or attachment metadata, and make the relevant coverage partial.
Successful charset conversion cannot imply successful transfer decoding. No
alternative encoding is guessed; the exact original remains in `input.eml`.
Known successful transfer decoders and identity encodings keep their behavior.

Identity domains follow [RFC 2045 sections 2.7-2.9 and 6.1](https://www.rfc-editor.org/rfc/rfc2045#section-2.7).
An absent declaration defaults to `7bit`; it is not an unspecified binary stream.
Both `7bit` and `8bit` reject NUL, bare CR/LF and lines over 998 octets. `7bit`
also excludes octets above 127. `binary` permits arbitrary octets and line lengths.
Violations retain unchanged bytes as `identity_bytes_invalid_transfer_domain`,
with partial transfer provenance in both body and attachment inventories. A
compatible charset can still produce complete text while transfer coverage is
partial. No output bytes are repaired and no risk points are added.

The transfer contract is tested as a family, rather than only the latest review
example:

| Transfer declaration | Checks and retained representation |
| --- | --- |
| Absent, `7bit`, `8bit`, `binary` | Identity domains above, case-insensitive declarations, 998/999 boundary, CRLF versus bare breaks, NUL/high octets, unchanged body and attachment bytes. |
| `base64` | Parser-decoded bytes and decoding defects; impossible-length fallback remains explicitly undecoded. |
| `quoted-printable` | Escape/line/literal checks below; recovery and unsupported padding remain partial. |
| Four uuencode aliases | Parser decoding/fallback and selected-block terminator; recovered truncated streams remain partial. This is a framing check, not a complete uuencode grammar validator. |
| Unknown, empty, duplicate | Undecoded unsupported declaration or explicit first-header interpretation, always partial. |
| Embedded message | Original-wire identity-domain checks for `message/rfc822`; derived serialization stays in attachment scope. Missing/ambiguous mapping or unhandled transfer interpretation is explicitly partial. |

Completion describes the implemented extraction/checks and their recorded
defects; it does not establish complete transfer-format conformance for every
decoder, message authenticity, or malware analysis. The original wire bytes
remain available even when a tolerant decoder recovers a representation.

Quoted-printable syntax is checked against
[RFC 2045 section 6.7](https://www.rfc-editor.org/rfc/rfc2045#section-6.7):
uppercase two-digit hexadecimal escapes, CRLF hard/soft breaks, permitted literal
octets and encoded lines of at most 76 bytes. Malformed escapes (including `=`
at EOF), lowercase hexadecimal recovery, noncanonical line breaks, illegal raw
octets and overlong lines use `transfer_decoded_partial_syntax` and partial
transfer coverage. Transport padding is valid to receive, but Python retains it
and fails to remove padded soft breaks; that unsupported interpretation is also
partial. Existing parser-decoded bytes are retained without repair or guessing.
No new authentication or risk contribution is introduced. `input.eml` retains
the exact original transfer representation, including any bytes the tolerant
decoder omits from its derived result.

Unknown/invalid charset fallback remains explicit in `decoding`. Defects or
partial decoding make that part and inventory partial without losing captured
payload bytes. UTF-8 transport cannot silently rewrite a derived unencodable
string: its text path is null/unavailable with an issue, and payload bytes remain.
Files use parser-generated IDs, never MIME filenames. Invalid/duplicate IDs are
rejected before writes; exclusive creation prevents overwriting existing files.

Attachment/nested-message bodies do not become the outer message body. Inline
binary content, text attachments, forwarded messages and unsupported types stay
in the existing attachment path. MIME containers are metadata, not body files.
An empty inventory completes within this supported scope; it does not prove
complete MIME parsing or attachment analysis. Full MIME coverage remains separate.

For `message/rfc822` attachments, the identity-domain check uses the original
encapsulated-message bytes, including its headers. Checking `child.as_bytes()`
would conceal changes made by folding headers or normalizing line breaks.
The bounded parser retains its original source. A framing-only lookup follows
multipart delimiters that match its existing tree, keeps offset/count bounds and
does not enter the embedded message or decode it again. Missing/ambiguous framing,
duplicate or unhandled transfer declarations, objects without a bound original,
and other unvalidated `message/*` subtypes remain explicitly partial as
`derived_embedded_message_transfer_unavailable`. Invalid original identity bytes
use `derived_embedded_message_invalid_transfer_domain`. Both retain the existing
derived serialization rather than mislabeling it as unchanged wire bytes.
Valid supported identity domains retain `derived_embedded_message_serialization`.
This checks the enclosing attachment's transfer domain; it does not claim full
content/format validation of the encapsulated email or fetch external bodies.

### Separate original embedded-message body bytes

`message/*` attachments additionally expose `original_wire` in MIME and attachment
metadata. It describes a byte span of `input.eml` located by the existing
framing lookup, with scope `parser_matched_original_mime_body_span`. Captured spans
include the encapsulated headers, folded/duplicate fields and original line
breaks; they exclude enclosing MIME headers and the boundary separator's newline.
Root `message/*`, nested multipart siblings and implicit `multipart/digest`
messages use the same lookup. The lookup stops at the enclosing message part;
it does not recursively create original files for its inner messages.

Captured metadata records the source EML path/SHA-256, zero-based byte `offset`,
`size` and span SHA-256. The attachment scanner writes a separate generated
`attachments/wire-part-<part-id>-<sha256>.bin` with exclusive creation and exposes
its `evidence_path`. Direct calls without a persistence directory retain the
in-memory capture metadata without a path. Existing attachment `size`, hashes,
`byte_source` and `evidence_path` still describe the existing parser representation;
neither representation silently replaces the other. Both files enter normal
case seals and exports, and the API exposes existing attachment metadata.

Capture is independent of transfer interpretation. Unsupported, duplicate or
invalid transfer declarations can leave interpretation partial while preserving
the exact located encoded bytes. `transfer_decoded` and `authenticity_verified`
are false for the original span. A captured span is not verified authentication,
format conformance, complete message parsing or malware analysis. It does not
make inner headers or URL candidates part of the outer message's evidence.
Non-message opaque content keeps its existing decoded attachment contract.

Missing bound source, unclosed/nonmatching multipart framing or a parser defect
that prevents locating the body produces `status: not_evaluated`, an explicit
reason and no span/hash/file. MIME and attachment coverage remain partial. No
serialization is substituted for missing original bytes. The full source still
remains in `input.eml`.

Span lookup stores offsets until an attachment is processed; no new decoder or
external read is introduced. The original source is limited to 25 MiB, and
mapped outer attachment body spans do not overlap or descend into one another.
Thus their aggregate additional retained bytes cannot exceed the original-input
limit. Existing part/depth checks apply before lookup; existing decoded-byte
limits continue to account for the parser representations independently.

Nine contract tests cover original versus derived bytes, exact boundaries,
root/nested/digest scope, empty bodies, subtypes, invalid/unsupported transfer,
unavailable mapping, limits, exclusive writes, tamper-detecting seals and no-egress.
The focused integration runs twelve actual full CLI cases and five loopback HTTP
workers, independently checking fixture byte spans, derived parser output,
source hashes, partial coverage, API/ZIP files and seals. These constructed
inputs establish extraction regressions, not classification accuracy.

The existing input, part/depth, decoded-byte and text-byte limits apply before
persistence. Supported body payloads share the 2 MiB text-byte budget; retaining
them does not introduce unbounded reads or a second decoder. Persisted UTF-8 text
can have a different size from the original charset bytes. Numeric scoring,
authentication, URL interpretation, joined deobfuscation and attachment scanning
are unchanged. No content execution, active fetching, archive extraction, macro
analysis or malware verdict is added.

The small `mime_body_evidence` coverage stage and technical report reference
the new artifact. Stable-case API detail exposes its metadata; normal seals and
ZIP exports include all new files. Historical cases without it remain readable.

Contract tests cover original octets versus derived text, alternatives, attached
scope, malformed base64, unsupported/failed/duplicate transfer declarations,
empty/JavaScript payloads and safe exclusive writes.
The real integration runs thirty-three actual supervised `full --no-egress` CLI cases
and fourteen loopback HTTP workers, independently checking payload bytes, charset text,
part mappings, original MIME, seals and API/ZIP exports. Constructed messages are
regression inputs, not a classifier accuracy corpus.
