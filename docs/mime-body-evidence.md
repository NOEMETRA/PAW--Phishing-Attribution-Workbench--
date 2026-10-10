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
The real integration runs twenty actual supervised `full --no-egress` CLI cases
and nine loopback HTTP workers, independently checking payload bytes, charset text,
part mappings, original MIME, seals and API/ZIP exports. Constructed messages are
regression inputs, not a classifier accuracy corpus.
