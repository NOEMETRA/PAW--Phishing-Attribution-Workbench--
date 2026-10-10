# Top-level header inventory

New CLI/API cases include `header_inventory.json`, a separate, sealed evidence
artifact. It inventories the existing Python email parser's recognized outer
header fields in order, including unknown field names and duplicate occurrences.
Previously PAW normalized selected fields only; the exact original `input.eml`
was already preserved. This addition exposes the other parsed fields without
changing that selected representation, authentication, index or numeric scores.

Each retained field records its original spelling, lowercase comparison name,
zero-based `header_index` across all outer fields, and zero-based
`occurrence_index` within that case-insensitive name. `raw_value_base64` encodes
the parser value's ASCII/surrogateescape octets, preserving folded values and
undecodable bytes. These are **not complete original field byte spans**: the
parser removes the colon, leading whitespace and final line endings. The source
path and SHA256 bind observations to the unchanged original EML. `input.eml`
remains the exact byte evidence.

`parsed_value` is an individually derived view using that message's email policy,
including supported encoded-word decoding and structured header parsing. Each
duplicate uses its own value. Parser defects, non-ASCII source octets, unsupported
derived parsing and output sanitization are explicit; the raw captured value
survives a failed derived parse. No header claim becomes independently verified.
Syntax defects and unavailable views add no risk or authentication points.

The scope excludes MIME-part/attached-message headers and header-looking body
text. Malformed input follows the existing parser's termination rules and reports
its outer message defects before body transfer decoding. Later body-decoding
defects belong to MIME coverage. A completed inventory means the recognized fields were
captured and their derived views completed within this scope, not that all bytes
of a malformed header section were interpreted or that the message is authentic.

Default extraction limits are 1,024 fields, 256 bytes per name, 16,384 bytes per
raw value and 262,144 captured raw bytes (including captured names). Derived text
is capped at 16,384 characters per field; defect descriptions at 256 characters
and 16 descriptions per field/message, with full defect counts retained. Fields
beyond the count limit are counted as omitted; oversized names/values and values
outside the raw budget retain their position with an explicit limit issue and a
null unavailable value. Long names have null names/occurrence indices. No
truncated value is presented as complete. Distinct-name/duplicate counts cover
only inventoried fields with retained names. The exact source remains available.
These limits bound this additional extraction, not the underlying email parser;
the existing input/MIME and worker resource limits still apply.

Coverage includes a small `header_inventory` stage; technical reports reference
the artifact and counts without embedding arbitrary header markup. Stable case
detail exposes `header_inventory` through the existing API read guard. ZIP export
includes it, and normal case sealing verifies it. Historical cases without the
artifact remain readable.

`test_header_inventory.py` checks order, duplicates, byte/derived distinctions,
malformed termination, nested scope, limits and parser-failure retention.
`integration_header_inventory_real.py` runs nine actual `full --no-egress` CLI
cases plus two actual loopback HTTP workers, checking independently parsed raw
values, original bytes, seals, API detail and ZIP content. Constructed fixtures
test extraction contracts; they are not phishing ground truth. No sample URL,
domain lookup or attachment execution is performed.
