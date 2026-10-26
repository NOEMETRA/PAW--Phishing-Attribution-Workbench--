# Explicit forensic representations (P2)

`paw inspect-representations <local-file> --interpretation mime|html-utf8`
creates a separate forensic case. Interpretation is an explicit request, never
inferred from the suffix, a classifier score or a successful recovery. It uses
P1 acquisition and modern analysis ownership; original caller bytes are not
rewritten. The source file and every representation remain distinct from any
future permission to execute a sample.

The case contains `source.bin`, content-addressed `blobs/<sha256>.bin`, a
manifest, execution record, `report/representations.json` and
`report/interpretations.json`. Nodes bind kind, exact byte length/hash, parent
IDs, transformation name/version/parameters, completion and notes. Their IDs
recompute from canonical JSON metadata; deduplicated bytes do not merge
different interpretation identities. The original root is always retained.
Root/candidate/selected nodes all state origin unverified and authority none.
The existing seal and ZIP attest local file consistency, not authenticity.

MIME interpretation observes the existing PAW parser and selected decoder
without changing their rules. Original wire-body slices are mapped only where
complete selected framing and child counts agree. Missing separators/closing
boundaries or ambiguous structure produce explicit unavailable mapping and
partial context, never reserialization presented as original wire. The report
records duplicate declarations, selection/context defects, Python parser
version and the exact selected payload's byte-source label. Non-ASCII raw
declaration octets use bounded labelled hex, preserving their digest without
unpaired Unicode surrogates or replacement text in the HTTP response.

Finite alternative transformations include strict standard Base64 with recorded
SP/HT/CR/LF removal, explicit missing-padding addition where possible, and only
a complete-quartet prefix when the remainder cannot be recovered. Omitted
normalized suffix bytes and noncanonical pad bits remain explicit.
Quoted-printable candidates decode valid escapes/soft breaks and preserve
invalid or dangling equals signs, including their count and bounded offsets.
Strict text views allow UTF8, ASCII, Latin1, Windows1252 and explicit UTF16LE/BE;
unsupported declarations/invalid decoding are omitted with reasons. No decoder
silently inserts replacement characters or replaces the original/selected view.

For declared HTML parts, both parser-selected and recovered candidate text get
their own bounded lexical observations and `view_role`. Standalone HTML requires
the explicit UTF8 interpretation. Positions refer to the selected decoded text,
not MIME byte offsets. HTMLParser events/counts/digests establish neither a
browser DOM nor markup validity. Scripts, styles, entities, references and forms
are not executed, fetched or used as host paths. A complete lexical observation
of a partial recovery does not remove its partial ancestry or overall coverage.

Public jobs run only with POSIX controls and fixed budgets:8MiB source,24MiB
representation bytes charged per node,64MiB aggregate byte work,64 nodes and
depth8. MIME has32 parts/depth6,64KiB wire-header search,256 header fields,
256-byte declaration values and two transfer alternatives. HTML has1MiB input,
4096 tokens, depth64 and65536 characters per tag. Omission inventory/count and
overflow are explicit. Standalone library limits are configurable within finite
caps; public job/API limits are fixed and cannot be expanded in a request.

The existing process supervisor enforces45s overall/15s stage,256MiB memory,
96MiB artifacts/160files/128KiB log; the POSIX worker has10/11s CPU, no core
dumps and80MiB per-file limit. Worker umask0077 makes generated ZIPs private
from creation in existing case stores. Cancel, deadline and worker-loss tests
retain exact acquired bytes, block access before known tree shutdown, then seal
honestly partial results. CPU/memory/deadline failure is not completed analysis.
The Python no-egress guard remains application policy, not OS isolation.

The local API accepts uploaded sources through existing `/api/sources/upload`,
then `POST /api/sources/representations` with `file_path` and the required finite
`interpretation`. Extra execution/options/limits and unknown interpretations
refuse. Queue/cancel/recovery are shared; forensic views expose their own source,
graph, interpretation, execution and partial coverage without invented email or
score fields. ZIP/integrity consumers keep existing stopped-writer guards.

Alternate multipart boundary trees, serialized embedded-message interpretation,
arbitrary charset guessing, browser rendering, grant issuance, VM execution and
real egress are outside P2. P3 must separately bind an explicitly selected view
to its source/parent case, exact bytes and one-use authority; existing strict
bridges remain unchanged. Development/acceptance uses owned harmless fixtures.

Local Linux/Python3.14 acceptance on26 October2026 passed29 pure module tests,
20 actual CLI/HTTP cases in source mode and20 using the installed wheel, plus
three CLI refusals per mode. Both modes passed real cancellation, narrowed-stage
deadline and worker-loss checks with exact originals, blocked live readers and
known-stop partial seals. Existing P1 source/installed eight-case checks, four
CLI lifecycle/privacy tests, queue and recovery regressions passed. P2 still
requires exact-head review, required CI, merge and main verification before
phase closure; these measurements do not enable a grant or guest execution.
