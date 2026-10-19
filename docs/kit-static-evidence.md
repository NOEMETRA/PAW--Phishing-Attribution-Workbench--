# Static captured-kit observations

`paw.core.kit_static` repairs the scalar/list HTML, JavaScript and CSS contract
used by `trace_one`. The former parser passed collector lists to string parsers,
losing observations, and produced HTTP/POST attacker-fingerprint defaults even
with no input. Its duplicate `analyze_kit_patterns` implementations are replaced
by one explicit unavailable-attribution boundary.

The separate [legacy kit case publishers](legacy-kit-publication.md) are
explicitly unavailable before source/output access. This package helper does not
automatically ingest or authenticate their saved graphs, TTPs or actor profiles.

Schema version 2 keeps static observations in `observations`, with a source
index, literal/parser value, context and position. Source records identify the
content type and list index. HTML attributes retain duplicate occurrences,
relative targets and parser-decoded character references. Comments and inline
scripts have separate positions; inline offsets refer to a parser data segment.
JavaScript URLs and code markers are lexical matches, including comments and
strings. CSS `url()` arguments remain literal candidates. Keywords remain
literal observations, without assigning a malware family or campaign.

No URL is visited, resolved or executed. Common host/URL substrings are not a
reason to discard evidence. Repeated occurrences retain their separate source
links. This is bounded lexical inventory, not a JavaScript interpreter, browser,
PHP analyzer, renderer, complete URL grammar or behavior verifier.

The direct input contract accepts a dictionary containing `html`, `javascript`
and/or `css`, each a string or list of strings. A malformed list item does not
erase valid siblings. Unknown keys and invalid types/Unicode are explicit
partial-coverage issues. An empty inventory may be completed: this means the
supported input was examined, not that the kit is safe or legitimate.

For direct input, `text_utf8_sha256` covers the **complete supplied text encoded
as UTF-8**, not original file bytes. `analyze_captured_kit` additionally retains
case-relative capture paths, the complete bytes read and their SHA-256. UTF-8
replacement decoding is explicit; a lossy flag distinguishes raw captures from
derived text. File hashes bind the bytes observed at ingestion, not the remote
site's identity or authenticity. Capture files remain in their existing case
directory and are not modified by this reader.
Complete raw-capture metadata survives rejection of replacement-decoded text
by per-source or aggregate text budgets. Oversized raw reads do not receive a
hash of their bounded prefix masquerading as a complete capture hash.

Default budgets:

| Resource | Limit |
| --- | ---: |
| Source records across all three types | 128 |
| Bytes per captured file / supplied UTF-8 text | 1 MiB |
| Total analyzed UTF-8 text | 4 MiB |
| Retained observations across all sources | 2,048 |
| Characters per retained observation | 4,096 |
| Examined capture-directory entries | 1,024 |
| Capture-directory nesting depth | 8 |

Oversized sources are not partially parsed or hashed as if complete. Rejected
sources retain their status/reason; count limits report known omitted source
records. Observation/value limits report total matched and omitted counts within
the sources actually analyzed. Directory limits and read failures set partial
coverage; counts do **not** pretend to enumerate unseen files or unparsed input.
The bounded reader ignores unsupported extensions, skips symlinks/reparse points
and non-regular files, and does not follow capture-directory links. Files are
limited before reading and text decoding. The collection must already be stopped;
this reader is not an isolation layer against concurrent hostile writers.

The legacy helper names remain importable through `trace`. Legacy `c2_servers`,
`callback_domains`, `exfiltration_endpoints`, `obfuscated_code` and
`suspicious_patterns` remain empty; callers must read the versioned observations.
Risk is `unavailable`; the attacker fingerprint is empty and family/campaign
attribution unavailable. Static URL names and markers cannot establish C2,
exfiltration, actual obfuscation, attacker identity or a calibrated risk level.

The trace consumer writes `phishing_kit_analysis.json` and adds an explicitly
unverified artifact reference under `campaign_origin.static_observations`, rather
than turning candidate URLs into a `kit_c2_analysis` infrastructure assertion.
The existing unified matrix retains this artifact under its intelligence-module
key. Active collection and full active report/export behavior remain S14 work.
Static publication is outside endpoint/summary-discovery conditions, with an
explicit no-egress guard. Campaign JSON/container validation precedes all
publication writes: rejection preserves both existing files (or their absence).
The final updated campaign is pre-serialized with the writer's strict
`allow_nan=False` contract before either write. Non-finite retained numbers,
including exponent overflow and nested/sibling values, cannot replace a prior
inventory before rejection. Finite numbers and text containing those token names
remain supported metadata.
Writes are atomic per file, not a transaction across both artifact paths.
The host's full `--no-egress` path continues to skip collection and this consumer;
static helper tests do not prove that detonation is working.

`tests/test_kit_static.py` exercises actual functions and bounded local capture
files, without mocks or sample network access. Constructed sources establish
operational/provenance contracts, not phishing labels or classification accuracy.
POSIX symlink/FIFO checks are separate from Windows validation.

Initial validation on Python 3.13 / Windows: 21 focused tests (20 passed, one POSIX
skip), 533 general tests (525 passed, eight platform skips), actual shared
CLI/HTTP query/export/verification and supervisor-crash recovery passed. A real
wheel contains all 90 Python sources with matching bytes. Actual local Windows
root/nested junction checks passed without following their sources. These checks
do not exercise suspicious-target collection, install all optional dependencies
or establish OS isolation. The POSIX FIFO/symlink regression is included in CI.

The review correction adds scalar/captured raw-versus-derived limit regressions,
rejected publication with existing/absent artifacts and all malformed JSON
container types, and actual static publication with missing/empty/malformed
summary metadata. A source-control-flow regression binds that consumer outside
endpoint/summary guards while retaining the no-egress guard. This is explicit
static reachability/consumer evidence, not an active trace/collection run.
On the corrected source, all 23 focused contracts were included in 535 general
tests (527 passed, eight platform skips). Actual shared CLI/HTTP query/export,
shutdown/crash recovery and the wheel's 90 source-byte matches passed again.

The subsequent serialization correction passed 25 focused tests (one POSIX
skip), all included in 537 general tests (529 passed, eight platform skips),
and a fresh wheel/90-source byte match. The production delta is confined to
preflight serialization in the static publisher; trace control flow and all
other package sources match the preceding reviewed version. CLI/API and the
20-original no-egress corpus results above remain prior evidence, not new runs
for this serialization-only correction. Active collection remains deferred.
