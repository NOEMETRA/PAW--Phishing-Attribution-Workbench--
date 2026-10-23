# Attachment capabilities, unavailable content and report coverage

Baseline: merged PR95, `ce5233a83ac4a859f872a0f5b2628fa64e091133`,
23 October 2026 (Europe/Rome). The [finite HTML/CSS perimeter](html-css-scope.md)
assigns attached/embedded content to G01 and unresolved resource relationships to
G02. This family reconciles those advertised capabilities with actual output;
it does not add document parsing, resource resolution or archive extraction.

## Actual baseline discrepancy

Eight actual supervised `full --no-egress` cases preserved 24 selected attachment
payloads. They included opaque declared types, inline HTML/CSS, embedded HTML
email, ZIP count/name limits, nested/encrypted declarations, reader errors and a
Content-Location/CID example. The metadata stage completed or became partial as
documented, and original payloads and seals remained intact.

None of the 24 attachment records explicitly described document/URL extraction
coverage. The technical report had no extraction-coverage section, including
the ZIP cases with an omitted member, a limited name, a malformed reader input
and an unsupported reader version. Those facts existed in `attachments.json`
but were missing from its report consumer. Existing malware/macro/type flags
were already unavailable; metadata completion did not mean content analysis.

This is an output/consumer omission, not evidence loss, a demonstrated malware
miss or a claim that the previous engine extracted those document formats.
Baseline inputs, observations and complete cases remain private outside Git.

## Finite capability disposition

| Input / existing operation | Supported output | Content or relationship interpretation |
| --- | --- | --- |
| Arbitrary parser-selected attachment payload, including empty data and declared PDF, Office/OLE, image, calendar, RAR, 7z, gzip or opaque bytes | MIME-declared type/name/disposition, part identity, payload size, SHA-256/BLAKE3 and entropy; payload saved using generated part/hash paths. | Independent MIME detection, document text, macros, malware, decryption and risk remain unassessed. Declared type/extension or magic-looking fixture bytes do not establish a valid format. |
| Attached text/HTML/CSS and filename-bearing inline HTML | Same byte-preservation and metadata path. | No inner text/HTML/CSS parsing or URL extraction into outer body inventories. An inline declaration does not override filename-based attachment selection. |
| Embedded `message/rfc822` | Separate derived serialization and, when supported framing is available, original wire body span, source offset/hash/path and transfer uncertainty. | Embedded body/HTML/URLs do not become outer-body observations. Existing parser-node header inventories remain separate; preservation does not authenticate inner sender claims. |
| Supported ZIP prefix and readable central directory | Bounded ordered member declarations, counts, names/path observations, encryption flags, macro-container name markers, limits and omissions. | No member decompression, CRC/local-header validation, macro-content inspection, recursive ZIP/document parsing or malware verdict. Names/declared sizes describe directory metadata. |
| Nested ZIP or declared encrypted/unknown-compression member | The outer supported central directory can still be inventoried; encryption is a declaration. | No recursive member read or decryption. A metadata-only result does not certify usable compression or readable contents. |
| Self-extracting/prefixed ZIP or unrecognized archive prefix | Payload preservation; ZIP inventory reports `not_evaluated` with its prefix limitation. | No assertion that the payload is not an archive, is unencrypted, contains no members or is safe. No RAR/7z/tar/gzip extraction is advertised. |
| Malformed/unsupported ZIP reader | Per-attachment error and partial metadata stage; other selected attachments remain available. Unknown entry counts remain absent. | An unreadable directory is not zero members. Existing [ZIP contract](attachment-archive-inventory.md) defines the caught-reader and malformed-name scope. |
| MIME/transfer/context defects and limits | Existing partial provenance, original EML and preserved decoder representation; admission/extraction budget failures remain failures. | Byte preservation does not establish unique MIME interpretation. Limits are not bypassed by this content-coverage addition. |
| CID, CSS/srcset markers and Content-Location | Existing same-message simple-CID candidate observations and original MIME/header evidence remain. | No Content-Location/base/relative, CSS/srcset CID or browser resource resolution. Generic equality is not resource selection. |
| Previously sealed cases | Existing artifacts remain readable and are not rewritten. | Missing new coverage fields mean unrecorded historical coverage, not newly inferred success, failure or content support. |

**G01 disposition:** keep child-document extraction unavailable for the current
candidate. Preserve originals, explicitly expose the unavailable content scopes,
and advertise metadata/ZIP-directory support only. A future nonexecuting child
document inventory requires a demonstrated investigative need, independent
part/message provenance, bounded observations/omissions and its own acceptance.

**G02 disposition:** retain the existing limited CID observation contract and
keep resource resolution unavailable. This family makes that limitation explicit
in attachment content coverage and verifies the existing non-resolution in the
combined worker flow. It does not implement a MIME resource resolver. G01/G02
now have a concrete current support decision; this does not close every S04/S06
helper, format combination, platform or independent-corpus acceptance gate.

## New output contract

`attachments.json` remains an ordered list with its existing fields. Each new
record adds `content_analysis` schema 1, status `not_evaluated`, scope
`attachment_payload_content`, a reason and six named unavailable scopes:
`document_text`, `url_extraction`, `resource_resolution`,
`embedded_message_body`, `archive_member_content` and `decryption`.
This describes the content of the attachment payload, not outer MIME header
inventory or the independent body URL pipeline. It does not infer format or
encryption from a filename, MIME declaration, entropy or missing marker.
The worker supplies `evidence_dir` when scanning; direct `scan_attachments`
callers that omit it receive metadata without writing payload files.

The `attachment_metadata` stage adds schema 1, its metadata-only scope and the
same content coverage, with explicit MIME/macro/malware unavailability. Existing
`status` and `count` retain their meanings: a completed scan lists the selected
payload metadata, and supported archive/transfer/context errors or limits can
make it partial. Zero selected attachments is a completed empty metadata scan,
not proof that every original byte has been semantically analyzed. An actual
scanner/publication failure stays `failed`, with its reason; report rendering
does not replace an unknown count with zero.

The technical report adds **Attachment extraction coverage**, a literal JSON
view of the actual stage plus each listed attachment's part ID, full SHA-256,
recorded content coverage and selected archive coverage fields. It preserves
status/reason, known entry/inventoried/omitted counts, limited-name count,
issues, limits and the macro-marker scope. Unavailable reader counts remain
absent. It does not duplicate the potentially 1,000 member rows or member-name
arrays; the existing literal five-column metadata table remains available.
The full member inventory and exact payload paths stay in `attachments.json`.
The displayed SHA-256 is the attachment payload hash; for embedded messages it
can cover a derived serialization. `byte_source` and separate original-wire
hash/offset/path provenance remain in `attachments.json`, with `input.eml`
authoritative; this report view does not relabel that hash as original wire.
The shared JSON-fence renderer prevents source text becoming active Markdown.

Case-detail API and sealed CLI/HTTP ZIP exports retain the same new metadata,
coverage and report bytes. URL source derivation remains v6; original payloads,
outer URLs, numeric score rules and historical cases are not rewritten. No new
runtime dependency or format detector is introduced.

## Bounds and verification scope

Existing MIME limits apply: 25 MiB input, 500 parser nodes, depth 30, 20 MiB
decoded payloads and 2 MiB analyzed body text payloads. Attachment document
content is not parsed to evade body limits. ZIP defaults retain at most 1,000
member rows, 4,096 UTF-8 bytes per name view, 262,144 captured name-view bytes
and a 100 MiB declared expansion threshold. Central-directory parsing happens
before retained-row/name caps, under the existing worker memory/deadline limits;
no new custom bounded archive parser is claimed.

The new regression family checks real payload/hash preservation, independent
declared-type versus content support, unavailable embedded/inline analysis,
metadata-versus-content status, unknown reader counts and bounded/literal report
publication. A member-open guard rejects accidental member reads while the
actual ZIP parser inventories its directory; it does not substitute results.
The new real integration uses eight CLI cases and six owned-loopback HTTP
workers, with original bytes, stopped owners, seals, independent MIME payload
reconstruction, source exclusion, CID/Content-Location boundaries and
JSON/report/API/ZIP comparisons. Inert format-shaped fixtures do not certify
valid PDF/Office/RAR/7z/gzip parsing, malware detection or investigative accuracy.

All analysis on the development host uses `--no-egress`. No sample URL/domain
is visited/resolved, no attachment is executed, no archive member is extracted
and no Docker is started. Owned HTTP loopback is allowed for the integration;
application no-egress is not OS isolation. The private 20-original pilot has no
attachments and cannot establish attachment coverage or detection accuracy.

## Final serial validation

Windows, 23 October 2026. All actual analyses use the supervised engine; no
parser or analysis result is substituted. Validators stop before final document
edits. The same constructed fixtures repeated on another runtime are not new
independent accuracy samples.

| Check | Actual result |
| --- | --- |
| Full Python 3.13.5 / BeautifulSoup 4.13.4 suite | 1,000 tests: 986 passed, 14 expected Windows exclusions; seven new contract methods. |
| Selected capability/archive/MIME/embedded/report contracts on actual Python 3.13.15 / BeautifulSoup 4.15.0 | 65 passed. |
| New capability integration on each real runtime | Eight full CLI cases / six owned-loopback HTTP workers per runtime. |
| Existing ZIP directory inventory integration | 22 CLI cases / twelve HTTP workers. |
| Existing embedded-wire integration | Twelve CLI cases / five HTTP workers. |
| Existing literal report integration | Three CLI cases / one HTTP worker; existing five-column table and literal evidence remain valid. |
| Existing URL source inventory integration | Nine CLI cases / five HTTP workers; existing v6 and exact 5,000/4,096/904 link accounting preserved. |
| Exact-original baseline replay | Eight further CLI cases; all 24 prior payload records match after excluding only the newly added content coverage. MIME/auth/URL/deobfuscation JSON and numeric scores match; old stage fields retain their values. |
| Real wheel | Python requirement, entry points and all 95 package Python sources match. This is a build comparison, not a new clean dependency installation. |

The matrix therefore includes 70 completed CLI cases and 35 loopback HTTP
workers, including repeated fixtures across runtimes and the exact replay.
Only two existing package sources change; 93 remain unchanged. All **284 tracked
Python/workflow hashes** stay frozen throughout verification. No historical case
is migrated, reinterpreted or resealed; baseline case bytes/hashes/seals are
checked unchanged after the replay comparison.

The first private replay verifier stopped because it compared the domain-age
`reference_time` as an invariant, although each actual run records its own UTC
reference time. The diagnostic and failed verifier log are retained. The corrected
private verifier checks the already completed replay cases, validates the later
UTC reference time separately and compares all remaining score/coverage values
after selecting the intended new attachment fields. No analysis, product/test/
workflow source or budget was changed to obtain that comparison; the exact
replay was not run a second time.

To reproduce the new family from a trusted checkout with required dependencies:

```powershell
python -B -X utf8 -m unittest discover -s tests -p 'test_attachment_capabilities.py' -v
python -B -X utf8 tests/integration_attachment_capabilities_real.py
```

Private original fixtures, cases, hashes and raw logs remain outside Git. Fresh
exact-head Copilot review and CI remain integration gates; this family does not
certify all extraction helpers, platforms, corpus accuracy, egress or UI.
