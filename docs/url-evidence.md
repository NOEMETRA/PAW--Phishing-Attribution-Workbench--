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

`url_evidence.json` and `headers.json.url_evidence` inventory observed URLs and
recovered textual URLs with provenance. Network targets are deduplicated separately
from evidence records: distinct source strings and transformation paths remain
visible even when they recover the same target, while identical records appear
once. Malformed observations remain evidence
without entering `headers.json.urls`. Ports, missing hosts, controls, ambiguous
backslashes, encoded hostname delimiters and malformed percent escapes in any
component are checked locally. Each `%` must be followed by two hexadecimal
digits; complete octets such as `%FF` are retained without UTF-8 decoding of
resource components. These are
bounded conservative syntax checks, not a full browser URL parser or proof of
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

- 27 URL contract tests exercise resource identity, whole URL recovery, Base64,
  nested JSON tracking, invalid UTF-8, IDN/visual comparisons, user information,
  malformed inputs, colliding provenance, all 256 complete resource percent
  octets, deterministic inventories and bounded decoding. They replace
  the old non-failing harness that expected rewritten destinations.
- Real supervised `full --no-egress` CLI regressions use constructed plain/HTML
  messages, preserve original bytes, verify case inventories, and assert that
  malformed URLs, comparison strings and embedded candidates are not network
  targets. These fixtures are not classifier accuracy ground truth.
- The full Windows contract suite passes: 129 tests, five POSIX-only skips.
  Real CLI/API shared-directory and crash-recovery integration also passes.
- A private pilot of 20 distinct original EMLs contains 300 MIME-extracted URLs.
  Before the change, 50 were altered and appended as additional reported URLs
  across three messages. After the change, all 300 retain their bytes and no
  additional rewritten targets appear; 50 embedded candidates remain available
  separately (28 in decoded JSON tracking containers).
- All 20 real cases complete with verified seals, preserved original bytes and
  explicit no-egress. The run after the review fixes takes 25.58 seconds with a
  peak sampled process-tree RSS of 127.27 MiB, observed every 50 ms;
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
