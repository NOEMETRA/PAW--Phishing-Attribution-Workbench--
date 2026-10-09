# Original HTML and descriptive static observations

An offline audit reconciled the residual deobfuscation contributions against
20 original MIME messages and persisted artifacts. URL scores were zero in all
20; all 13 residual contributions came solely from `html_entity_decode`. Each
HTML score was `0.15`, adding `0.00675` under the existing blend. Eight recognized
legitimate messages, two suspected phishing, two commercial-spam candidates and
one uncertain message received it. The audit replayed 305 URL observations and
51 embedded candidates; no standalone JavaScript artifact was present. These
provisional categories are not independently adjudicated labels.

Ordinary entity decoding is HTML syntax processing, not evidence of concealment.
The old path globally unescaped HTML, reparsed the result and repeated decoding
up to four times. Escaped literal form/iframe/script text could become invented
elements. Its attribute decoder rewrote data URIs and dropped invalid UTF-8 bytes.

## HTML schema version 2

Both the exported `HTMLDeobfuscator` and the main engine preserve original decoded
markup in `original_html` and `final_html`. The engine observes it once; derived
strings never feed back into markup parsing. Original EML bytes remain primary
evidence, and historical sealed cases are not rewritten.

Forms, iframes, hidden elements and inline scripts remain best-effort static
observations of original markup. Escaped markup and tags in comments do not
create script observations. The optional BeautifulSoup parser is not a browser
DOM; script marker matching is not JavaScript semantic analysis. Nothing executes
and no target is visited. Parser availability is explicit; an unavailable parser
or candidate-scan limit yields partial coverage. Existing form/iframe/script
marker names describe heuristic observations, not verified phishing.

`html_schema_version: 2`, `risk_detection: not_evaluated` and `calibrated: false`
make the scope explicit. `assessment_status` is `descriptive_only` or `partial`;
`suspicion_score: 0` remains only a compatibility contribution, with empty
transformation/indicator lists. Unsupported direct HTML risk weights and hidden
element numeric ratings are removed. Entity-reference counts are descriptive,
not risk scores or validation of the entities. Zero does not establish safety.

`encoded_attribute_candidates` inspects explicit base64 data URIs in parsed
`src`, `href`, `data`, `value` and `alt` attributes. It records source node/index,
parsed original attribute, declared media type, decoded-byte size/hash and strict
UTF-8 text if available. Invalid base64 and opaque bytes remain explicit, without
lossy text conversion. The original attribute stays unchanged. Candidates are
`candidate_only` and `network_target: false`: they are not markup, verified
destinations, executed payloads or additions to the URL inventory.

Candidate scanning is bounded to 1,024 nodes, 32 candidates and 16,384 encoded
characters per value, with partial results on limits. These are candidate-scan
bounds; structural helpers are not a complete bounded browser parser. Full CLI
supervision and MIME budgets remain in force on this host.

Aggregate coverage distinguishes descriptive text/HTML from URL/standalone-JS
transformation heuristics. With no scored channel, aggregate score is null and
complexity not evaluated; mixed or incomplete observation has partial status.
The human CLI exposes HTML coverage and unassessed risk. Numeric URL/JS heuristics
remain uncalibrated. Standalone JavaScript decoding needs its own audit; final
attribution weights and thresholds are unchanged. No accuracy or speedup claim.

## Measured validation

The final serial Windows suite ran 193 tests: 188 passed and five POSIX-only
tests were skipped. Ten HTML regressions cover routine entities, escaped/comment
markup, actual static nodes, data-URI separation, binary/invalid/oversized input,
candidate/node limits, missing parser, API parity and aggregate coverage. The
initial preservation/coverage regressions fail against the prior implementation.
Five new supervised full `--no-egress` HTML cases verify persisted markup,
candidates, original bytes, compatibility score, coverage and seals. Eight
content and eleven URL integration cases also passed during this phase.

The final private full run completed all 20 original EMLs in 18.665 seconds,
with 113.63 MiB peak sampled process-tree RSS (50 ms sampling). Original bytes,
seals and execution records verified. Original HTML is preserved; text/visual
comparisons, URL inventories, standalone-JS artifacts, remaining headers,
authentication and MIME metadata are unchanged. Raw scores reconcile after
removing `0.00675` in exactly 13 cases. Thirteen displayed scores change; no
verdict changes, and all 20 remain Inconclusive. None now has a deobfuscation
contribution in this pilot. Nineteen messages have descriptive HTML observation;
one has no HTML. No data-URI candidate occurred in the original pilot, so candidate
behavior is checked by constructed regression inputs, not measured accuracy.

The historical four-hour online run remains unreproduced. The subsequent
[standalone JavaScript contract](javascript-evidence.md) removes simulated eval
results and iterative rewriting; it does not evaluate JavaScript risk/execution.
The next audits cover header/domain signals, plus legacy/installation
coverage and representative independent holdout labels. UI and Linux lab deferred.
