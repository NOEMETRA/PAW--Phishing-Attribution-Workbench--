# Static JavaScript evidence, schema version 2

The standalone JavaScript API and the engine preserve `original_code` and
`final_code` identically. Neither code nor decoded candidates are executed.
Candidates are inspected once from original source, never recursively substituted
or reparsed. There is no executable sandbox in this decoder.

## Reproduced legacy defects

The old decoder rewrote partial regex matches with Python `repr` strings and
repeatedly decoded inserted text. The wrapper ran this iterative decoder
up to five more times and discarded original source/analysis metadata.

Constructed regression strings reproduced lost bytes, invented expression
results and unsupported numeric risk. `atob("//4A")` lost two bytes and generated
11 transformations with direct score 1.0. `String.fromCharCode(65+1,variable2)`
extracted digits from the expression and identifier, produced 21 transformations
and direct score 1.0. Invalid base64 `Y!Q==` was accepted as `a`.
Enabling the legacy flag generated `[EVAL RESULT] hello` without execution;
the default injected `[EVAL BLOCKED]` into source.

Schema v2 removes simulations, arbitrary JavaScript risk weights and iterative
rewrites. A dynamically assigned legacy `safe_execution_enabled` attribute has no
effect. `transformations` and `suspicion_indicators` are empty; iterations are zero.
Numeric complexity is unavailable. The nested zero `suspicion_score` is only a
compatibility contribution, never a negative risk assessment. `risk_detection`
and `execution.status` say `not_evaluated`; `calibrated` is false.

## Candidates and limits

`literal_candidates` carries original character offsets (half-open Python string
indices), exact matched excerpt, kind, status and decoded candidate. Every record
has `candidate_only:true`, `syntax_verified:false` and `network_target:false`.
Matches may be inside comments/strings, refer to shadowed functions or occur in
invalid code. This is bounded lexical scanning, not AST analysis, a complete
string-literal parser or proof of a runtime call. Names are case sensitive.
Within the bounded argument region, parentheses are balanced outside supported
quoted strings so nested unsupported arguments retain their whole call excerpt.
Comments, regex literals and templates are not parsed as JavaScript syntax.

The supported literal subset is conservative:

- `atob` quoted literals support selected unambiguous JS escapes and WHATWG
  forgiving-base64: ASCII whitespace/omitted padding allowed, invalid alphabet
  and padding rejected. All bytes survive as a binary string (Latin-1 mapping),
  with byte size/SHA-256; they are not guessed UTF-8.
  See [HTML atob](https://html.spec.whatwg.org/multipage/webappapis.html#dom-atob)
  and [Infra forgiving-base64](https://infra.spec.whatwg.org/#forgiving-base64-decode).
- `String.fromCharCode` accepts decimal integer lists within the exact JavaScript
  integer range and applies modulo 65536. UTF-16 units remain explicit; valid
  pairs yield text, unpaired surrogates stay units. Expressions, identifiers,
  hex/float/octal forms and large rounded integers are unsupported, never guessed
  from extracted digits.
  See [ECMAScript fromCharCode](https://tc39.es/ecma262/multipage/text-processing.html#sec-string.fromcharcode).
- `decodeURIComponent` literals require valid percent escapes and strict UTF-8.
  Invalid data has no decoded value; `+` remains `+`.
  See [ECMAScript decodeURIComponent](https://tc39.es/ecma262/multipage/global-object.html#sec-decodeuricomponent-encodeduricomponent).
- `eval` with a supported literal records its argument with `not_executed`,
  never an evaluated result. Other forms remain `unsupported_literal`.

Escapes in other contexts are counted only as lexical observations. No global
hex/Unicode substitution changes source. Unsupported forms remain original
excerpts. Candidates can overlap lexically, each with its own original span.

Limits: original-source scan 262144 characters, 32 candidates, 16384 characters
per argument scan region (including closing parenthesis). Reached limits are
explicit `partial` coverage/reasons propagated to the engine. These bound
scanning/candidate expansion; full-source retention still consumes memory.
Full CLI MIME/worker limits apply independently. `completed` means the bounded
lexical scan completed, not complete JavaScript analysis. Newly decoded candidates
never enter URL inventory/network targets; the independent URL pipeline still
examines original MIME representations under its existing contract.
`coverage_scope:literal_candidate_search` specifies the meaning of
`scanned_characters`: the processed search prefix ends at the first omitted call
when the candidate cap is reached. `available_window_characters` is separate;
`unprocessed_source_span` identifies the rest of the original source for that
search (or null when exhausted). Independent escape counts report their own
scanned window and cannot establish candidate-search coverage.

## Aggregate and migration

Direct API and engine return the same schema/provenance. JavaScript contributes
no transformation points. JavaScript-only aggregate risk is null and complexity
`not_evaluated`. Descriptive text/HTML/JavaScript plus URL heuristics is `partial`.
The compatibility `score_scope:nontext_transformations_only` now includes only
URL transformations; coverage and limitation explicitly identify unassessed
JavaScript risk/execution. Human CLI reports these unavailable checks too.
The attribution blend already excludes standalone JavaScript scores; weights
and thresholds are unchanged. Migrate consumers from rewritten `final_code`, old
`analysis` risk lists and transformation counts to candidate/coverage metadata.
Historical sealed cases retain original artifacts.

## Validation scope

Fifteen contracts cover source/API parity, fake eval, recursion, repeated/nested spans,
binary/invalid/forgiving base64, strict URI decoding, expressions/UTF-16 units,
lexical context, limits and unchanged URL heuristics. Initial seven regressions
fail on legacy code. Eight supervised full `--no-egress` CLI MIME fixtures check
persisted source, seals, candidates, zero deobfuscation contribution, explicit
unavailable execution and URL inventory, including a decoded URL that must never
become a network target.

The first Windows serial suite passed 200 tests with five POSIX-only skips (205 total).
The initial seven real JavaScript CLI cases passed, as did eleven URL, five HTML and eight
content full CLI fixtures. A fresh private `full --no-egress` replay completes
20/20 original EMLs with verified seals/original bytes. Text, HTML, URL inventory,
MIME/authentication/remaining evidence and all final scores/verdicts are identical
to the prior HTML phase; JavaScript risk/execution coverage is now explicit.
All 20 remain Inconclusive. The run took 18.353 seconds with 112.78 MiB peak
sampled process-tree RSS (50 ms sampling). Source-file hashes match the run.

The GitHub review reproduced two provenance defects: candidate-limit scanning
reported the whole window, and nested parentheses truncated unsupported calls.
New regressions fail before the correction; processed prefix/unprocessed range
and quote-aware bounded parenthesis depth now preserve those boundaries.
The corrected Windows suite passes 203 tests with five POSIX skips (208 total);
eight real JavaScript CLI cases additionally verify both reviewed paths.
A fresh 20-original replay again preserves all evidence, final score artifacts
and verdicts, with matching source hashes and valid seals (20.569 seconds,
127.12 MiB sampled process-tree RSS). This remains execution/integrity validation.

The private original pilot has no standalone JavaScript artifacts. Fixture results
verify evidence contracts, not phishing accuracy or the historical four-hour
online analysis. Header/domain signals, legacy paths, clean install and independent
holdout remain separate audits. UI and Linux detonation lab are deferred.
