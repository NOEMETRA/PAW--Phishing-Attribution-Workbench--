# Descriptive Received timing and relay observations

The preceding implementation used zero for an unavailable interval and carried a
timestamp across a missing hop. It could report a non-monotonic adjacent chain
from non-adjacent endpoints. Equal timestamps or repeated IP claims produced a
"suspicious relay chain" flag; intervals longer than one hour produced
"timestamp manipulation". On the protected original corpus, nineteen of twenty
messages had the relay flag. This is a count of unsupported heuristic flags,
not a phishing false-positive-rate measurement.

SMTP includes queueing and retries: [RFC 5321 section 4.5.4.1](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.5.4.1)
permits delayed delivery. Timing alone does not identify its cause. PAW has not
independently authenticated the header chain, verified the servers' clocks or
established the recipient trust boundary.

## Schema and compatibility

`received_path.json` is schema 3. Original parsed strings, source indices, chain
position, IP candidates and date values remain preserved. The compatibility
field `skew_s` now means a signed difference between adjacent aware timestamp
claims, or null when unavailable. The first hop has no predecessor; a missing,
naive, invalid or unknown-timezone date interrupts comparison. A later valid
adjacent pair resumes comparison without bridging the gap. Header order is never
sorted by timestamps. Date parsing remains bounded library parsing, not a
complete RFC calendar/trace validation.

Each hop's `timing_observation` records source positions/header indices, comparison
status/result, signed seconds and `verified: false`. Equal known timestamps yield
zero; unknown timing yields null. `origin.json` and `transmitting_server.json`
link the selected hop's same observation and nullable interval. Consumers that
previously assumed every `skew_s` was numeric must handle null.

`received_anomalies.json.timing_observations` has timing schema 1: adjacent pairs,
timestamp availability, repeated selected-IP claims and comparisons against a
recorded UTC reference from the analysis host's clock. Future claims are visible
even in a single-hop chain. That clock and the source claims remain unverified.
Recomputation can use the recorded reference to avoid silently changing the
observation on a later day. Repetition is descriptive, not evidence of a relay
loop, compromise or shared ownership.

The compatibility `non_monotonic_dates` is true when an available adjacent pair
decreases, false only when all adjacent pairs are available and none decrease,
and null when the whole-chain result cannot be determined. Coverage records
partial timestamp availability separately from comparison availability. The
`received_timing` stage exposes pair counts and unevaluated interpretation.

`suspicious_relay_chain`, `timestamp_manipulation` and `impossible_negative_skew`
are null: PAW cannot establish these interpretations from the claims alone.
Timestamp/relay names are not added to `spoofing_patterns`. Numeric contributions
from timestamp order and the automatic origin-hop interval diagnostic are zero;
observations remain available. Profile modifiers, independent authentication,
other domain components and decision thresholds are unchanged. Direct legacy
caller diagnostics, legacy header-forgery scoring and online HELO/PTR heuristics
are outside this audit; a nullable direct score diagnostic no longer raises.

## Verification

Fourteen contracts cover first-hop availability, missing/invalid/naive dates,
unknown zones, timezone offsets, gap recovery, partial comparisons, decreasing
claims, equal timestamps, long intervals, repeated IPs, future claims, reference
validity and offline operation. The first twelve regressions produced ten failing
assertions and four metadata/API errors before correction. Fourteen supervised
`full --no-egress` CLI cases verify persisted origin, numeric ledger, coverage,
original bytes and seals; the existing twenty-five IP-provenance CLI cases also
pass with schema 3. Constructed samples verify contracts, not classifier accuracy.

Windows/Python 3.13: 266 contracts, 261 passed and five POSIX-specific skips;
all 39 CLI cases above pass. A fresh protected twenty-original replay completes
in 23.727 seconds with 137.480 MiB peak sampled process-tree RSS (50 ms sampling).
Both runs' seals and original bytes verify; source-file hashes match. Twenty-six
unavailable hop deltas (twenty first hops and six unavailable adjacent pairs) are
now null, and three cases have partial timing coverage. Thirty-three equal
timestamp pairs and one case with repeated selected-IP claims remain descriptive.
The nineteen old suspicious-relay flags are now unevaluated interpretations.
IP provenance, date values and origin IPs are unchanged; header/authentication/
domain/URL/MIME/deobfuscation artifacts are identical. All numeric contributions
reconcile and all twenty scores/`Inconclusive` decisions remain unchanged. This
does not assert parity of every derived artifact, measure accuracy/speedup or
reproduce the historical online workload. Private emails stay outside Git.

UI and the separate Linux enrichment/detonation lab remain deferred. The no-egress
policy is an application guard, not OS isolation. Independent authenticity,
classifier accuracy and the historical four-hour online workload remain open.
