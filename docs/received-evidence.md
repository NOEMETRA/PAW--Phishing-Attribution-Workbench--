# Received evidence schema v2

The old parser scanned an entire Received field for IPv4 before IPv6 and selected
the first result. A receiver address or queue ID could replace the sender's IPv6
claim. Multiple distinct sender addresses, malformed comments and scoped/network
tokens could also yield an arbitrary or truncated selection. The original
regression set fails before correction. Constructed inputs establish parser
contracts, not phishing accuracy.

## Field scope, bounds and source preservation

`received_path.json` preserves complete parsed header strings, original
zero-based header indices and positional chain order, plus schema version 2.
No sorting by untrusted timestamps is performed. This is a bounded lexical
parser for supported SMTP From/By clauses, not full RFC validation. Clause
keywords and the timestamp delimiter are located outside comments, quoted
strings and literals; nested/escaped comments are handled. A field longer than
65,536 Unicode code points remains preserved but is not parsed for candidates:
partial coverage and the length limit are explicit.

The inventory retains recognized complete IPv4/IPv6 candidates from every
clause, with clause scope, source text, half-open offsets into the preserved
header string and `verified: false`. Offsets are Unicode code points, not MIME
byte offsets. Original MIME bytes remain in `input.eml` unchanged.
Whole bracketed and mapped IPv6 literals are retained; malformed brackets,
hostname suffixes, CIDR tokens and interface-scoped addresses are not silently
reduced to a different address. Those formats are outside the selected-IP scope;
their original text remains preserved.

The selected `ip` requires one unique recognized address in the supported From
clause, with one ordered From/By pair and supported host tokens. Identical
repeated candidates remain in the inventory without inventing ambiguity;
distinct candidates leave selection unsupported and parsing partial. Addresses
in By, ID, For or other text remain candidates without becoming the sender IP.
No selection establishes the actual socket peer, the authenticity of a Received
header or an actor's infrastructure. Origin selection links its header index,
IP observation and provider-role hypothesis, all explicitly unverified.

[RFC 5321 trace information](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.4)
distinguishes sender and receiver information and permits address literals.
Syntax observations and address candidates are kept separate from authentication
and evidence of malicious activity.

## Address categories and receiver boundary

Address observations distinguish RFC 1918 private addresses, IPv6 ULA, loopback,
link-local, shared address space, documentation, unspecified, multicast, public
unicast candidates and other special addresses. Mapped IPv6 is preserved as IPv6
and classified using the embedded IPv4 address. The documentation prefixes include
[RFC 9637's 3fff::/20](https://www.rfc-editor.org/rfc/rfc9637.html), independently
of older Python registry snapshots. The classification's `is_global` means the
public-unicast category; `stdlib_is_global` separately preserves the runtime
library observation. This is not a live routing or reachability check.
[Python's is_private](https://docs.python.org/3.13/library/ipaddress.html)
does not mean only RFC 1918 space; conflating it with malicious private routing
was unsupported.

Provider hostname suffixes remain compatibility role hypotheses with explicit
provenance and `verified: false`. They cannot establish the recipient's actual
trust boundary. `received_anomalies.json.receiver_boundary` is unevaluated and
`private_ip_before_boundary` is null. Private, loopback and link-local address
claims remain visible as descriptive observations. Single-label or literal By
values can be non-FQDN without proving malicious routing or invalid message
content; hostname kind and the compatibility syntax count remain descriptive.

The automatic pipeline therefore gives zero to
`received_private_ip_before_boundary` and `received_invalid_fqdn`, and does not
add an origin-hop FQDN penalty through header diagnostics. The component names
remain in the ledger with descriptive source explanations. Other sender-domain,
authentication and profile contributions retain their existing rules. The
existing claimed non-monotonic timestamp contribution is unchanged and remains
an unverified, uncalibrated heuristic needing separate validation. Missing
timestamps/timezones are explicit parsing limitations; legacy zero skew values
do not prove simultaneous delivery. Standalone legacy caller diagnostics and
HELO/PTR comparison also need separate validation.

## Verification scope

Fifteen contracts cover field provenance, IPv4/IPv6 precedence, complete mapped
literals, comments, multiple IPs, missing/duplicate/unsupported clauses, limits,
address categories, non-truncation and offline operation. Twelve real supervised
`full --no-egress` CLI fixtures verify bytes/seals, selected origin provenance,
candidate spans, explicit boundary uncertainty and zero category/syntax penalties.
The selected strict profile's 0.05 modifier is kept separate from observed risk.

On Windows/Python 3.13, the combined contract suite passes 241 tests with five
POSIX-specific skips (246 total); all twelve supervised CLI fixtures pass.
Replaying the protected twenty-original corpus against the preceding merged
version completes twenty cases in 20.235 seconds, with 131.781 MiB peak sampled
process-tree RSS (50 ms sampling). Original bytes and all seals verify; the
no-egress guard reports no attempted blocked operations. Source-file hashes
match the tested implementation. These are offline workload measurements, not
a speedup claim or a reproduction of the historical four-hour online run.

Ten numeric scores change exactly by removal of the prior private-IP/boundary
and By-host syntax contributions. Selected hop IPs and origin IPs do not change
on this corpus. All twenty decisions remain `Inconclusive`. Five cases now
explicitly report partial Received parsing. The inventory contains 93 selected
address claims (75 public, four RFC 1918, thirteen loopback and one link-local),
three unavailable and five unsupported selections across 101 Received fields.
Headers, authentication, domain, URL, MIME and deobfuscation evidence artifacts
are unchanged; this comparison does not assert parity of every derived artifact.
The private originals, filenames and case-level comparison stay outside Git.

Independent sender authenticity, binary classifier accuracy, speedup and the
historical four-hour online analysis remain unestablished. Remaining timestamp,
relay and legacy diagnostics, domain/brand/non-ASCII heuristics, clean installation
and an independent holdout remain outstanding. UI and the Linux detonation lab
are deferred. The no-egress policy is an application guard, not OS isolation.
