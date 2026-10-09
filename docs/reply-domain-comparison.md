# Reply-To domain observations

The previous regex picked the first angle-bracket address, mistook comments for
domain text and compared raw spelling. It could contribute 0.15 with no From
domain, a duplicated Reply-To, a mailbox list/group or original parsing defects.
Those constructed regressions fail before correction; they are not phishing
accuracy labels.

## Supported parsing and comparison

`headers.json` preserves `reply_to_header_count` and `reply_to_domain`: status,
normalized domain, reason, scope, source `message_headers` and verification
`not_evaluated`. Domain selection requires one defect-free ungrouped mailbox,
with a username and a domain accepted by the existing offline IDNA normalizer.
Comments and quoted local parts remain structured mailbox content, not domain
text. Named groups, lists and duplicate fields are unsupported by this narrow
scope. Missing fields are unavailable; reported defects are partial. Valid
multi-address/group syntax is not itself a parser defect or numeric risk.

The implementation uses the stdlib's documented
[structured addresses and groups](https://docs.python.org/3/library/email.headerregistry.html).
[RFC 5322 section 3.6.2](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.6.2)
allows an address list in Reply-To. Supporting only one ungrouped mailbox is an
explicit analysis limitation; selecting a list's first member is not a complete
comparison.

The comparison uses normalized lowercase IDNA domains, equality and a label
suffix relationship. Equivalent Unicode/A-label spellings compare alike.
The existing unrelated-domain contribution remains 0.15. This is a structural
heuristic, not organizational-domain ownership or DMARC alignment, and the
remaining brand/TLD/non-ASCII heuristics retain their existing behavior.
Two available unrelated domains do not establish phishing, account compromise
or an actor's identity. Even equal domains do not authenticate the message.

`score.json.sender_domain_observations.reply_to_comparison` and the coverage
stage expose the operands, scope, result and exact contribution with
`verified: false`. Missing/invalid normalized From domains, defective or ambiguous From
identities, or unavailable/unsupported Reply-To domains produce `not_evaluated`,
null result and zero contribution. From's normalized domain is the existing
unverified auth-parser/caller observation; this change does not independently
validate that identity. The From gate requires `from_identity.status == parsed`
when metadata exists and rejects all original From field defects. A supplied
From must also parse as one defect-free ungrouped mailbox whose domain matches
the supplied normalized domain. This deliberately excludes even defects in the
display name: recovery does not prove that a defect is confined to that part.
For example, `a@exa mple.invalid` can render as `a@exa`; that recovered fragment
must not acquire a mismatch contribution. Original defects and counts remain
effective after JSON reload. Legacy string callers use the same structured
parser; historical sealed results are not rewritten.

Header-parsing coverage also retains Reply-To metadata and becomes partial for
unsupported/defective Reply-To. An absent optional Reply-To does not make header
parsing partial, while its comparison remains explicitly unevaluated. No missing
field, defect or unsupported format adds numeric risk or authentication failure.

## Verification and remaining audit

Twelve focused contracts cover comments, quoted local parts, group/list ambiguity,
duplicate fields, normalized domain equivalence, unavailable From, original
Reply-To defects, defective From fragments, legacy callers and JSON parity.
Seventeen real supervised `full --no-egress` CLI
fixtures check original bytes, seals, comparison coverage, actual contributions
and persisted scoring. Eight existing mailbox CLI fixtures also pass. The serial
Windows suite passes 226 tests with five POSIX-only skips (231 total).

The final private replay `full-20261009T200626Z` reconciles 20/20 original EMLs,
preserved bytes and valid seals, with matching source hashes. All numeric scores
reconcile: the P1 correction removes only the prior 0.15 Reply-To contribution
in six cases whose original From identity is defective. Decisions remain
unchanged (20 Inconclusive); MIME, URL, authentication, origin, Received and
deobfuscation evidence remain identical. Sixteen Reply-To domains are parsed and
four are unavailable: eight comparisons are same-or-subdomain, two different
and ten unevaluated (six defective From, four missing Reply-To). The run took
24.324 seconds with 136.91 MiB peak sampled process-tree RSS (50 ms), without
accuracy or speedup claims. Two new regression methods fail with six assertions
before this P1 correction, including original objects, persisted metadata and
legacy strings.

The read-only Received audit finds nine non-FQDN `by` tokens across six cases,
all single labels. Across all hops, `is_private` includes four RFC 1918/ULA
addresses, thirteen loopback addresses and one link-local address. These counts
are parsed header claims across hops, not malicious-message counts or validated
IP provenance; the existing before-boundary contribution occurs in five cases.
Received scoring is unchanged in this correction.

The next unresolved Received audit examines FQDN-only penalties, extraction of
IPs from arbitrary header positions, `is_private` categories and the unverified
provider-name boundary. Header syntax or private transport addresses do not
independently establish malicious activity. The domain spelling/brand and
non-ASCII-as-mixed-script heuristics also remain uncalibrated. Independent holdout,
legacy and clean-install validation follow. UI and the Linux detonation lab are
deferred. No accuracy, speedup or historical four-hour online reproduction is
established by these offline checks.
