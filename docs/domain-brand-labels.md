# Domain label and brand spelling comparisons

The brand heuristic compared only the leftmost From domain label. `paypa1.com`
added 0.20, but `mail.paypa1.com` lost that signal because PAW compared `mail`.
PAW now compares both the normalized leftmost label and the PSL registrable label.
The recognized brand seeds and edit-similarity threshold are unchanged.

## Evidence and numeric contract

`report/score.json.sender_domain_observations.domain_brand_comparison` and
`analysis_coverage.json.stages.domain_brand_comparison` share an observation with
`brand_schema_version=1`, `verified=false`, `ownership_status=not_evaluated`:

- `normalized_domain`, `registrable_domain`, `private_suffix`;
- `comparisons`: role, label, nearest brand seed, unrounded similarity and whether
  the existing `0.7 <= similarity < 1.0` lookalike rule matched;
- `max_similarity`: maximum of the available label comparisons;
- `exact_leftmost_under_other_public_domain`: the existing exact-brand subdomain
  condition, or null when its public registrable domain is unavailable;
- `contribution`: at most 0.20 for this domain-label rule, even if both labels match.

The existing exact-leftmost rule still uses the ICANN-section registrable label:
`paypal.attacker.com` and `google.github.io` retain their prior contribution.
Registrable labels include private namespaces, so `mail.paypa1.github.io` compares
the tenant label `paypa1` rather than `github`. Suffix labels such as `co`/`uk`
are not brand candidates. The source is the bundled `tldextract` PSL snapshot,
with package version recorded, HTTP list fetching disabled and disk cache disabled.

For an unambiguous From domain, `status=observed_unverified` means both roles were
available; it is not verified ownership or a phishing verdict. Unknown suffixes
retain only the existing leftmost comparison, with `status=partial`, unavailable
registrable metadata and partial coverage. No registrable label is guessed.

Duplicate/grouped/defective From identities, partial parser identity, disagreement
with the supplied domain or invalid normalized domains leave the comparison
`not_evaluated`, with no label candidates, `max_similarity=null` and zero points.
Original occurrence/defect metadata is respected when scoring persisted JSON.
Legacy direct callers may supply only a domain hint; the spelling observation then
records `source=supplied_domain` rather than claiming original From evidence.
Presence of From fields or parser occurrence/identity metadata retains
`source=message_headers`, including missing/empty From observations. Unavailable
identity remains unevaluated; provenance does not assert a usable mailbox.
An explicit null From or occurrence/identity metadata without an actual From value
cannot promote a supplied domain hint into message evidence. The shared From gate
also prevents Reply-To comparison or Unicode observation from using that hint.
The legacy fallback is reserved for callers without any From metadata.

The legacy `bk_score` is now the rounded maximum of these label similarities and
is null when the domain comparison cannot be evaluated. It is a spelling metric,
not a calibrated phishing probability. A maximum of 1 does not exempt a separate
leftmost lookalike or the existing exact-subdomain rule: the comparisons explain
each condition independently.

## Scope and limits

Normalization uses PAW's existing IDNA 2003 codec and DNS label/domain length
limits. Case and a root dot in direct domain hints are normalized; byte-parsed
mailbox defects still block evidence. Internationalized spellings are compared
in their normalized ASCII form. Unicode script/confusable analysis remains
unevaluated; this is not homograph detection or an official brand-domain allowlist.

Only the leftmost and recognized registrable labels are compared. Intermediate
subdomain labels are not exhaustively scanned. Unknown suffixes can therefore
still hide a similarity behind a service label; partial coverage exposes this.
Exact spelling such as `paypal.com` does not prove brand ownership or safety.

Display-name, Reply-To, TLD, domain-age, authentication, dynamic contributions and
attribution thresholds are unchanged. The 0.20 cap applies to this domain-label
rule only; separately existing display-name/Reply-To contributions remain separate.
TLD and general reputation/ownership heuristics still require their own audit.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_domain_brand_contracts.py' -v
python tests/integration_domain_brand_real.py
```

Seventeen unit contracts reproduce the hidden registrable-label signal and check
root/service equivalence, retained first-label rules, one contribution, private
tenants, unknown suffixes, authoritative From gates, JSON defects, normalization,
unrounded thresholds and no egress attempts. Twenty-two constructed EMLs run
through the actual supervised full CLI with `--no-egress`, checking original
bytes/seals, contributions and persisted-JSON/coverage parity. These are regression
contracts, not phishing ground truth or calibrated detection accuracy.

The protected pilot replay completed all 20 original EMLs with valid bytes/seals
and matching source hashes. Scores, decisions, selected IPs and 180 other evidence
JSONs were unchanged from merged main. Nine legacy similarity values changed:
six unavailable identities now have null metrics, and three available comparisons
have a different maximum. Fourteen domain comparisons were observed/unverified
and six were unevaluated. All decisions remain Inconclusive. No pilot case triggers
a positive domain-brand contribution; this replay checks regressions and integrity,
not the new lookalike rule's independent accuracy.

Suffix semantics and offline configuration: [tldextract documentation](https://github.com/john-kurkowski/tldextract#understanding-domain-parsing).
