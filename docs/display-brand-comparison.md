# Display name and registrable domain spelling

The display-name heuristic used only the leftmost From domain label. For example,
`Google <a@accounts.google.com>` added 0.20 because `google` differed from
`accounts`, while the same name at `google.com` added zero. This change removes
that inconsistency for a recognized display brand matching the public registrable
domain label. It does not establish that any domain is officially owned by a brand.

## Narrow comparison contract

`report/score.json.sender_domain_observations.display_brand_comparison` and
`analysis_coverage.json.stages.display_brand_comparison` share one observation.
An unambiguous normalized From domain and a defect-free structured mailbox are
required. Existing occurrence/identity/field-defect metadata remains authoritative
when scoring persisted JSON. Missing, ambiguous, grouped, defective or disagreeing
From domains leave `status=not_evaluated`, `result=null`, `contribution=0`.
An absent/null From value remains unevaluated even for legacy callers supplying
only a domain. A valid bare mailbox has an observed empty display name and can
report `completed/no_brand_match`; missing From input cannot.

The existing display recognition rule (brand substring and normalized display-name
edit similarity >= 0.8) is retained. If no brand matches, `result=no_brand_match`
adds zero. Matching cases record `matched_brand`, `normalized_domain`,
`public_registrable_domain`, `private_suffix`, the local suffix source and package
version. Outcomes are:

- `registrable_label_match`: the recognized brand equals the ICANN-section
  registrable label and the domain is not in a PSL private namespace; zero points.
- `leftmost_label_match`: the previous leftmost comparison already matched;
  its zero display-name contribution is retained.
- `different`: the existing unverified display-name mismatch contributes 0.20.

Public/private suffix lookups use the bundled `tldextract` PSL snapshot with
`cache_dir=None` and `suffix_list_urls=()`. No DNS or remote PSL update is used.
Hosted tenant labels such as `news.google.github.io` and
`news.google.blogspot.com` do not receive the registrable-label exception merely
because the tenant spells a brand. Unrecognized suffixes retain the existing
leftmost comparison, with unavailable registrable-domain metadata.

Every outcome has `verified=false` and `ownership_status=not_evaluated`. The label
exception also applies to spelling such as `google.co.uk`; there is no official
domain allowlist or independent ownership check. A match does not establish
authenticity or safety, and a mismatch is not proof of phishing.

The separate domain-label lookalike/subdomain rule, TLD list, domain age, Reply-To,
authentication, Unicode observations, profile and dynamic scores are unchanged.
In particular, the existing `google.attacker.com` subdomain rule retains its own
0.20 contribution; this change does not double-count that display-name case.
Domain-label lookalikes, unknown suffix behavior and TLD heuristics still require
their own focused audit. Attribution thresholds remain unchanged.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_display_brand_contracts.py' -v
python tests/integration_display_brand_real.py
```

Nine unit contracts reproduce the service-subdomain mismatch and cover retained
other-domain/hosted-namespace risk, From availability, JSON defects, encoded names
and explicit unverified ownership. Fourteen constructed EMLs run through the
actual supervised full CLI with `--no-egress`, checking numeric expectations,
original bytes, seals and persisted-JSON/coverage parity. These fixtures are
regression contracts, not phishing labels or an accuracy benchmark.

The protected pilot replay completed all 20 original EMLs, with valid bytes/seals,
unchanged numeric scores, decisions, origin IPs and 180 other evidence JSONs. The
numeric comparison also recomputed both the merged scorer and the changed scorer
on the same original headers. Fourteen messages had no recognized display brand
and six had unavailable From identity; the pilot therefore does not independently
validate the new matching exception. All decisions remain Inconclusive.

Suffix semantics: [tldextract documentation](https://github.com/john-kurkowski/tldextract#public-vs-private-domains)
and [Public Suffix List](https://publicsuffix.org/list/).
