# Normalized TLD-list observations

The legacy rule added 0.10 for `example.click`, including when the supplied From
identity was missing, ambiguous or defective. It also lost the contribution for
equivalent uppercase domains and root-dot domain hints. The rule now uses the
existing normalized-domain/From availability gate and exposes its own observation.

## Evidence contract

`report/score.json.sender_domain_observations.tld_comparison` and
`analysis_coverage.json.stages.tld_comparison` share `tld_schema_version=1`:

- `source`: `message_headers` for From/occurrence/identity metadata, including
  incomplete metadata; `supplied_domain` for headerless legacy domain hints;
- `normalized_domain`, `tld`: the final label of a validated dotted domain;
- `listed`, `result`: membership in the recorded legacy static list;
- `listed_tlds`, `list_source`, `list_version`: the rule snapshot, not a live feed;
- `contribution`: the existing 0.10 if listed, otherwise zero;
- `verified=false`, `reputation_status=not_evaluated`.

`observed_unverified` means the spelling comparison was available. A listed suffix
does not verify maliciousness, and `not_listed` does not establish safety. The
scope is `normalized_final_domain_label_static_list`: it does not query public
suffix membership, registry status, reputation or domain ownership. A syntactically
valid unknown suffix can therefore be observed as an unlisted final label without
claiming that it is a delegated public TLD.

Missing, duplicate, grouped, defective or incomplete From metadata, disagreement
with the domain hint, invalid domains and single-label inputs are `not_evaluated`:
`tld`, `listed` and `result` remain null, with zero contribution. Coverage includes
`tld_comparison` when unavailable. Original parser defects/counts/identity are
respected during scoring of persisted JSON; a clean rendered field cannot erase
recorded defects. An absent/null actual From with explicit metadata cannot promote
a supplied domain into message evidence. Legacy headerless hints remain supported
with their own source.

Normalization retains PAW's IDNA 2003 codec and DNS label/domain size checks.
`EXAMPLE.CLICK` and `example.click.` domain hints agree with `example.click`, but a
root dot that the original mailbox parser reports as defective remains gated out.
Only the final label is compared: `click.example.com` is a `.com` observation.

## Scope and limits

The list remains `.click`, `.icu`, `.cfd`, `.rest`, `.tk`, `.gq`, `.ml`, `.ga`, `.cf`,
and the 0.10 weight is unchanged. Neither is calibrated or updated by this change.
This comparison performs no network request. Domain age/RDAP, brand/display-name,
Reply-To, Unicode, authentication, dynamic contributions and thresholds are
unchanged. Future registration dates currently becoming age zero require a
separate domain-age correction. UI and the Linux detonation lab remain deferred.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_tld_contracts.py' -v
python tests/integration_tld_real.py
```

Twelve unit contracts check normalized spelling, identity gates, original/JSON
defects, static list and weight preservation, unknown/single-label inputs, hint
provenance, separate numeric contributions and no egress attempts. Twenty-four
constructed EMLs pass through the actual supervised `full --no-egress` CLI with
byte/seal, score/coverage, provenance and JSON parity checks. These are regression
contracts, not independently classified phishing samples or simulated outputs.

The protected pilot replay completed all 20 original EMLs with valid original
bytes/seals and matching source hashes. Archived merged-main and current scorers
were recomputed on the originals: numeric scores, decisions, selected IPs, other
scoring metadata and 180 other evidence JSONs are unchanged. Fourteen TLD
observations are observed/unverified and six are unevaluated. No pilot message
adds TLD points; all decisions remain Inconclusive. This checks regressions and
integrity, without establishing detection accuracy, speedup or the historical
four-hour online runtime. Private originals and per-case results remain outside Git.
