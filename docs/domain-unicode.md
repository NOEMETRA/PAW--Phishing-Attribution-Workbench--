# From domain Unicode observations

PAW previously called any non-ASCII spelling `mixed_flag=true` and added 0.20
to `sender_domain_heuristics`. A Latin accented domain and a Cyrillic domain
received the same penalty; their ASCII IDNA representations received none.
Non-ASCII presence does not implement Unicode mixed-script detection.

## Current contract

`report/score.json.sender_domain_observations.unicode_domain` and
`analysis_coverage.json.stages.unicode_domain` contain the same observation:

- `unicode_schema_version=1`, `source=message_headers`, `verified=false`;
- the normalized ASCII domain and its decoded Unicode spelling, if available;
- `decoded_non_ascii=true/false` describes the decoded spelling only;
- `mixed_script=null`, `script_analysis_status=not_evaluated`, and
  `homograph_analysis_status=not_evaluated`;
- `contribution=0.0`: this observation adds no automatic risk points.

`status=observed_unverified` means spelling was decoded, `unavailable` means an
unambiguous normalized From domain is absent, and `partial` means the normalized
ASCII spelling cannot be decoded with the configured codec. Unknown observations
keep `unicode_domain` and `decoded_non_ascii` null. Duplicate/grouped/defective
From fields, parser partial identity and disagreement with the supplied domain
block observation, including when scoring persisted JSON.

The normalizer is PAW's existing `normalize_domain` and Python's standard-library
IDNA codec (IDNA 2003), with the existing DNS label and domain length bounds. This
change does not introduce IDNA 2008/UTS #46 validation, or replace the normalizer.
Equivalent supported Unicode/ACE spellings and case produce the same observation.
The normalizer also accepts a root dot for direct domain callers; a From mailbox
with that spelling remains unavailable if the mail parser reports defects.
Raw UTF-8 domains in byte-parsed From headers currently produce parser defects
and likewise remain unavailable. Valid ASCII ACE mailboxes can still expose their
decoded Unicode spelling; this change does not add SMTPUTF8 parser support.
The input MIME and original headers remain unchanged.

The legacy `mixed_flag` and `is_mixed_script()` adapter now return null/None.
Consumers must treat this as an unperformed check. The score coverage explicitly
lists `domain_script_analysis` and `domain_homograph_analysis` as unevaluated.
Ordinary ASCII, international names and potential homographs are not classified
as safe, malicious, authenticated or official from spelling alone.

Other existing brand, TLD, domain age, Reply-To, authentication, profile and
dynamic contributions and decision thresholds are unchanged. Brand/subdomain
and TLD heuristics still require their own audit; this PR does not validate them.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_domain_unicode_contracts.py' -v
python tests/integration_domain_unicode_real.py
```

Eight unit contracts reproduce the old penalty and cover Unicode/ACE parity,
ASCII observations, invalid ACE, missing/ambiguous/defective From, and retained
other contributions. Fourteen constructed EMLs run through the actual supervised
full CLI with `--no-egress`; checks include original bytes, evidence seals,
coverage and persisted-JSON scoring parity. These are regression contracts, not
independent phishing labels or a detection accuracy benchmark.

The protected pilot replay completed all 20 original EMLs with `--no-egress` and
valid original bytes/seals. Fourteen From domains supplied observations and six
remained unavailable under the existing identity gate. All numeric scores,
decisions, selected origin IPs and 180 non-Unicode evidence JSONs were unchanged
from the preceding timing audit. All 20 decisions remain Inconclusive. This pilot
contains no decoded international domains and does not validate IDN detection
accuracy, classifier accuracy or the historical four-hour online runtime.

References: [Unicode UTS #39 mixed-script detection](https://www.unicode.org/reports/tr39/#Mixed_Script_Detection)
and [Python 3.13 IDNA codec](https://docs.python.org/3.13/library/codecs.html#encodings.idna).
