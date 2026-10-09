# Nullable registration-age calculations

`nrd_days` previously clamped a future registration timestamp to zero, adding the
existing 0.35 recent-domain contribution. The reputation helper also interpreted
negative intervals as very new domains. Both paths now use the same nullable
calculation: a timestamp after the reference time has no usable age.

## Temporal observation

`observe_domain_age(created_iso, reference_time=None)` returns `age_schema_version=1`:

- `created`, `created_utc`: supplied string and normalized timezone-aware instant;
- `reference_time`: the UTC calculation instant, saved for reproduction;
- `age_days`: elapsed whole days, or null when unavailable/invalid;
- `status`, `reason_code`, `reason`: observed/unverified, unavailable or invalid;
- `verified=false`: the calculation does not verify the registration source.

The default reference is the current UTC execution time. A caller may provide a
timezone-aware datetime or ISO string; an invalid/naive explicit reference is
rejected rather than replaced by the current time. The stored reference reproduces
the observation. PAW uses Python's ISO datetime parser; this is not a strict RFC
3339 input validator or a registry-response conformance check.

Missing timestamps are `unavailable/timestamp_unavailable`. Malformed/non-string
dates, missing timezone and future dates have explicit invalid reasons. Timezones
are not guessed. Future comparison occurs before flooring to whole days, including
subsecond future values. Equal instants and valid ages under 24 hours remain zero;
the original 7/30-day score thresholds and weights are preserved for valid ages.
`nrd_days` remains a nullable compatibility adapter to this calculation.

## Actual analysis output

`domains.json.from_domain.domain_age` and the `domain_age` stage in both score
coverage and `analysis_coverage.json` share the temporal observation, sourced to
`domains.json.from_domain.created`. `from_domain.nrd_days` is explicitly null when
the calculation is unavailable, including when no From domain exists. The normal
pipeline therefore stores unknown age as SQL NULL rather than a missing-key age
zero. Unavailable/invalid calculations are listed in coverage's `not_evaluated`.

Original reported registration metadata is preserved. The observation establishes
only an interval from a supplied timestamp; it does not verify registry provenance,
registrable-domain binding, current ownership, authenticity or maliciousness.
An observed age is not a calibrated reputation measure. The reputation helper
retains its other keywords/weights and applies age points only when the shared
calculation is usable.

Under `--no-egress`, RDAP remains skipped and no registration date is invented.
Actual offline cases report unavailable age, zero age contribution and null
indexed age. This change does not enable registry requests or alter network policy.
RDAP response parsing, redirects, subdomain lookup/binding, other reputation rules,
and arbitrary numeric `nrd_days` supplied directly to legacy scorers/index callers
remain separate validation work. UI and the Linux analysis lab remain deferred.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_domain_age_contracts.py' -v
python tests/integration_domain_age_real.py
```

Eleven local calculation contracts reproduce future-age risk, then check future
subseconds, timezone-equivalent instants, valid threshold boundaries, missing,
naive/malformed dates, invalid references and stored-reference reproduction. These
call the real calculation/scorer without mocking registry responses or the clock.
Seven constructed EMLs pass through the actual supervised offline full CLI,
checking unavailable age in domains/score/coverage/index, original bytes and seals.
Future registration values are exercised in the component contracts; the offline
CLI has no live/local registry-date input, so these CLI cases do not exercise a
future RDAP response. Constructed inputs are regression contracts, not phishing
ground truth or simulated analysis results.

Private original replay and source hashes are checked separately; age coverage
metadata can change without changing scores or establishing detection accuracy.
