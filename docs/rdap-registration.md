# RDAP registration-name binding

The domain collector previously selected the last `registration` event from any
HTTP 200 JSON response without checking its object class or domain name. An entity,
nameserver, unrelated domain or ambiguous registration events could supply the
`created` timestamp used for age and reputation.

The collector now shares a pure `observe_rdap_registration` interpretation with
the real HTTP path. It requires `objectClassName=domain` and a valid ASCII LDH name
equal to the normalized requested domain. DNS case and one terminal root dot are
equivalent; whitespace, malformed names and Unicode in `ldhName` are rejected.
The query uses PAW's existing IDNA normalization; `unicodeName` and links are not
substituted for a missing LDH identity. See the domain object and event structures
in [RFC 9083 sections 5.3 and 4.5](https://datatracker.ietf.org/doc/html/rfc9083).
This is PAW's conservative evidence-selection policy, not a complete RDAP
conformance validator.

Only one top-level `registration` event with a nonempty string date supplies
`created`. Missing events, malformed event arrays and multiple registration events
(including identical duplicates) leave it null. No first/last date is guessed;
nested entity events are not domain registration. Candidate strings and event
indices are retained for ambiguous selections. Validity/timezones/future dates
are subsequently handled by the existing [temporal age observation](domain-age.md).

The online collector stores `rdap_registration` under the domain record:

- schema version 1, status, reason code and `verified=false`;
- normalized requested domain, returned original LDH name, normalized returned
  domain, reported object class and nullable `domain_match`;
- registration event candidates and nullable selected `created`;
- request URL, final response URL and HTTP status for the actual HTTP lookup.

`domain_match=true` describes normalized name equality, even if event selection
fails. It does not establish registry authenticity, domain ownership, trustworthy
registration history or maliciousness. An HTTP success is not a verified registry
result. The legacy registrar field is only read from a matching domain object;
its existing limited `registrar.name` extraction is not a full registrar/entity
parser. Missing/failed HTTP or JSON responses leave an explicit unavailable reason.
NS/MX collection remains separate and unchanged.

The production endpoint remains rdap.org. This change does not rewrite subdomain
queries to a registrable parent, use the PSL for registration-age inheritance,
validate IANA bootstrap/redirect provider authority, restrict existing redirects,
or authenticate response provenance. If a query for `mail.example.com` returns
`example.com`, the timestamp is unavailable for that exact requested name. A later
parent-domain lookup will require a separately scoped observation rather than
silently assigning the parent's age to a host or private-suffix tenant.

Under `--no-egress`, `domain_rdap` still returns the existing skipped/no-egress
record before HTTP/DNS. Offline analysis output and scores are unchanged. The
internal shared HTTP collector also checks the policy before requests. No online
sample/registry requests are needed to run these checks; the Linux lab and UI
remain deferred.

## Validation

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p 'test_rdap_registration.py' -v
python tests/integration_rdap_registration_real.py
python tests/integration_domain_age_real.py
```

Sixteen local object/scorer contracts exercise name/class binding, ASCII/ACE,
parent/subdomain mismatches, missing/malformed/nested/duplicate events, future-age
handling, input preservation, nontext query rejection and early no-egress skip. Supplied objects are
protocol regression fixtures, not genuine registry responses or phishing labels.

Eight HTTP cases call the same collector with an explicitly local loopback server:
matching/mismatching/wrong-class/nameless/ambiguous objects, non-200, invalid JSON
and a local redirect to a mismatching object. HTTP status and final URL are
observed through real requests, and only the matching single event adds the
existing valid-age points. Enabling no-egress adds no server request. The server
supplies protocol fixtures; this is not a simulated full email analysis, live
registry verification, DNS test or proof of online deployment behavior.

Actual offline CLI and private original replay separately check skipped RDAP,
unchanged scoring/coverage, source hashes and byte/seal preservation. They cannot
exercise an online registry response or measure the historical four-hour run.
