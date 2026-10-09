# Mailbox names and header-field parsing coverage

The header/domain audit of 20 sealed original EMLs reconciles all existing score
components. Eight sender-domain contributions come entirely from Reply-To
differences; none comes from spelling or display names. Five cases contain the
private-Received-IP heuristic and six contain the Received FQDN heuristic. These
are unverified observations, not independent authentication or phishing labels.
Their weights/meaning still require separate validation.

## Reproduced parsing defects

The old display-name regex ignored unquoted multiword names, did not decode
RFC 2047 names, truncated escaped quotes and invented a display name from a bare
mailbox's local part. The same `PayPal A <a@example.invalid>` field scored
differently when its display name was surrounded by quotes. Conversely,
`paypal@merchant.invalid` acquired a display-name contribution without having
a display name. On the original pilot, regex names differ from structured names
in 14 cases: six owner-recognized legitimate and eight acquired from Spam.
This is parsing disagreement, not a measured phishing detection error.

Six original From fields also have `UndecodableBytesDefect`, while the existing
header-parsing coverage says `completed`: `msg.defects` omits each field object's
defects. The domain is still normalizable in those cases; a damaged display field
does not establish a malicious domain or verified authentication failure.

## Corrected contract

`extract_display_name` uses the stdlib structured address representation. It
returns the actual display name only for one defect-free mailbox with a username
and domain. Bare addresses yield an empty display name; malformed or ambiguous
lists yield no selected name. Existing parsed objects keep their original defects;
rendering and reparsing cannot silently turn them into defect-free observations.
Direct string callers use the same HeaderRegistry parsing, including encoded words.
See [Python HeaderRegistry](https://docs.python.org/3/library/email.headerregistry.html)
and [RFC 5322 addresses](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4).

This parsing fix retains the existing display-brand heuristic/threshold/weight;
it does not calibrate the heuristic or verify sender identity. Correctly parsed
names remain claims made in the message. Equivalent supported representations
now receive equivalent heuristic treatment; absence of a name adds no invented
display-name observation.

`headers.json` adds `header_field_defects` for defects reported by the stdlib on
the selected top-level From, Reply-To, Return-Path, Date and Subject fields.
Records carry field name, zero-based occurrence index within that field, defect
type/description and `source:message_headers`. The compatibility `header_defects`
list combines existing message defects with those explicitly labelled field
defects. No original header or MIME bytes are rewritten.

The header-parsing stage persists those records as `field_defects` and becomes
`partial` when defects exist. It is parse coverage, not an authentication verdict.
Defects themselves add no risk points and never become independently verified
authentication failures. Recovery/index/report consumers retain original evidence.
This collects reported defects for selected fields; it is not complete RFC
validation, and not every malformed byte/encoded word is reported by the stdlib.
Fields outside that set, ambiguous identity policy and remaining domain/Received
heuristics require further audit. Historical sealed cases remain unchanged.

## Verification scope

Eight contracts cover unquoted/quoted/encoded names, bare mailboxes, ambiguous
and malformed fields, comments/escaped quotes, original undecodable bytes,
occurrence provenance and reported Date/Reply-To defects. Six supervised real
`full --no-egress` MIME fixtures verify persisted coverage, original bytes/seals,
equivalent name scores, no fabricated bare-mailbox name, and no risk points from
a bad Date. Coverage changes are checked separately from numeric score values.

The serial Windows suite passes 211 tests with five POSIX skips (216 total).
All six mailbox CLI fixtures and eight existing content CLI fixtures pass.
A new private `full --no-egress` replay verifies 20/20 originals and case seals,
with matching source hashes. Numeric scores/verdicts remain identical and all
20 are Inconclusive. Header-parsing coverage changes to partial in exactly six
cases, preserving reported From-field defects; other evidence, MIME, URLs and
authentication artifacts are unchanged. Every numeric contribution reconciles.
The run took 20.644 seconds with 129.25 MiB peak sampled process-tree RSS at 50 ms.

The fixtures are not accuracy ground truth. Original-pilot labels remain
provisional; no independent sender authenticity, binary phishing accuracy,
speedup or historical four-hour online reproduction is established. UI and Linux
detonation lab remain deferred.
