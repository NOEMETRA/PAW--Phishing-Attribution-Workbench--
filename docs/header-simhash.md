# Selected-header SimHash and legacy index values

The index formerly called the first 16 hex digits of an MD5 digest `simhash`.
That was an ordinary digest, not a locality-sensitive fingerprint. On a
constructed eight-word example, reordering identical word features changed 32
bits of the old digest. The new word-feature fingerprint is invariant under that
reordering. This is an algorithm contract, not email classification accuracy.

## Current algorithm and scope

New indexed cases use a 64-bit weighted SimHash:

- Input is selected Subject, From and Received header strings, joined with spaces.
  Original MIME and parsed headers remain preserved in the sealed case. The body,
  attachments and independently verified authentication are outside this scope.
- Features are Unicode `\w+` tokens (including underscores), casefolded and weighted
  by occurrence count. There is no Unicode normalization; combining-mark and
  precomposed spellings may differ. Token order and field boundaries are discarded.
- Each feature contributes its frequency as positive/negative votes using the
  first 64 SHA-256 bits. Positive sums set a bit; ties clear it. Hex output is
  zero-padded to 16 digits, including when the actual result is all zeroes.
- `simhash_method` identifies this exact version and the runtime Unicode database
  version. Compare fingerprints only with matching methods and scopes.
- Input over 65,536 characters yields SQL NULL and `unavailable_input_limit`;
  no word features yields NULL and `not_evaluated_no_features`. Neither is a zero
  fingerprint or evidence of dissimilarity. The direct helper rejects oversized
  or non-text input rather than silently truncating it.

The feature/vote construction follows the weighted SimHash description in
[Manku, Jain and Das Sarma, Detecting Near-Duplicates for Web Crawling (WWW 2007)](https://research.google/pubs/detecting-near-duplicates-for-web-crawling/).
Its web-crawl thresholds are not adopted as phishing or header-similarity rules.

## Existing databases and query results

Initialization adds nullable `simhash_method` and `simhash_status` columns under
a SQLite write transaction. Existing row values, timestamps, indicators and
sealed case files are preserved. Historical rows lacking a method are exposed
by both CLI and API queries as `legacy_md5_prefix_64` with status
`legacy_not_similarity_fingerprint`; the original stored digest remains intact.
An API reader can also annotate an old schema without migrating it.

New rows store the genuine fingerprint with status `observed` when features
exist. Query records expose `simhash_scope=selected_subject_from_received_headers`
and `similarity_validation=not_validated`. Consumers must inspect the method and
status; a 16-digit value alone cannot distinguish historical MD5 from SimHash.
There is no automatic legacy backfill or rewrite of sealed cases.

## Measured checks and limitations

Unit contracts check independent SHA-256 token vectors, weighted votes, zero ties,
word ordering/case, Unicode, empty/oversized inputs, offline behavior and real
SQLite migration preserving legacy rows. Integration runs actual supervised
offline full analysis on four constructed header fixtures and one original public
EML, then actual CLI and loopback HTTP queries. It checks version metadata,
header-only scope, original MIME and unchanged sealed files.
It also reconstructs legacy index metadata from those actual parsed headers to
check read-only HTTP behavior on an old schema. That database fixture is distinct
from the actual full analyses and supplies no classifier ground truth.

The fingerprint is descriptive index data, not sealed authentication evidence or
a duplicate verdict. The mutable index is outside individual case seals. No
threshold is calibrated, no near-duplicate search is enabled, no cases are skipped
or merged, and no score contribution is added. Cross-case campaign/actor
correlation remains explicitly unavailable; identical header word bags do not
establish identical messages, shared infrastructure, maliciousness or authorship.
