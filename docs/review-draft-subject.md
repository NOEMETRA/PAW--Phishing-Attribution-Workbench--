# Review-draft subject consistency

`package/subject.txt` uses the same neutral subject as the existing local MIME
review draft: `PAW local review draft - CASE_DIRECTORY_NAME`. It identifies the
case without labeling the email as phishing or presenting header-derived IP,
ASN or domain values as an independently established origin.

The previous helper always prefixed `[Abuse][Phishing]` and `Origin`, even when
the actual report decision was `Inconclusive` and `origin.json` stated
`verified: false`. An actual supervised full analysis of original EML bytes under
no-egress reproduced both that contradiction and disagreement with the already
neutral MIME `Subject`. The source email and case seal remained intact; this was
an output-interpretation error, not an accuracy evaluation.

The correction changes one subject-construction line in `paw/core/trace.py`.
Source headers, candidate origin/ASN/domain observations, structured draft
records, scores, decisions and report contents keep their existing contracts.
The subject identifies a local draft for review, not a report that was sent.
English/Italian draft bodies and the existing MIME subject are unchanged.

Actual English/Italian original-EML full flows in
`integration_legacy_abuse_draft_real.py` compare the helper file with the parsed
MIME subject, retain original bytes and valid seals, and still check legacy
publisher rejection. `integration_api_real.py` checks the same equality through
actual HTTP analysis and ZIP export, including the original EML bytes. The draft
subject is sealed and exported with the case, rather than patched afterward.

This fixes one S08 export-consumer inconsistency. Other reports, diagrams,
subject/field consumers, malformed-source readability, format conformance and
independent classification/attribution validation remain open. No new analysis,
reporting, sending, enrichment or identity capability is introduced.
