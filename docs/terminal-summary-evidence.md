# Terminal summary evidence boundary

The final CLI/worker summary uses the same `authentication_report(auth)` text as
`report/executive.md`. Reported SPF/DKIM/DMARC/ARC claims, per-check verification
status and unavailable policy lookup remain separate. Actual DKIM checks against
supplied local keys are displayed with their explicitly unverified key
provenance; a cryptographic match is not independently authenticated DNS or
sender identity.

A supplied key snapshot is described as supplied, independently of whether a
signature was present or a check completed. In particular, unsigned messages
retain `not_evaluated` without a statement that a signature was checked. This
shared wording applies to the terminal and executive report.

The previous summary promoted the reported `dmarc=none` result to `DMARC policy:
none` even when actual policy lookup was skipped. Its blanket authentication
statement also omitted completed local-key checks. A supervised full no-egress
batch reproduces both discrepancies: original EML plus six explicit signature
and header fixtures, with actual RSA verification and a reported-none message.
Source JSON was already qualified and seals were valid; the defect was in its
terminal consumer.

The unsupported policy finding is removed. The table identifies header claims
as unverified and the canonical per-check text supplies their details. The
Received panel labels a selected address as an unverified transmission candidate,
or says that a candidate is unavailable. Its source text is literal Rich `Text`,
so provider strings do not become Rich markup or unmatched closing tags.
Source records, selection, authentication algorithms and scores are unchanged
by this presentation repair. New executive reports use the qualified snapshot
wording; previously sealed cases are not rewritten.

`test_terminal_summary_contracts.py` renders actual Rich output from declared
presentation fixtures under the application offline guard, checking unavailable
policy, absent/candidate addresses, literal provider text and unchanged data/files.
These are not independently labeled email analyses. The existing actual DKIM
CLI/HTTP integration adds an original EML and reported-none fixture, verifies
canonical terminal text across all five CLI presets, and retains real signature,
key snapshot, input rejection, original-byte, ownership, seal and HTTP export
checks. The actual API integration also checks its worker log against the saved
authentication record and the candidate state.

This repairs the supported current terminal authentication/candidate view, not
every branch of the legacy formatter or all publishers. Other terminal styling,
optional legacy panels, Markdown/resource/renderer admission and remaining output
consumers still need audit. No claim of calibrated phishing detection, actor
attribution, authenticated key provenance, independent SPF/DMARC/ARC verification
or OS network isolation follows from passing these checks.
