# PAW development and review

Analyze email samples with `--no-egress` on the development host. Do not visit
sample URLs, resolve sample domains, execute attachments, or start Docker as part
of a review. Constructed messages are regression fixtures, not ground truth for
classifier accuracy. Integration tests using an explicitly local loopback server
are allowed; do not substitute a live external target.

## Code Review Rules

- Check that no-egress reaches every supported CLI/API worker and blocks DNS,
  sockets and subprocess escape paths. The Python policy is an application guard,
  not OS isolation; unavailable enrichment or detonation must remain explicit.
- Keep sender/receiver header claims separate from independently verified
  authentication. Missing or unavailable checks must not become malicious verdicts,
  verified passes, fabricated attribution, or unsupported takedown statements.
- Check process-tree termination before sealing interrupted cases, original MIME
  preservation, complete evidence inventories and partial batch accounting. A
  successful job or matching seal establishes execution/integrity, not attribution
  accuracy or authenticity of the email's claims.

The next development priority is engine correctness and corpus validation. UI
development and the separate Linux detonation lab are deferred. See
`docs/offline-validation.md` for the measured scope and unresolved limitations.
