# Domain diagram text boundary

`graphs/domain.mmd` presents existing `domains.json.from_domain` fields. The
domain is selected from the message's From observation; its presence does not
establish authenticity or ownership. Registrar/creation/NS/MX values retain
their collector contracts. No-egress skips network collection; empty NS/MX
display placeholders are not evidence of an empty DNS answer.

An actual supervised full no-egress analysis of a message without From completes
with the source domain unavailable, but previously emitted `D[]`, which Mermaid
rejects. A supplied registrar string collected through actual loopback HTTP
also reached the diagram as unquoted graph syntax, including parentheses,
quotes, delimiters and a newline. These are output defects, not classification
or live registry findings.

The diagram now quotes all five existing node labels and uses the same decimal
entity escaping as the attribution diagram. Node IDs, four edges, joined list
order and present values are unchanged. Missing, empty or null domain values
display `Domain unavailable`: an empty quoted node label is also rejected by
the parser, so quoting alone is insufficient. The source mapping is not changed
or populated with this display text. Existing cases are not rewritten.

The shared graph contract tests cover unchanged source mappings, source text
round trips, inert labels, existing topology and unavailable-domain display.
The actual full/CLI-export integration retains its original attribution checks
and adds the domain diagram, absent From and a single-label From domain (which
already parsed in the baseline). The original EML and six constructed contract
fixtures run under no-egress with stopped-owner, source-byte, seal and ZIP-byte
checks. HTTP analysis/ZIP checks both graph files. The loopback RDAP integration
retains the earlier domain-binding/error/no-egress checks and adds one supplied
registrar-text response; it is not a live registry or DNS observation.

This is one bounded S08 publication repair. Parser/topology checks do not prove
renderer/UI safety, global output/resource admission, arbitrary malformed field
types, source authenticity, DNS/RDAP completeness, ownership or attribution.
Other reports and consumers remain open audits; egress isolation and UI work
remain later stages.
