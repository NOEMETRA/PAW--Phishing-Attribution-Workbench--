# Attribution graph evidence boundary

`graphs/attribution.mmd` is a view of parsed, unverified Received observations,
not a verified sender, original machine or attacker attribution. Its existing
filename and oldest-first header-position order remain unchanged. Dates do not
establish that order. Provider roles are hostname heuristics, not an authenticated
recipient boundary.

Each hop includes its zero-based `received_path.json` header index. If the engine
selected an address candidate, exactly that hop is marked
`UNVERIFIED TRANSMITTING CANDIDATE`. Selection uses the chosen observation, not
the first occurrence of its IP: repeated addresses can have different header
indexes and role observations. When `origin.json` reports an unavailable address,
the graph has no candidate badge, including a parsed hop without a selected IP.
This does not change the selection algorithm, source records, scores or verdicts.

Previously the graph inserted `<<ORIGIN>>` as a second label on the node ID,
reused that decorated ID in the next edge, and could badge the wrong occurrence
of a repeated IP or a hop without an address. Original-EML full analysis and
explicit Received fixtures reproduce these output discrepancies; the case seal
does not establish the truth of their labels. The duplicate-label output is
also rejected by the Mermaid parser.

Node identifiers remain generated identifiers. Labels are quoted, with Mermaid
decimal entities for quotes, entity delimiters, markup delimiters, backticks,
backslashes and nonprintable characters. Header/provider text cannot insert
graph statements through those labels. The underlying JSON and original EML
retain the source observations; a diagram is not a replacement evidence record.
The quoting follows the [Mermaid flowchart entity syntax](https://mermaid.js.org/syntax/flowchart.html#entity-codes-to-escape-characters).

`test_attribution_graph_contracts.py` checks inert source labels, unchanged input
records, single candidate declarations, plain node IDs and missing candidates.
`integration_attribution_graph_real.py` uses actual supervised full no-egress
workers on one original EML and four constructed contract fixtures: repeated IP,
no selected address, no Received fields and an IPv6 receiver literal. It checks
stopped ownership, source bytes, header-index binding, sealed graph membership,
actual CLI ZIP bytes and unchanged seals. Constructed fixtures are not phishing
ground truth. `integration_api_real.py` checks the actual HTTP worker and ZIP
contain the same qualified graph bytes.

This is a bounded repair of one S08 artifact. The separate domain diagram,
Markdown reports, other publishers, malformed-source readability and global
resource limits remain open audits. Local parser checks do not validate all
renderers or complete the UI, classification, provenance authenticity or OS
isolation work. Existing cases are not rewritten.
