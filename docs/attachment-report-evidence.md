# Attachment table evidence boundary

The attachment table in `report/technical.md` previously interpolated MIME
filenames directly into Markdown. An actual full offline analysis of an inert
constructed message reproduced shifted columns and a missing displayed digest
from a pipe in a filename. RFC 2231 encoded newlines also introduced a report
heading. Original MIME, attachment metadata, payloads and seals remained intact;
the defect was in this report consumer.

Only filename and MIME cells in that table change. They now contain literal JSON
strings in code spans: control characters remain visible as JSON escapes, each
backtick fence exceeds the runs in its value, and pipes are escaped for GFM table
parsing. JSON quotes distinguish source backslashes from control-character
escapes. Unicode text remains Unicode. Exact metadata is still in
`attachments.json`; the SHA256 column retains its existing display prefix and
the full hash remains in the source metadata. Existing sealed cases are not
rewritten. Extraction, scores, file naming and attachment analysis are unchanged.

`tests/integration_attachment_report_real.py` runs three actual full no-egress
CLI cases: the repository's original EML, an ordinary attachment and a constructed
message with pipes, backslashes, newlines, tabs, backticks, Markdown/HTML-looking
text and Unicode in attachment names. A separate actual loopback HTTP worker
analyzes the constructed message. An independent MIME parser checks names and
payloads; a passive Markdown parser with GFM tables checks all rows, five columns,
literal cells and displayed hashes. Actual CLI ZIPs, HTTP detail and HTTP ZIP
bytes, stopped owners, original MIME, payloads, metadata and seals are checked.
The regression fails before the repair and passes after it. Fixtures are not
independently labeled phishing data.

This contract covers the existing attachment table with the tested Markdown
parser, without browser rendering or resource loading. Other report sections,
renderers and resource/control-character admission remain separate audit work;
it does not establish malware detection or email authenticity.
