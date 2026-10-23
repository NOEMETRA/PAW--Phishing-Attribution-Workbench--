# Parser-selected MIME context

Baseline: PR87 merged as `43c5c47fe4cafe62e3168a071aa8861a5663583d`,
23 October 2026. Codex found no issues on tested head `ab81261`; all three head
and merge CI checks pass. This family addresses context selection by the existing
MIME extractor and its evidence/coverage consumers.

## Reproduced boundary and correction

Duplicate Content-Type or Content-Disposition fields could select a body,
attachment or multipart tree without any defect reported by the stdlib. The
extractor then reported completed MIME coverage. Conflicting and identical
repeated declarations both reproduced this behavior. A missing closing multipart
boundary also left its selected child body without inherited context uncertainty.

The extractor retains the same stdlib-selected view. It does not choose a later
declaration, reconstruct alternative trees or execute content. Each visited outer
MIME node now has `mime_context` with three fixed header observations: counts,
first zero-based per-entity header positions and selected-field defect counts for
Content-Type, Content-Disposition and Content-Transfer-Encoding. Absent fields
record `parser_default`, count zero and no selected position.

Known parser structure defects are counted before transfer decoding. Repeated
fields, selected-field/structure defects or inherited uncertainty make context
partial. Ordered `partial_ancestor_part_ids` bind inheritance to the selected
tree; a sibling does not inherit another branch. Later decoder/charset defects
retain their existing separate observations. Completed context diagnostics do not
certify unique interpretation, MIME conformance, authenticity or safety.

Body and attachment inventories retain the context and mark affected records
partial without changing their selected payload/text bytes or hashes. Coverage
and the technical report expose partial/inherited context counts. Successful job
completion still means execution completed; uncertainty adds no risk points.

## Contexts, bounds and omissions

| Existing view | Supported boundary and limitation |
| --- | --- |
| Outer text/plain, text/html and text/javascript | Existing selected non-attached bodies and per-part provenance; HTML/JS are not executed. Ambiguous selection is now explicit. |
| Attached or encapsulated content | Separate payload/header/original-wire inventories keep their existing scope. Inner declarations do not become outer sender/body context. |
| Repeated/defective declarations or malformed framing | Preserve the parser-selected view and known uncertainty. Alternative trees are not interpreted; no count of hypothetical missing bodies is invented. |
| Bounded header catalogs | Positions refer to the original parser entity. The catalog may omit selected values under its own limits; input.eml is authoritative. Complete header capture is distinct from complete interpretation. |
| Other extraction contexts | Existing URL links cover supported outer bodies and first selected Subject/From views. Other headers, attached/embedded body discovery, relative-resource resolution, Content-Location and CSS/srcset resource semantics are not certified by this block. |

Context metadata retains fixed field observations and bounded ancestor IDs,
without copying all declarations. Existing 500-node/30-depth tree bounds apply,
including embedded-node preflight. Input/decoded/text byte limits still reject
rather than silently truncate MIME analysis. Header catalogs separately retain
bounded prefixes and exact omission counts. Tests exercise 1,500 declarations
without growing context metadata with their values, plus a selected field after
1,100 other headers omitted from the catalog but bound to its parser position.
Original bytes, selected content, target strings and scoring algorithms are
unchanged. Historical sealed cases are not rewritten; missing historical context
diagnostics are not completed context checks.

## Verification

Eight regression contracts cover defaults, duplicate/defective declarations,
bounded counts/positions, structural defects, inherited body/attachment context,
unaffected siblings and embedded-header separation. Declaration contracts fail
on the baseline; the malformed-parent contract fails before structure propagation.
Failed subtests are not independent bug counts.

`tests/integration_mime_context_real.py` runs 16 actual full no-egress CLI cases
and four loopback HTTP workers. An independent stdlib parse checks selected
types/dispositions, positions and bytes. Original EML, body/attachment hashes,
partial status, late omitted headers, unaffected score contributions,
coverage/report/API parity, stopped owners, seals and CLI/HTTP ZIP bytes pass.
The malformed multipart retains the stdlib's removal of its final separator CRLF
in the derived payload; exact wire remains in input.eml rather than being repaired.

On final frozen Windows Python 3.13 sources, 898 tests run: 884 pass and 14 platform
exclusions remain. Six serial real integrations pass: the new context flow, MIME
bodies (33 CLI/14 HTTP), MIME headers (12 CLI/3 HTTP), literal reports (3 CLI/1
HTTP), local DKIM across five presets/HTTP and the actual wheel (92 Python
sources). Four existing package sources change; 88 remain unchanged. All 238
Python/workflow hashes are rechecked before docs.

```text
python -B -m unittest discover -s tests -p 'test_mime_context.py' -v
python -B tests/integration_mime_context_real.py
```

Constructed messages are regression fixtures, not phishing accuracy labels.
The application guard is not an OS sandbox. PR88 exact-head Codex review is clear;
all three head/merge CI checks pass, integrated as
`418f8aa6985e7b3ee18c83648048ab414b0a25ee` with the reviewed tree unchanged.
The counts above describe that MIME family;
other extraction contexts, platform installation, independent labels/holdout,
controlled egress and UI retain their separate audit gates.
