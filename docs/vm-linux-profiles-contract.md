# P4 finite Linux profiles and explicit browser JavaScript

P3 is closed at [its actual acceptance checkpoint](vm-p3-acceptance.md).
This first P4 increment implements bounded source admission metadata and three
explicit forensic interpretations through the supervised CLI/HTTP worker. It
does not implement native VM execution, issue grants, install I08, change the
limited operator or activate a recipe. P4 and P5 remain open.

## Static source interfaces

`paw inspect-representations SOURCE --interpretation MODE` and the existing
`/api/sources/representations` route accept the following additional modes.
The caller must choose; extensions, shebangs and signatures never select an
interpreter automatically. Existing `mime` and `html-utf8` behavior is retained.

| Interpretation | Finite declaration | Source bound |
| --- | --- | --- |
| `posix-shell-utf8` | `linux-posix-shell-offline-v1`, strict UTF-8 without NUL, fixed guest `/bin/dash`; source shebang is preserved and cannot select a command | 64KiB |
| `elf64-x86_64` | `linux-x86_64-elf-offline-v1`, Linux/System-V ELF64 little-endian AMD64 executable or PIE | 1MiB |
| `javascript-utf8` | Explicit classic-script HTML candidate for the existing `linux-chrome-html-offline-v1` profile; not Node.js or a module runtime | 256KiB source, 512KiB generated HTML |

Original acquisition retains its existing8MiB forensic limit. A source outside
the selected profile's format/encoding/size stays preserved, with explicit
`unsupported`/partial coverage and no derived executable candidate when the
transformation cannot complete. There is no lossy decode, source replacement,
classification or safety verdict. Worker wall/stage/CPU/AS/file and graph budgets
are unchanged, including tightening against lower inherited POSIX ceilings.

ELF inspection reads bounded bytes with `struct`; it never invokes `ldd`, a
loader, compiler, executable, archive tool or dependency lookup. At most128
program headers and128MiB aggregate declared load memory are admitted. Entry,
load ranges, alignment, architecture/ABI and a single optional ASCII interpreter
are checked. Only `/lib64/ld-linux-x86-64.so.2` and
`/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` are declared interpreter names; they
are metadata and are not opened on the host. Sections/symbols and DT_NEEDED are
uninterpreted. Structural admission does not prove guest loadability: missing
guest libraries and loader errors must remain execution outcomes in the later
runtime increment. Validity is not harmlessness or permission to execute.
Unused `PT_NULL` entries are skipped rather than interpreting their undefined
members as file ranges, as specified by the
[gABI program-header definition](https://gabi.xinuos.com/elf/07-pheader.html#segment-types).
An actual byte-only negative/positive regression covers this compatibility case;
the first implementation incorrectly rejected it. The PIE data fixture places
its interpreter entry before its load entry.

The JavaScript transform checks strict UTF-8, then Base64-embeds the exact bytes
in a fixed classic-script data URL inside a new HTML document. Quotes and closing
script/HTML tags in the source cannot become wrapper markup. The separate
`browser_html_candidate` node has its original-byte parent, source digest,
versioned `javascript-to-browser-html` transform and explicit parameters. It
records the changed document/origin and relative-URL environment; no original
standalone environment, Node APIs or module semantics are asserted. The host
encodes data and does not parse or run JavaScript. Invalid UTF-8 and graph work,
node or aggregate-byte exhaustion leave explicit omissions and original bytes.

The existing P3 request/receipt schemas, profile allowlist and contract file are
unchanged. An operator can explicitly prepare an HTML request selecting the new
wrapper; preparation confers no execution authority and leaves the sealed parent
unchanged. Shell/ELF need a distinct versioned request/receipt and Root authority
increment before they can execute. Existing grants retain their exact
bytes/profile bindings and cannot authorize native shell/ELF execution.

## Measured ordinary acceptance and remaining runtime work

Eleven admission and four JavaScript derivation tests cover byte identity, bounded
headers/ranges/entry/ABI/interpreter/memory, shell encoding/NUL, markup-safe
embedding and graph omissions. All121 existing representation tests pass.
Forty actual source plus40 installed CLI/HTTP cases pass, including seven new
fixtures per mode, original/seal/private-ZIP/known-stop checks, HTTP metadata and
explicit JavaScript→HTML request preparation without a grant. Three invalid
source/path refusals pass in each mode. No specimen was executed.

A fresh ordinary venv received a real local wheel installation; all110 Python
files match source/wheel/installation and dependency checking passes. Validated
dependencies were copied locally without downloading; clean dependency
resolution remains the four-version installed CI gate. The fixed client used
by the accepted Root runtime was not replaced. No Root snapshot or VM changed.
The first CI run exposed a test-fixture import that failed under Python `-P`.
The same isolated installed invocation reproduced it locally. The test now
loads only its fixed byte-data fixture by absolute path; it does not add the
checkout to `sys.path` or relax the installed PAW origin assertions. The updated
40-case installed CLI/HTTP suite passes with `-P`, outside the checkout and with
`PYTHONPATH`/`PYTHONHOME` removed.

Next P4 increments must provide separate native selection/receipt/one-use
authority, opaque ingress and trusted guest-only `/bin/dash`/x86-64 execution,
then finite normal/error/loop/fork/output/memory/file/owner/protocol acceptance.
The already reserved `shell-owned-v1` and `elf-owned-v1` commands must remain
finite: no caller paths, source bytes, commands, service properties or automatic
real-source grants. Root/client privilege separation, exact immutable releases,
review/head+main CI, global lock, image/context checks, no NIC/sharing, known
external stop and existing laboratory/controller budgets remain mandatory.
JavaScript must also pass actual source/installed browser handoff of the explicit
derived view. P4 closes only after those actual harmless runtime/I08 results;
P5 still requires the full operational consolidation in the project plan.
