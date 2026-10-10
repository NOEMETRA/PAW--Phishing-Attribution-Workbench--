# Standalone deobfuscation input

`paw deobfuscate` interprets one supplied string or UTF-8 text file locally. Its
file reader previously ignored invalid UTF-8 bytes and translated newlines;
the reported `original_text` could differ from the supplied bytes. For example,
`pa\xffypal\r\nOriginal` became `paypal\nOriginal`. Multiple input flags were also
accepted: `--text` could silently override `--url`, then be analyzed as the URL.

## Accepted input and preserved observations

Choose exactly one source, including an explicitly empty text value:

```powershell
paw deobfuscate --text "Literal text" --json
paw deobfuscate --file extracted-utf8.txt --json
paw deobfuscate --url "hxxps://example[.]invalid/a%2Fb" --json
```

Files must be regular files with valid UTF-8, at most 1 MiB. Reading is bounded
to the limit plus one byte using one file descriptor; a growing file cannot
cause an unbounded read. Invalid encoding is rejected before analysis, without
repair, dropped bytes or charset guessing. BOMs, CR/LF and Unicode spelling are
preserved. Literal text/URL values have the same UTF-8 byte limit. Missing,
conflicting, oversized or unreadable inputs fail nonzero; JSON stdout is empty
on input rejection. A file's extension does not determine its encoding.

The JSON result adds `input_observation` with source kind, exact observed UTF-8
byte count and SHA-256. Encoding the reported `original_text` as UTF-8 reproduces
the bytes read. These observations describe the read snapshot; they do not
authenticate its provenance or prove a file was stable throughout acquisition.
The original file is never rewritten. Empty files/text remain explicitly empty.
No case, seal, job registry or evidence archive is created by this command.

For original EML/MIME parsing and sealed evidence, use supervised analysis:

```powershell
paw full original.eml --no-egress
```

Do not use this standalone text reader as a MIME or attachment decoder. Extracted
or transcoded text needs a separate labeled copy; preserve the original email.

## Offline boundary and remaining scope

Reading and decoder dispatch run under the Python no-egress application guard.
`--url` is a literal candidate, never a download or navigation request. The guard
does not cover CLI bootstrap, native code or OS filesystem/network isolation.
UNC paths are rejected, but that check does not establish the isolation of other
mounted or mapped filesystems. The standalone command has a bounded input, not
the shared CLI/API analysis process supervisor or a total execution deadline.

Text risk remains unevaluated. Existing descriptive observations, URL candidate
provenance and uncalibrated URL transformation heuristics are unchanged. No score,
phishing verdict or attribution is added by a valid input/hash.

Validation includes real CLI invocations, exact BOM/CRLF/Unicode/empty inputs,
invalid UTF-8 and conflicting-source rejection, byte-limit/nonregular-input
contracts, human/help/JSON output and unchanged source files. An instrumented
actual CLI observes the input open under the guard and no socket/process attempts
during dispatch after bootstrap. These constructed regression inputs do not
measure phishing accuracy or demonstrate OS isolation.
One subsequent actual supervised `full --no-egress` on an original public EML
also verifies common-parser compatibility, original MIME and its evidence seal.
