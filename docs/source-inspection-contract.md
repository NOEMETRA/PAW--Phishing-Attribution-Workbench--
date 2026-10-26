# Bounded opaque source inspection (P1)

`paw inspect-source <local-file> [--workdir <workspace>]` acquires a regular
local file as bytes. Empty files, binary data, misleading suffixes and malformed
text/MIME are accepted within the default16MiB input budget. This command does
not choose a parser or execute a source. Existing email commands and scoring
remain separate. Python's offline policy is an application guard; local kernel
mounts and the host are outside its network-isolation claim.

Acquisition uses one nonblocking, no-follow descriptor where POSIX supports
those flags, bounds reads, and compares descriptor/named-inode identity, length,
mtime and ctime after reading. Schemes/UNC paths, final-component links, FIFO/devices/directories,
oversized files and observed concurrent changes refuse. A successful acquisition
does not prove authenticity or future stability of the caller's original file.
The bounded captured bytes become `source.bin`, read-only in a fresh case.

The versioned observation records SHA256, byte length, empty status, bounded hex
prefix, byte counts, entropy and signature-prefix hints. Strict UTF8 observation
has a1MiB budget and preserves BOM, CRLF, NUL and invalid-byte errors; it never
substitutes replacement characters. Omissions are explicit. Prefixes and text
decodability establish neither format validity nor semantic understanding.
Coverage says interpretation/semantic analysis not performed, classification
not evaluated and execution authority none. No score or attribution is produced.

The worker uses the existing supervisor and modern `analysis_` ownership registry:
30s overall,10s per stage,256MiB address space,66MiB artifacts,128 files and128KiB
log. POSIX worker CPU is10s with11s hard limit, core dumps disabled and65MiB
per-file ceiling. Unsupported native controls are not advertised as enforced.
The library reader's configurable input ceiling is64MiB; the public job/API
always use16MiB and never increase the fixed worker budgets automatically.
New `case-source-<uuid>` cases contain a manifest/job binding, execution status,
exact bytes and observation report, followed by the existing seal and ZIP.
Cancellation/abnormal termination retain honest partial accounting only after
the supervisor confirms tree shutdown. Verify/export guards block live writers.

The local API adds `POST /api/sources/upload` and `POST /api/sources/inspect` with
`{"file_path":"<returned upload path>"}`. Uploads use private generated names;
their names do not establish a source format or original provenance. Empty and
binary files are valid. The multipart envelope requires fixed Content-Length,
no Transfer-Encoding and at most16MiB+64KiB; the file itself is capped at16MiB.
Inspection accepts only the upload store and fixed limits, no execution/options.
Queue/cancel/recovery use the existing job lifecycle. Source case views expose
byte coverage without fabricated email fields, zero scores or an assessment.
Existing email upload/analyze contracts remain unchanged.

P2 representation derivations, P3 selected-view grants and P4 additional guest
profiles are not provided by this increment. In particular these observations
cannot admit bytes to a VM, loosen the strict existing HTML bridge or authorize
real inputs. Tests use owned fixtures, loopback HTTP and inert content only.

Local acceptance on26 October2026 used Python3.14:13 reader tests and3 actual
CLI/ownership/interruption tests passed. Source and clean-wheel installations
each passed8 CLI/HTTP cases plus3 CLI admission refusals, strict source views,
upload-envelope/file ceilings, seal/ZIP accounting and known-stop cleanup.
The wheel SHA256 was
`41fb8993bfa64cd0a09b654411f31ecd802c2ac19e80621a71f57506d0f3f843`;
all109 packaged files matched its installation and dependency checks passed.
Existing supervision(8), queue(3) and recovery(18,2 platform skips) unit checks
and actual CLI/API ownership/crash integration also passed. P1 closure still
requires its exact-head review, required CI, merge and main verification.
