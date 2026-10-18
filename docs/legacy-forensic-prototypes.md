# Legacy forensic prototype publication

Both `advanced/quantum_resistant_forensics.py CASE_DIR` and its
`util/quantum_resistant_forensics.py` launcher explicitly report unavailability
before accessing a case. Accepted paths exit 1, exact `-h`/`--help` exit 0,
missing/unsupported arguments exit 2, long-option abbreviation is disabled and
import is inert. Both retain `main()` invocation and accept explicit `main(argv)`.
Direct invocation uses only the standard library.

The advanced `file_hashes`, `quantum_safe_hashes`, `immutable_chain` and
`zero_knowledge_proofs` call shapes raise `RuntimeError` before inspecting their
arguments. Ordinary `sha3_512_hex`, `blake2b_hex` and `calculate_block_hash`
implementations are unchanged; they do not provide the unavailable proof or
publication contracts. No package code, hash algorithm or replacement proof
system is introduced.

Actual guarded runs of both former entry points on declared sealed filesystem
fixtures returned success, overwrote analyst notes and invalidated the seal.
Six missing input files were each published with size zero, the hash of empty
bytes and `quantum_resistance_level: HIGH`. Missing files thereby became digest
records without an error outcome. The source itself described the commitment
outputs as placeholders. This is a local filesystem/output observation, not an
actual email analysis, cryptographic proof assessment or post-quantum assurance.

Saved case sources and prior outputs remain intact. No tracked production
consumer outside this two-script prototype family invokes its functions. The existing supervised
case seal, `paw verify` and ZIP export remain available for their recorded
integrity scope. Those separate products do not replace zero-knowledge proofs,
authenticate prior output claims or establish historical custody. Future proof
capabilities would need a justified independent cryptographic/verification
contract, source/error admission, bounded processing and versioned publication.

`integration_legacy_quantum_real.py` runs an actual full original-EML analysis
under no-egress, checks stopped supervision, original bytes and seal, then
exercises both entry points against completed, sealed, unsealed, malformed,
missing, outside and owner-metadata fixtures. Thirty-six fresh guarded processes
cover execute/main/import/help/errors/prefixes and the four advanced APIs with
opaque arguments; twelve direct stdlib invocations run outside the checkout
without `PYTHONPATH`. Source snapshots, notes, seals and process state remain
unchanged; observed source operations are rejected and no blocked network
attempts occur. The file hook does not cover every metadata syscall and is not
OS isolation. Owner/file fixtures are not live workers or captures. Actual CLI
verify and ZIP export preserve every original case file after the rejected
publishers. A matching seal establishes integrity in this tested flow, not
authenticity, accuracy or any of the unavailable proof guarantees.
