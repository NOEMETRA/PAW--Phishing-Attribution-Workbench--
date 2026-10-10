# Local DKIM key evidence

All analysis presets accept `--dkim-keys PATH` while keeping `--no-egress` active:

```text
paw full inbox --no-egress --dkim-keys keys.json
```

The UTF-8 JSON file has exactly these fields:

```json
{
  "schema_version": 1,
  "source": "Analyst description of where these public TXT records came from",
  "records": {
    "selector._domainkey.example.com": "v=DKIM1; k=rsa; p=PUBLIC_KEY_BASE64"
  }
}
```

The example key is a format placeholder and cannot verify a signature. Use actual
public DKIM TXT records already obtained outside this offline analysis. `source`
is an analyst claim, not a trust certificate. No DNS query, download or fallback
lookup is performed. Names are compared case-insensitively with one optional
trailing dot; duplicate normalized names are rejected. TXT values are assembled
record strings, without DNS presentation quotes. Empty `records` are allowed and
do not authorize any verification.

Admission limits are 64 KiB of UTF-8 JSON, 32 records, 8,192 ASCII characters per
record and 1,024 characters for the source description. Unknown fields (including
claims that the key is trusted), invalid names/types, duplicate file JSON fields,
nonregular files and oversized inputs are rejected. CLI file bytes are captured
before job creation; queued workers do not reopen the original path.

For the HTTP API, supply the same JSON object in `options.dkim_keys` on
`POST /api/analyze`. Paths and arbitrary evidence-snapshot fields are not accepted
through this option. The API validates the decoded object before enqueueing and
captures a detached canonical JSON snapshot. It does not preserve the HTTP body's
whitespace or repeated JSON fields discarded by its ordinary request parser.

Each new case preserves the snapshot as `dkim_keys.json`, with its SHA-256, source
claim and unverified provenance in `manifest.json` and `auth.json`. CLI snapshots
retain exact file bytes; API snapshots retain the accepted object. Key evidence,
original MIME and results enter the same sealed inventory and ZIP export. Existing
cases are never updated or resealed. The worker and direct engine ingress validate
the snapshot again before creating cases.

Verification checks each signature against the corresponding supplied record.
A valid signature is `pass`; changed signed content is `fail`; missing keys or
absent signatures remain `not_evaluated`. A missing selector is checked before
body verification, so an altered message with no corresponding key does not
become a verified failure. Malformed key/unsupported algorithm outcomes remain
errors, not proof of phishing. Multiple signatures retain per-signature outcomes;
any successfully checked signature makes the aggregate result `pass`.

The result is scoped to `signature_with_supplied_keys`, with key provenance
`unverified`. DKIM associates a signature with a signing domain, which can differ
from the purported author ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376.html)).
This path does not establish historical DNS authenticity, sender identity,
message legitimacy, DMARC alignment or actor attribution. Failures against local
unverified keys do not add authentication-risk points; coverage retains
`dkim_key_provenance` as unavailable. Existing header claims are not promoted to
independent authentication. No automatic trust override is provided.

The regression generates real RSA keys/signatures and tests original/tampered,
missing-key, unsigned and multiple-signature messages through supervised offline
CLI workers and a loopback HTTP API. It checks all five presets, input admission,
unchanged original/key bytes, provenance, scoring, seals and ZIPs. These constructed
cryptographic fixtures establish these contracts, not classifier accuracy or
the authenticity of keys for the private email corpus. Without the new option,
the existing unavailable-key behavior remains unchanged.
