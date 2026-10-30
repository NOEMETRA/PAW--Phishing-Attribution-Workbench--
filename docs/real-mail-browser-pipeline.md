# Real mailbox to isolated online browser: acceptance plan

Owner instruction,30 October2026: test the actual PAW email pipeline on a
user-designated Spam corpus, including website navigation and JavaScript in an
isolated VM with controlled egress. This extends the finite completed P0–P5
project. [That checkpoint](vm-final-acceptance.md) explicitly excludes real
egress and does not authorize this new execution path.

## Actual baseline and concrete remaining boundary

Three original messages were exported through Outlook's EML download, without
opening their embedded links, and copied byte-exact into a private local corpus.
Provider-exported MIME is the acquired source; it is not a reconstruction from
the connector's normalized message body or proof of original SMTP wire history.
The account, source identities, original SHA256 values and provider metadata stay
outside Git. Spam-folder membership and the owner's phishing triage are not
independently adjudicated accuracy labels.

The actual installed `paw full --no-egress` batch completed all three inputs.
Each original, report, coverage record, seal and exported ZIP was independently
reconciled. One original also passed actual loopback HTTP upload, queue/worker,
case/list and byte-exact export, with CLI/API score parity. All three strict
profile results were `Inconclusive`,0.05, uncalibrated: the only score contribution
was the existing profile modifier. Network enrichment and detonation were
explicitly skipped. This is an offline execution/integrity PASS, not online
acceptance, a phishing verdict or evidence that egress alone will fix accuracy.

A read-only diagnostic checked the actual installed URL handoff on the three
cases: each had three eligible URL records and all three reached the runner's
selection helper. No missing-URL defect was reproduced. No browser was started
and no target contacted; the diagnostic's application offline guard blocked one
socket-construction attempt during imports. Earlier observer mistakes and their
corrected readbacks remain private evidence, not product defects.

The installed Root operator has only five owned/no-guest recipes and requires
zero real specimens executed. Its parent service declares `IPAddressDeny=any`.
Its actual accepted browser profile has no NIC. The separate historical
[controlled uplink](s14-controlled-uplink.md) is one trusted GET to a fixed
operator-owned endpoint, without arbitrary website JavaScript. Neither is an
online phishing-browser gate. Running the legacy network-enabled host browser
would not establish the requested VM isolation and is not an acceptance shortcut.

## First increment: unprivileged preparation only

`uplink_policy.prepare_mail_browser_plan` creates a distinct
`paw-mail-browser-egress-plan-v1` value. It binds at most three selections, each
with email SHA256, sealed parent manifest SHA256, URL-evidence artifact SHA256,
exact URL-record index and exact supplied HTTP(S) URL. Hash syntax is not custody
verification. One email may appear only once in this initial bounded batch.

The exact URL bytes, including query and percent escapes, remain intact. HTTP
is explicit and is never silently upgraded to HTTPS. Credentials, fragments,
literal/noncanonical numeric IP forms, alternate ports, non-ASCII/control/space
characters, encoded authorities and backslashes refuse. ASCII DNS hostnames
and their standard80/443 ports are the only preparation forms. This function
does not resolve a name, open a socket, parse/render fetched content or execute
anything. DNS/public-address/response checks are future runtime requirements.

The value always states `PREPARED_NOT_ACTIVE`, `network_authority:none` and
`execution_authority:none`. It names required controls but does not establish
them. Validation rejects changed endpoint bindings, extra fields, claimed
authority, removed controls or changed budgets, including bool/int ambiguity.
A caller can construct another syntactically valid plan; that is never evidence
that its parent exists, its URL was observed or its execution is approved.

Prepared ceilings are three seed URLs, eight separately admitted public hosts,
32 requests, five redirects per navigation,4MiB aggregate response bytes,
15 seconds browser time,256KiB DOM and1MiB netlog. The external stop bound is
strictly below12 seconds. These are proposed limits to enforce and measure,
not a claim that preparation currently installs counters or packet controls.
Guest/QEMU/Root/client/aggregate resource ceilings are not increased here.

This increment adds no Root command, recipe, policy file, firewall/NIC change,
privileged source file or network permission. The existing128-file lab inventory
stays128; `endpoint`, `admit`, the old fixed GET and all installed static operator
modules remain unchanged. No immutable release is promoted by preparation.
Future source-changing activation needs its own current context and acceptance;
old P0–P5 readiness is not inherited.

## Ordered activation work and closure criteria

| Stage | Work | Required evidence before advancing |
| --- | --- | --- |
| O0 | Real offline pipeline and original corpus acquisition | Actual source-copy hashes, installed CLI/API workers, honest coverage, seals/exports and stopped writers. Completed as described above; private artifacts retained. |
| O1 | Separate prepare-only contract | Completed in PR140 after exact-head review, head7/main7 and tree equivalence. No activation follows from passing it. |
| O2 | Broker, guest transport, custody and limited operator integration | Root independently rechecks actual sealed source/parent/URL record and protected per-hash approval, immutable reviewed code and fresh scoped runtime context. Finite commands and exact data only; no caller-selected host code, paths or administrative properties. |
| O3 | Actual owned online-browser matrix | Rehearse complete installed PAW→broker→disposable browser VM→sealed sidecar using owned local HTTP/TLS fixtures. Exercise success, JavaScript resource/navigation requests, redirects, forbidden addresses, guard/owner/protocol loss, counters/deadlines, DNS rebinding and replay. Independently reconcile stop and full host restoration. |
| O4 | Explicitly approved real batch | Present the concrete corpus hashes, initial targets, allowed-host policy and tracking/token disclosure before accepting per-hash execution approval. Require all preceding gates current and clear; then run the real installed pipeline with controlled egress, preserve partial/failure observations, import a separate sealed sidecar and reverify original cases. |

O2 must keep a strict separation between preparation and protected approval.
Neither a workspace JSON field such as `approved:true` nor an ordinary request
can mint that approval or a grant. A reviewed native update may be necessary
once when expanding the installed operator's finite scope; ordinary admitted
jobs must then use the narrow mechanism without repeated passwords. No stored
password, generic sudo or writable workspace code executed as Root is allowed.

## Required online isolation semantics

The disposable guest may execute website JavaScript only inside the browser
sandbox, with nonroot guest execution, verified immutable image/controller,
enforcing host confinement, no host shares/devices/credentials and the existing
whole-process budgets. A dedicated reviewed network path must prevent direct
guest/host-scope bypasses. Host credentials and mailbox sessions never enter it.

Every destination, subresource and redirect must pass the bounded host/public
address policy; unregistered hosts refuse and are reported as missing coverage.
Actual DNS answers are rechecked, all mixed/private/special answers refuse, and
approved IPv4 pins are leased against monotonic deadlines. LAN, host, loopback,
metadata endpoints, IPv6, alternate ports, guest DNS and uncontrolled QUIC must
remain unreachable independently of the guest's claims. Guard loss, expiration
and owner death must cut established traffic, not merely new connections.

TLS verification remains enabled. URL tokens and request metadata may identify
the recipient to a remote site even without credentials; O4 approval must state
that disclosure. Observe navigation/resource loading, not account login, form
submission, email sending, purchases or downloaded-file execution. Application
method filters must not be described as an OS guarantee unless a trusted network
layer actually enforces them across HTTPS. Limits/refusals and TLS/network
failures remain visible rather than relaxed for a page to succeed.

The trusted coordinator must consume one-use authority before execution, keep
per-request/host/redirect/byte counters, stop writers externally and verify the
domain/QEMU/TAP/broker state before publication. Host rules/routes/interfaces
must restore exactly; unknown stop prevents import. Root-private audits remain
protected. Published attestations, opaque bounded artifacts and independent
ordinary readback must be distinguished honestly, as in P3/P4.

Online observations belong in a separately sealed sidecar bound to the exact
parent, email hash, URL evidence, requests, runtime and policy. Do not rewrite
original MIME, original scoring, seals or prior offline reports. Any later
assessment must identify its new observations and uncalibrated interpretation;
successful execution, Spam placement and matching hashes do not supply labels.

## Current disposition

O0 passed for three acquired originals; O1 merged with review, head/main CI and
tree equivalence. O2–O4 are open. Zero real target connections or real website-script
executions have occurred in this new corpus test. The completed P0–P5 monitor
stays disabled; this document does not silently recreate an automation, extend
its closed goal or claim full online pipeline acceptance.

### O2 component: sequential request accounting and HTTP transport

`paw.core.browser_mediator` is a library component, with no CLI, API, Root
operator or guest entrypoint. Import and ledger operations open no socket and
perform no DNS. Its explicit `exchange` function can open one numeric pinned
IPv4 HTTP(S) connection; calling it does not establish permission or isolation.
It must only be wired into the separately confined trusted broker after O2
integration. The old offline operator and accepted no-NIC profiles are unchanged.

The ledger consumes a nonce/sequence before request admission, requires the exact
initial seed even after refusal, allows one pending request and refuses replay
or changed leases. Invalid envelopes, wrong nonce/sequence, replay or concurrent
admission permanently close the session before another lease can be admitted or
completed. Well-formed requests with refused URL/method/DNS facts still consume
their request slot. Reconstructing this ordinary ledger is not a new protected
one-use job grant. It enforces32 request slots, eight public host pin sets,
4MiB response bodies,15 seconds and at most five seconds per lease. The initial
version uses a stricter five-redirect ceiling across the entire session. Public
host discovery defaults off; enabling it is a future protected policy decision.
Mixed/special/noncanonical answers, changed DNS pin sets and stale facts refuse.
DNS facts passed to this object are not independently verified by the object.
Its internal lease identity is not a Root approval, grant or security boundary
against a caller that controls Python memory.

Only GET/HEAD use fixed broker headers: page cookies, credentials, client headers,
proxies and environment settings are not forwarded. TLS loads the fixed Linux
CA file `/etc/ssl/certs/ca-certificates.crt`, with hostname verification, SNI and
TLS1.2 minimum. It ignores caller CA-directory/file and key-log environment
variables. The future immutable runtime must bind the actual CA bytes to its
scoped context; a fixed path alone does not attest those bytes.
Redirects are returned for a separately
admitted browser request. The absolute deadline covers connect, TLS, header and
body reads. Fixed-length, close-delimited and simple chunked HTTP/1 bodies are
bounded; interim/upgrade responses, chunk extensions/trailers, encoded bodies,
ambiguous framing and truncation refuse. Failed exchanges exhaust the remaining
body allowance and close the session, rather than restoring quota after partial
unaccounted reads. Cookies, authentication challenges, hop headers and fields
named by `Connection` are removed from responses. An additional CSP blocks forms
and objects; this is an application restriction, not kernel confinement.

Returned metadata says explicitly that TLS was verified **by the broker**.
Broker TLS fingerprints must not be labeled browser TLS fingerprints. This
mediated observation deliberately differs from a browser's direct TCP/TLS stack;
unsupported protocols/resources and refusals must remain visible coverage gaps.

Tests use inert data, mocked numeric transport and actual owned loopback HTTP
streams, including slow-header deadlines, partial/oversized/ambiguous responses,
DNS/pin/replay refusals, certificate-failure handling and actual stdlib rejection
of caller-selected CA/key-log environment. They launch no browser,
create no namespace/firewall or Root authority and contact no public target.
They do not constitute the owned VM acceptance matrix. Guest CDP interception,
bounded serial transport, independently checked real custody/protected approval,
immutable source integration, the confined runtime and external stop/restoration
remain O2/O3 work before any concrete real-batch O4 approval is requested.
