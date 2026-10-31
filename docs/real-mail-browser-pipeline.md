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

### Owned kernel prerequisite

The fixed `vm-acceptance-v1` no-VM recipe now includes a finite owned kernel
prerequisite after maintained runtime validation. Its only destinations are two
numeric aliases on loopback inside a new PID1-owned private network namespace.
It creates no interface pair, default route, NAT, forwarding change or host
namespace mount. These aliases do not contact the public addresses they spell.
The generated payloads are raw nonce-bound TCP/UDP fixtures, not HTTP, TLS or
DNS. This component alone cannot establish O3 or authorize real egress.

Five cases cover default drop, DNS-port-only tuple, TCP tuple expiry, loss of
the namespace keeper during an established stream, and deletion of both owned
filter tables during a stream. Two default-drop tables admit only one expiring
tuple, including return packets; connection state alone cannot bypass expiry.
Filter hooks run after connection tracking. The Root keeper accepts only fixed
scalar control operations, holds only `CAP_NET_ADMIN`, has an eight-second
PID1 runtime ceiling and cannot restart using the same protected marker.

The two network roles use reserved numeric identities65520/65521 only after
exclusive NSS/process vacancy checks. PID1's static numeric `User=` admission
requires an existing account: the first actual owned attempt refused the
fixture with217/USER, after the keeper passed its namespace/cgroup/capability
checks. Terminal reader reconciliation confirmed stopped writers, restored host
and zero real/public work. That consumed attempt is retained and not replayed.

To avoid modifying the host account database, PID1 now starts a small immutable
credential bootstrap inside the role's readonly private root and network
namespace. Its only initial capabilities are `SETUID`/`SETGID`, plus low-port
bind for the fixture. Before any socket or peer input it clears supplementary
groups and sets real/effective/saved UID and GID to the one fixed role identity.
The probe retains no capabilities. The fixture retains only bind until both
sockets exist, then clears effective/permitted/inheritable/ambient sets before
readiness or peer processing. Each socket is created as the nonroot identity,
preserving firewall `skuid` checks. Configuration is protected and exactly bound
before dropping; no path, account, capability mask or command is caller-chosen.

Roles have no home or credentials, no new privileges and syscall/address-family
restrictions. Independently read process state must show nonroot UID/GID,
empty groups and zero capability sets before work. Joining the
keeper's verified namespace and `BindsTo`/`After` tie both to its life. The Root
coordinator uses pidfds for the known owner fault and independently observes
UID/GID/groups, capabilities, seccomp, namespace inode and actual cgroup limits.

The existing512MiB/64task/100%CPU Root budget is partitioned into coordinator
256/32/50%, keeper64/8/10%, probe128/16/25% and fixture64/8/15%; swap remains
zero and the separate1536MiB QEMU ceiling stays unchanged. Every partial actor
is registered before readiness. Cleanup attempts all actors even after an
earlier failure, restores the parent limit, checks stopped writers and compares
the full host/network observations before publishing a terminal diagnostic.
Unknown cleanup or restoration prevents publication; an observed component
failure stays FAIL and prevents the enclosing runtime recipe from passing.
Bounded stderr from these fixed owned actors is included only after their
writers are confirmed stopped, to diagnose partial startup without a repeat.

Inert lifecycle tests and installed systemd259 parser checks do not prove
packet filtering, namespace joining or fault latency. Those remain unaccepted
until a reviewed, CI-green immutable release completes the actual owned recipe
and its independent reader reconciliation. This change adds no static helper
verb, real-source approval, I08, VM NIC or public route. The complete broker,
guest and installed PAW custody matrix is still required afterwards.

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

O0 passed for three acquired originals; O1 and the separate request mediator
component in PR141 merged with review, head/main CI and tree equivalence.
O2–O4 are open. Zero real target connections or real website-script
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

### Owned no-NIC Chrome/CDP probe

The next increment adds a fixed generated CDP probe to the existing
`browser-owned-v1` recipe, before its nine existing HTML cases. Only the
immutable reviewed release can supply its code. There is no new administrative
verb, caller-selected URL/source, host network permission or real-source grant.
The dispatcher, installed static helper and `IPAddressDeny=any` parent stay
unchanged. Actual execution still requires this increment's review, head/main
CI and independently verified Root promotion; software tests do not activate it.

`BrowserVM`'s separate `owned_cdp` seed uses the same read-only Chrome image,
no-NIC XML and existing job lifecycle/file/QEMU budgets. The guest service
accepts only inspect/start/poll/cancel and a fixed kind plus generated nonce.
Nonroot sandboxed Chrome starts on `about:blank`, with private descriptors3/4
for NUL-delimited CDP. It exposes no TCP DevTools port and no host browser is
launched. Downloads and permissions are denied before the controlled page is
navigated; Fetch interception is enabled before navigation. Authentication is
cancelled, child targets close without debugger resume, and requests after the
DOM snapshot boundary fail with explicit missing coverage.

The page and one JavaScript-requested text resource are generated fixture bytes
for `https://paw-owned.invalid/` and `/owned-data`. The callback opens no socket
or DNS connection; every other URL/method refuses. The script must change the
DOM title and a body attribute using the returned nonce. The trusted controller
retrieves actual DOM through CDP and checks that result plus the existing guest
renderer NNP/seccomp/nonroot/PID-namespace witnesses. This proves only the
measured owned Chrome/Fetch/DOM path when the Root trial passes. It is **not** a
TLS, DNS, public routing or real-email-browser test.

CDP decoding bounds each frame, aggregate bytes and event count; serial body
chunks independently bind nonce, sequence, order, length and digest and stay
below the existing60KiB console frame cap. The owned callback itself supplies
only its two small fixed resources. The guest keeps512MiB/256 process limits,
15 seconds,256KiB DOM and1MiB netlog. Its controller keeps128MiB/32 tasks;
QEMU remains1536MiB/64 tasks/50%CPU with1024MiB guest memory. No resource ceiling
is raised. CDP EOF/protocol loss requests immediate stop instead of waiting for
the whole-job deadline.

The Root producer reconciles external stop below12 seconds, absent domains,
host restoration, immutable images/source/canary and exact Chrome identity
before publishing a small Root-owned reader attestation. It also reads the
protected external owner's result: only requested stop, closed connection and
the same VM UUID preserve PASS. Mere absence after a guard/limit/controller or
unexpected QEMU exit is insufficient. Missing/unexpected results refuse
publication. Raw VM audits stay
Root-private. Ordinary readback must verify the protected attestation/source
identity and distinguish producer verification from independent raw-audit
inspection. Failure/unknown stop publishes no success. The nine pre-existing
HTML cases still run after the probe; this does not reopen unrelated audits.

Inert tests exercise the actual seed composer and preserve the original job
seed, fixed fixture/launcher refusal, EOF handling, CDP state/order/budgets and
bounded body transport. An ordinary harmless Python process also checked the
Linux descriptor3/4 ABI. The actual generated guest scripts are imported under
Python `-I` without calling main; standalone lookup restores only the trusted
seed directory. An inert fake-VM producer test rejects unexpected/missing owner
dispositions even when domains are absent and snapshots match. None of those software checks launches Chrome or
establishes VM acceptance. Public broker namespace/leases, full owned online
fault matrix, Root custody/protected hash approval and sealed real observations
remain required O2–O4 work.

### Actual owned CDP acceptance checkpoint

PR142's reviewed probe and PR143's separately reviewed exact host-maintenance
transition reached actual protected runtime acceptance on main
`01c4d33af2dd53e15262cdfe3a8d047d81277d2d`. Both PRs passed exact-head review,
head/main7 and independent immutable promotion. Fixed no-guest job
`d92fd2411c964506a3eec979a9f01d11` passed the current maintenance/context
readback without a password, guest start, grant or network authority.

Owned browser job `87174a6474134a5ea374e5491c07aba9` then passed actual
Chrome/CDP/Fetch/JavaScript/DOM and all nine original HTML scenarios. The CDP
probe observed two fulfilled requests and39 frames, the expected nonce-bound
DOM, nonroot renderer/NNP/seccomp/PID-namespace witnesses and stopped writers.
Its requested external stop took approximately1.07 seconds. The Root-owned
attestation binds the three program hashes, current context, VM UUID, owner
disposition and protected audit digest. Ordinary readback verified that
attestation and exact source hashes; its raw CDP VM audit remains Root-private.

The nine HTML audit copies were independently checked with the actual inert
execution/fault verifiers. Normal/error/timeout/cancel/output/memory and
paused/owner/protocol-loss cases passed, including replay and unknown-stop
publication refusal. The terminal helper, QEMU, domains, active networks and
namespaces were absent. A private1309-member archive was verified and retained;
its SHA256 is `3c50f3b60b753c33a8539ccd55ced641dfaab1a0ea63e1cab221f42099985834`.
All source-freeze interlocks were released only after that readback. Old P0–P5
closure and its deleted monitor stay unchanged.

This establishes the measured owned no-NIC browser path on that release. It is
not public egress, DNS/TLS/kernel-broker integration, a real-source I08 or O4
acceptance. Real target connections and real website script executions remain0.

### Pre-DNS admission, resolver and private broker data channel

The next unprivileged increment adds two ordinary modules and a trusted
resolver callback in the existing ledger. It is not connected to the CLI,
API, guest service or installed Root operator and promotes no Root release.

`admit_resolved` consumes the request slot and validates envelope, seed,
URL/method/resource and host policy before calling trusted resolver code.
Invalid envelopes/reentry close the session; DNS failures and refused answers
still consume the slot. At most eight names may be considered, including names
whose answers refuse. DNS facts are timestamped after the actual response, then
checked for age/TTL, public IPv4 pins and rebinding. A callback is trusted code,
never a page/RPC-supplied callable or an authority object. Existing `admit` and
the `close` statistics shape remain available.

`mail_browser_dns` provides a finite A/CNAME codec and explicit single connected
UDP exchange to numeric9.9.9.9:53, with a one-second ceiling and the enclosing
monotonic deadline. No OS resolver/search/proxy, retry or TCP fallback is used.
Packets are at most4096 bytes, with one matching question, up to16 answer rows,
bounded backward compression, finite CNAME chains and positive bounded TTL.
Wrong transaction/question/flags, truncation, unrelated/incomplete/duplicate or
mixed/special-address answers refuse. This is an observed recursive answer,
not DNSSEC validation or authentic origin. A future protected runtime must
first establish its fixed resolver kernel lease; importing the module or
passing tests does not authorize a public DNS query.

`browser_broker_wire` frames canonical JSON metadata (64KiB maximum) and a
separate digest-bound binary body (4MiB aggregate). A decoder binds nonce and
strict sequence,128 frames and8MiB wire bytes; declared oversize, duplicate or
noncanonical/nonfinite JSON, changed digests, replay and truncated EOF close it.
Requests cannot carry response bodies. Descriptors, peer identity, per-operation
field validation and Root approval must be established by the future runtime;
framing alone establishes none of them.

Tests cover admission before DNS, failed-lookup/name ceilings, timestamp and
reentry refusal, inert DNS/compression mutations, actual application offline
denial, maximum/fragmented binary frames and a harmless actual OS pipe. Owned
UDP loopback tests check transaction/truncation/private-answer refusals without
calling the public resolver. Owned TLS loopback tests verify the expected
certificate/hostname, wrong-host and untrusted-certificate refusal and ignored
caller CA/key-log environment. Their explicit test adapter maps one numeric
public-looking peer to an owned127.0.0.1 listener: it does not prove real pinning
or namespace confinement. No sample hostname is resolved and no browser or
Root job is started. Actual broker confinement, expiring kernel leases,
owner/guard/established-flow stop and full VM/PAW custody integration remain
O2/O3 work before real activation.
