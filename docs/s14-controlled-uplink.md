# Controlled real-link connectivity test

The user authorized the next objective on 24 October 2026: a controlled real
connection. This is a separate trusted connectivity probe, not activation of a
PAW worker, collector, browser or detonation path. The existing prepare-only
profile and closed gateway remain unchanged. No email resource is used.

`lab/s14/controlled_uplink.py` defaults to an owned local TLS fixture. Public
mode additionally requires `--authorize-public-one-get` and root-owned successful
local evidence for the success, guard-loss and owner-loss cases on the exact
current source inventory. Failed prerequisites cannot fall back to public mode.

The public scope is one `GET https://httpbingo.org/get`, with no query, user
data, credentials, cookies, redirects, retries, IPv6 or guest DNS. After the
verified disposable KVM image boots under empty guards, the host coordinator
queries its existing DNS resolver twice for this exact name, checks all observed
IPv4 addresses against the conservative public-address policy and requires
matching answer sets. CNAME/TTL records and admission times are retained. These
observations do not establish independent DNSSEC validation or domain ownership.

The trusted guest receives one numeric peer through its bounded serial channel,
connects directly to that IPv4 and verifies HTTPS using the exact hostname and
a copy of the host CA bundle. Request allowance is consumed before connecting.
The guest has a whole-request alarm of at most five seconds, an 8 KiB body
limit, a 24 KiB HTTP wire-read limit, no decoding and no redirect handling. It
returns bounded metadata and a body hash rather than rendering the response.
The host independently enforces the original monotonic kernel lease deadline,
revokes both sets immediately after the operation and bounds the post-boot job
to 30 seconds through the AUTODESTROY owner.

The VM has one vCPU, 512 MiB guest RAM, a 768 MiB/64-task/no-swap host scope,
AppArmor enforcement, non-root QEMU DAC, no host shares and a private TAP.
The existing aggregate 2 GiB lab budget remains in force. Host monitoring checks
policy structure, VM identity, captures, bridge ports and Wi-Fi binding; public
route checks must select the captured Wi-Fi/source address. A mismatch revokes
leases and expires ownership. Independent kernel expiry remains effective if
the coordinator dies. The physical Wi-Fi is never added to a bridge.

Temporary PAW tables, bridge and scoped DOCKER-USER extensions are restored only
after the identified domain/QEMU/TAP stop oracle. No persistent activation or
autostart is installed. An unconfirmed stop prevents successful publication;
failure retains evidence. Run only in a bounded PID1 systemd service, not the
desktop AppArmor scope. The operator supplies the output paths; the tool is not
a general privileged service or arbitrary target launcher.

Read-only reconciliation checks frozen source inventory, effective domain
confinement, restore/stop records, budgets, exact DNS/profile/peer bindings,
retry refusal and positive request/response packets. Public mode reconciles both
the bridge capture and a destination-filtered Wi-Fi capture showing host SNAT.
The destination-filtered capture is not a capture of all host traffic.

The source includes seven inert regression methods. Local KVM and public results
must be recorded separately; the presence of this code is not a passing run.
No full live worker/gateway/broker integration, hostile-code acceptance, corpus
accuracy, general collector acceptance or R08 closure follows from a successful
trusted GET. Real detonation remains outside the authorized scope.
