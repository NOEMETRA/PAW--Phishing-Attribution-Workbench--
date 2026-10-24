# S14 Wi-Fi uplink preparation and exact target admission

24 October 2026. Follow-up to the measured [closed profile and cold boot](s14-gateway-validation.md).
The user selected the existing Wi-Fi with filtered routing and delegated choice
of a benign public domain. This change **prepares disabled configuration**;
it does not enable the old gateway's live transport, change PAW collectors,
visit email resources, execute attachments, start Docker or authorize detonation.

## Prepared configuration

`lab/s14/prepare_uplink.py --output <new-private-directory>` reads the current
interface, MAC, source IPv4, next hop, NetworkManager connection UUID and AP
BSSID. It writes a disabled profile, two independent timed inet guards, a pinned
bridge guard, an IPv4 NAT table, scoped DOCKER-USER command arguments, external
bridge XML, a profile hash and explicit readiness blockers. It performs no DNS
query, opens no target connection and installs no rule, bridge or network.
Actual local network identifiers remain outside Git.

The proposed path is worker -> trusted gateway -> host-owned point-to-point
bridge -> host routing/NAT -> the selected Wi-Fi. The host link is
`198.18.41.1/30`, gateway `198.18.41.2`, with pinned TAP and MAC. The physical
Wi-Fi is never added to a bridge. This uses the routed/NAT approach described by
[libvirt](https://wiki.libvirt.org/Networking.html), whose networking guide
explains why a wireless station interface cannot be used as a normal host bridge.

Both inet guards require the correct input/output interface, gateway source,
approved IPv4/TCP port tuple and current timed element in **both directions**.
There is no broad established/related exception. IPv6, alternate transport,
fragments, private/special prefixes, host input and host-originated output toward
the gateway are denied. Bridge rules pin ingress TAP/MAC/IP/ARP and prohibit L2
forwarding between ports. NAT is separate from filtering: later packets use
the established translation, so revocation must act in the forwarding guards,
not just NAT. See the [nftables NAT documentation](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29).

The observed host uses iptables-nft and DOCKER-USER. The proposal adds only two
interface/source-scoped user extensions, after independent PAW filtering; it does
not replace a Docker-managed chain or change its default policy. This follows
[Docker's documented user extension](https://docs.docker.com/engine/network/firewall-iptables/).
Other firewall backends or policy changes require fresh acceptance. An nft
ACCEPT is not an override for a later base-chain DROP, as documented in
[nftables chain ordering](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).

## Candidate target and admission

The chosen candidate is exactly **`https://httpbingo.org/get`**, GET only, TCP
443, no query, credentials, cookies, submitted user data, subresources or
redirects. The [go-httpbin project](https://github.com/mccutchen/go-httpbin)
documents httpbingo.org as its public HTTP-testing instance. This is a public
read-only testing scope selected under the user's delegation, not a claim that
the user owns the domain or that any response establishes attribution.

The candidate's address pins are deliberately empty. Neither the preparer nor
the validators contact or resolve the public service. A future trusted
coordinator must obtain fresh DNS observations and reviewed public IPv4 pins
before admission; missing pins, mixed/unapproved addresses, stale observations,
wrong exact URL or changed network binding refuse. IPv4 special-prefix denial
is explicit and conservative rather than dependent on maintenance-version
`is_global` behavior. IPv6/mapped/alternate numeric address forms refuse.

Admitted plans bind the profile hash, exact target/URL, peer, TLS hostname,
authorization reference, current boot and monotonic deadline. Compilation rejects
expired/prior-boot plans and never grants their original lifetime again after a
delay. Kernel leases have at most five seconds for this initial profile; no
packet-path update renews them. [nftables timed elements](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts)
provide the independent expiry. The controller must compile/apply immediately,
within the original deadline; generated rule text is not an authentication token.
The caller remains trusted and the supplied authorization/DNS data is not
independent ownership or DNSSEC verification.

The proposed application budgets are one request, 8 KiB response, 30 seconds
per job and zero redirects. These fields are structurally validated here;
enforcement by a supported live broker/coordinator remains separate integration
work. This preparer is not an operational launcher or a browser.

## Measured validation

- Eight inert admission methods cover disabled/malformed profiles, public vs
  special IPv4, exact URL scope, mixed/rebound/stale DNS observations, forged
  plans, network drift and delayed/prior-boot plan rejection. No DNS/socket
  operation occurs in these tests.
- Sixteen actual kernel scenarios run in three disconnected namespaces with
  only loopback, veth and bridge interfaces. They reproduce a FORWARD DROP before
  scoped DOCKER-USER integration; check positive TLS/SNAT, forbidden addresses,
  ports, DNS/UDP/QUIC, forced private tuples, source spoofing and alternate
  routes; reject four empty/absent guard admissions; and stop established TLS
  on lease expiry, revocation and issuer SIGKILL. Peers stay alive during the
  no-progress observations. Host nft/route/interface snapshots match before and
  after, and all temporary writers/namespaces are stopped/removed.
- The exact Wi-Fi rule files also pass host `nft --check`. No live rule is
  installed. Candidate files and catalog are hashed in the measured preflight;
  independent reconciliation rejects later substitutions.
- A trusted disposable KVM probe then exercises the actual host bridge,
  forwarding, scoped DOCKER-USER extensions and NAT into an owned namespace.
  Its only admitted address is the benchmark fixture `198.18.43.10:443`.
  The guest uses the existing verified base, one vCPU/512 MiB, enforcing AppArmor,
  non-root DAC and bounded cgroup; it has no host shares. Empty leases deny;
  TLS/GET through SNAT succeeds; expiry/revoke stop an established response;
  owner SIGKILL triggers AUTODESTROY and a domain/PID/TAP stop oracle. All scoped
  test rules, routes, interfaces and extensions are restored afterward.
- The first host-side capture contained host-originated mDNS/IGMP on the new
  test veth. Independent reconciliation rejected it. Emulation now also drops
  host-originated output on its owned egress veth; production Wi-Fi output and
  host discovery services are unchanged. The final namespace/KVM repeat passes on 35 frozen sources. Independent
  reconciliation verifies 151 namespace and 124 KVM-uplink packets; the KVM
  owner-loss stop oracle takes 0.471 s. Both host networking snapshots restore
  exactly. Five catalog/policy/source/packet/writer tamper probes reject. Earlier
  results and failed reconciliations are retained.

The old closed gateway, `paw/`, scoring, originals and prior seals are unchanged.
CI compiles the inert tools and runs admission tests; it does not create network
namespaces, privileged rules or VMs. Exact results, packet counts and head CI are
recorded in the stacked uplink PR and the local evidence bundle.

## Finite remaining activation work

The profile remains **PREPARED_NOT_ACTIVE**, with no real pins and no supported
live activation command. Before live use: integrate the supported coordinator
and guest transport with these admission/deadline contracts; obtain fresh
reviewed address bindings for the chosen exact endpoint; validate the actual
Wi-Fi forwarding path and its route/BSSID/version changes; then perform the
separately authorized single benign GET. No public service connection is
claimed here. This does not reopen consolidated offline engine audits or close
R08, broad collector/browser or hostile-code acceptance.

Two other reproduced preparation defects were corrected before the final pair:
a delayed plan could regain its original lifetime, and the evidence reader did
not bind the prepared catalog to the measured preflight. Plans now carry a boot
identifier and monotonic deadline, and measured hashes cover the profile plus
all seven generated files. Previous evidence is not edited or relabelled.

### Review correction: positive capture evidence

Review reproduced a KVM reconciliation defect: replacing the capture with its
24-byte header, or with ARP alone, still passed. The reader now also requires
TCP/443 traffic from the expected SNAT address to the fixture and a response
in the reverse direction. Six offline regression methods exercise the complete
reader with empty, ARP-only, one-direction, wrong-direction, foreign-address
and valid bidirectional captures; CI includes them. The stricter reader accepts
the original 124-packet KVM evidence without changing its frozen source files
or rerunning a VM. This is a post-run reader correction, not a new kernel or
physical Wi-Fi measurement; historical archives remain unchanged.
