# S14: verified image, bounded guest, owned traffic and failure fixtures

Current follow-up: [closed gateway and target admission](s14-gateway-validation.md),
including corrected supervision, a 2 GiB aggregate budget and the still-open gate.
The measurements below retain their historical profile.

24 October 2026. Follow-up to the [single-PC preparation](s14-single-pc-linux.md).
The owner authorized a trusted Linux image, tighter process budgets and benign
traffic/failure tests, with no real egress or detonation. **The bounded matrix
below passes; the complete S14 isolation/collector gate remains open.** No
production PAW source, scoring, original mailbox or sealed case was changed.

## Image admission and disk ownership

The vendor base is Ubuntu Minimal 24.04 amd64, pinned to
[release-20261017](https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261017/).
Its 259,981,312 bytes have SHA-256
`b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658`.
[fetch_trusted_image.py](../lab/s14/fetch_trusted_image.py) first verifies the
detached SHA256SUMS signature using the already installed Ubuntu cloud-image
keyring, then downloads/verifies the selected image and checks its qcow2 metadata.
An offline one-byte manifest-tampering probe was rejected by gpgv. This binds the
bytes to the admitted vendor release; it is not a malware-safety attestation.

The staged base is root-owned, mode 0444. Every run gets a fresh qcow2 overlay;
the host never mounts or parses the guest filesystem. A second writer's
`qemu-img check -r all` is refused by QEMU's image lock while the first VM is
still paused. The guest receives only its overlay and a read-only NoCloud seed
on virtio. There is no host filesystem, agent, clipboard, USB passthrough or
credential sharing. The fixed serial agent is supplied by that seed.

A reproduced preparation mismatch showed libvirt's automatic DAC ownership
changing the base owner to the QEMU user without changing its bytes. The
validator uses a static DAC identity with `relabel='no'` alongside dynamic
AppArmor. It restores only the identified read-only, hash-matching preparation
base when no domains exist, then requires its root ownership, nonwritability
and vendor hash to remain intact after every run. The passing matrix preserves
all three invariants. The initial SATA seed was not admitted by the first guest
bootstrap; a read-only virtio seed and explicit NoCloud SMBIOS selection are
used in the passing runs. The underlying cause of the initial seed discovery
failure is not independently established.
[Libvirt security labels](https://libvirt.org/formatdomain.html#security-label),
[cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html).

## Actual process and memory budgets

[machine-paws14.slice](../lab/s14/machine-paws14.slice) limits the entire lab to
128 tasks, 1,280 MiB resident memory, zero swap and one CPU worth of time. Each
QEMU scope is limited to 64 tasks, 768 MiB memory, zero swap and 75% CPU before
resuming its one-vCPU / 512 MiB guest. Each fixed guest-agent service has 32 tasks,
128 MiB memory and 50% of a guest CPU. Fixture scopes have 32 tasks / 128 MiB.
The trusted supervisor runs as a bounded transient systemd service, with
64 tasks, 384 MiB memory and a 900-second maximum runtime.

Actual kernel task enforcement is tested, rather than inferred only from XML:
[host_task_budget_probe.py](../lab/s14/host_task_budget_probe.py), under a separate
16-task user service, creates 15 children, gets its next fork refused, and reaps
them all. The guest's corresponding bounded fork probe also reaches its actual
32-task service limit and stops all created children.

The guest's QEMU UID is non-root and its per-domain AppArmor label is in enforce
mode. The trusted supervisor is launched by systemd, outside the desktop app's
AppArmor profile. A direct invocation through the desktop profile had been unable
to signal the confined tcpdump process, masking its original timeout during
cleanup. That failed attempt and a PID-checked systemd recovery are retained;
the harness now refuses that launch context and preserves cleanup failures.
No app, capture or QEMU AppArmor profile was disabled or weakened.

Tcpdump opens a privileged capture handle, drops to its dedicated account and
writes through a pre-opened descriptor. A reproduced private-directory open
failure is thereby avoided without granting it directory access. File output is
limited to 8 MiB; PCAP snaplen is 192 bytes, so full packet payload preservation
is not claimed. Serial input/output is bounded to 8 KiB control frames, 64 KiB
lines and 2 MiB total received bytes.

## Owned topology and measured traffic

[benign_guest_validation.py](../lab/s14/benign_guest_validation.py) accepts no URL,
domain, attachment or arbitrary shell command. The
[guest agent](../lab/s14/guest_agent.py) has fixed operations and fixture endpoints.
Its route table has no default route or DHCP resolver; only the owned canaries
have explicit off-link routes. Application endpoint admission is not an OS
sandbox and is not claimed to validate a production proxy/resolver.

The VM has one NIC on `pawbr-int`. The peer listener is in a host-created network
namespace on that private bridge; it has forwarding disabled and no uplink.
The forbidden LAN listener is in another namespace on a synthetic veth segment.
The host listener binds an owned loopback alias. No ordinary LAN device is
scanned and no lab target or gateway is placed on the physical Wi-Fi link.
These namespaces are trusted test fixtures, **not an implemented gateway VM**.

| Actual guest attempt | Independent result |
| --- | --- |
| HTTP to 192.0.2.10:18080 and DNS to 192.0.2.10:5353 | PASS: the peer received the requests and the guest received the fixed responses. DNS is answered locally; no upstream query is made. |
| TCP to host 198.18.0.1:18081 | PASS denial: a SYN is captured; the live host canary receives only its preceding host-side positive control. |
| TCP and UDP/DNS to synthetic LAN 198.18.1.2 | PASS denial: both attempts are captured; the LAN canary receives only its preceding host-side TCP positive control and no UDP. |
| TCP to owned host/LAN IPv6 canaries | PASS denial for those paths: both attempts are captured, with no canary request. Host IPv6 is disabled on the private bridge. IPv6 guest-to-peer traffic is not covered. |
| Three raw frames with forged source IP and MAC to the host canary | PASS denial: frames are captured, no host UDP request arrives. This does not establish complete L2 anti-spoofing between peers. |
| Unadmitted fixture hostname | PASS application rejection before socket creation; no DNS lookup is substituted. |

The independent reader finds 36 packets in the normal traffic capture, including
each listed attempt. Host and LAN logs each contain exactly one TCP request from
the host positive control and zero UDP requests. The allowed peer records five
TCP connections, one DNS request and four established-stream starts over the
whole matrix. There is no actual public destination in this traffic matrix.

## Failure, reset and evidence results

Every VM is transient and created paused with libvirt `AUTODESTROY`. The owner
connection is held by a separate supervisor child. The hypervisor therefore
destroys the domain if that process is killed or loses its connection. The
supervisor also monitors the exact effective guard, identified capture/fixture
processes and its expiry. Its own parent-death signal closes that owner on
outer-controller loss. Unknown stop prevents stable evidence inventory/export.
[Libvirt create flags](https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainCreateFlags).

| Measured test | Result |
| --- | --- |
| Effective guard empty / absent, before launch | PASS: actual child admission refuses each condition; no domain is created. Only the PAW-owned table is temporarily changed, with no VM active, and restored. The checker verifies hooks, priority and all four drop expressions, not just a service-active flag or a rule count. |
| Normal traffic / guest process budget / marker | PASS, completed run. |
| Capture process loss with an active stream | PASS, interrupted run; domain, QEMU and TAP disappear in 0.491 s after trigger. |
| Supervisor SIGKILL with an active stream | PASS, interrupted run; owner exit -9 and independent libvirt destruction, 0.363 s. |
| Expiry with an active stream | PASS, interrupted run; 1.553 s from trigger, including the configured one-second delay before expiry. |
| Peer fixture process loss with an active stream | PASS, interrupted run; 0.384 s. |
| Five fresh overlays / original base | PASS: all initial marker observations are absent; the normal run's marker is written/synced; the vendor hash, root ownership and read-only mode remain unchanged after each run. |
| Final teardown | PASS: all guest/capture/listener writers stopped; guest TAPs, synthetic veths/namespaces and host aliases removed. The private bridge and guard remain, without an active guest. |

The stopped oracle requires the domain absent, its identified QEMU process gone
and the TAP absent. It establishes loss of the guest packet source; it does not
assert an immediate receiver-side TCP timeout or FIN for a powered-off guest.
The short latencies are observations on this host, not universal response-time
guarantees. Lab cgroup peaks observed across preparation/replays were about
512 MiB and 39 tasks; browser or concurrent gateway capacity is not established.

The whole fixture matrix passes with **one completed and four explicitly
interrupted runs**, plus two rejected admissions. Sixty host-created evidence
files are inventoried only after the known writers stop.
[verify_benign_evidence.py](../lab/s14/verify_benign_evidence.py) independently
reconciles hashes/membership, effective budgets, domain identities, failure
reasons, packet attempts and listener counts without extracting an archive or
mounting a guest filesystem. Altering one XML member and recomputing its ZIP CRC
is rejected by the inventory digest. This is internal integrity and bounded test
reconciliation, not a report signature, content authenticity or PAW seal.

## Reproduction boundary and remaining gate

Use a prepared Ubuntu/AppArmor/libvirt host and the verified base at
`/var/lib/libvirt/images/paw-s14/base/`. Install genisoimage/python3-libvirt and
the lab slice through ordinary administrator authentication. Run only one matrix
at a time in a bounded systemd **service**, with `/usr/bin/python3 -I`; do not
invoke the privileged harness directly from a confined desktop process. Its
output directory must be new. Keep the original PAW host path `--no-egress`.
The validation source and evidence hashes are retained with the private run.
CI compiles these inert tools and checks the offline PAW regressions; it does
not run a guest or certify this physical host's isolation.

The complete I02–I08 gate is still open: actual management/LAN topology,
complete L2 spoof/fragment/tunnel/IPv6 coverage, an independently filtered gateway
VM/uplink, production resolver/proxy target admission, redirect/rebinding,
active guard removal, daemon/capture/storage/clock failure combinations,
whole-host reboot/startup ordering, guest-output quarantine and networkless
extraction remain unvalidated or unimplemented. No arbitrary guest attachment
execution, real egress or detonation is enabled by these tests. R08 and the
separate provider/browser/attribution contracts retain their previous limits.
