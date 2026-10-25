# Separate offline HTML browser profile

The owner requires browser validation before the first real email test. The real
MIME is held privately and is not a fixture or committed artifact. This profile
is **not yet accepted**: code, preparation and controlled runtime acceptance are
distinct. The established Python ingress and its existing budgets stay separate.

## Trusted image preparation

The host downloads packages only; no browser package is installed on this PC.
An isolated non-root APT configuration uses Ubuntu Noble/main/universe/updates/
security and the official stable Chrome repository. Before root approval, the
administrator verifies vendor signatures, signed uncompressed Packages hashes
and every downloaded .deb hash. The exact canonical verified-manifest SHA is
then explicitly approved for the root builder. A manifest's own assertions are
not authority: the root operator is trusted to perform that external verification
before supplying its approved digest, just as for the existing I08 receipt.

The [Google signing-key reference](https://www.google.com/linuxrepositories/)
identifies the active primary fingerprint
`EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796`. The initial local download contains
197 packages (246343012 bytes), reconciled through seven signed package indices;
it is only preparation, not proof of an installed guest.

`browser_image.py --manifest VERIFIED --expected-sha256 APPROVED --export AUDIT`
is an explicit root PID1 operation. It never mounts a guest filesystem or runs a
package installer on the host. It checks exact package bytes while streaming
them into protected staging, creates a read-only package ISO and installs only
those local packages in a preparation VM with no NIC. The original signed Ubuntu
base remains root-owned0444 and byte-identical. The derived browser image and
its local root certificate are published only after provisioning, an owned
JavaScript/title probe, actual non-root renderer/NNP/seccomp/PID-namespace checks,
guest sync/shutdown, independently known VM stop and host/context restoration.
The custom image is locally derived, not vendor-signed or remotely attested.
Existing images/certificates are never overwritten by this command.

The new guest retains the normal Chrome sandbox. The official Ubuntu Chrome
AppArmor user-namespace profile is loaded at its standard executable path, as
described in the [Ubuntu release notes](https://documentation.ubuntu.com/release-notes/24.04/)
and [Chromium documentation](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).
No sandbox-bypass or web-security-disable flags are used; no global host or guest
user-namespace restriction is disabled. Only owned probe HTML/JavaScript runs
during image construction. Package installation and image preparation do not
admit a real email attachment.

## Proposed resource and host boundary

The separate VM uses1vCPU,1GiB guest RAM, QEMU1536MiB/64tasks/CPU50%/zero swap,
inside the existing2GiB/128tasks/zero-swap aggregate slice. No NIC, filesystem
share, host device, vsock, graphics or USB is admitted. Memory merging, PMU,
VMware I/O port, AVX/XSAVE and nested VMX/SVM are disabled. The actual QEMU
executable, non-root DAC, AppArmor enforce, seccomp, cgroup limits and XML are
checked while paused before resume. A root-owned libvirt AUTODESTROY connection
closes on owner/controller loss, heartbeat/guard/limit/clock change or deadline.
Known external stop remains mandatory; the existing12s stop bound is unchanged.

Image preparation has a separate bounded1200s lifetime and2GiB per-file cap to
install trusted packages. Runtime proposes360s maximum VM life,256MiB overlay
cap, and a512MiB/128-task guest browser job. These values require actual harmless
validation; the image preparation phase is not evidence for runtime fault or
untrusted-input acceptance. The no-NIC image masks guest network wait-online,
SSH and automatic APT timers; no host service, Wi-Fi or firewall rule is changed.

## Reproduced temporary-input privacy defect

After the owned PR109 run, UID1000 could open its root-owned0444 seed ISO and
root-owned0644 user-data through the0755 run folder and recover the exact owned
source bytes. No real sample had been used. This reproduced a confidentiality
gap for future noncatalogue sources, distinct from the already-private exports.
The hash adapter now makes its per-VM folder root:QEMU0750, seed root:QEMU0440
and plaintext seed files root:root0600; the QEMU-owned overlay remains0600.
The change is covered by actual-mode inert role tests and requires fresh runtime
admission proof before real input. Historical bytes/archives remain untouched.
Runtime browser input media must also be root:QEMU0440 in a root:QEMU0750 folder.

## Remaining acceptance

Inert unit tests do not execute Chrome, install packages or start a VM. Review
and CI must precede the trusted preparation service. Actual image provisioning,
the bounded HTML operator/one-use authority and case request/import contract,
harmless render/sandbox/failure/replay/stop/reset acceptance, effective I08,
final review/CI and an owned end-to-end smoke remain required before real HTML.
No TCP debugging server, input-selected URL/arguments, host browser rendering,
credential entry, form submission or real egress is authorized by this code.
Ordinary PAW analysis will not launch a privileged job automatically.

## Preparation review corrections

The first review reproduced three issues before any preparation VM was started.
Limit monitoring now resolves the actual systemd scope ancestor when libvirt
places QEMU in its threaded `libvirt/emulator` subgroup. Publication requires a
libvirt STOPPED/SHUTDOWN lifecycle event and a successful owner result; mere
process absence or a shutdown acknowledgement cannot promote an overlay after
owner-triggered destruction. CI's symlink refusal test also substitutes the QEMU
account lookup, so inert tests require no host libvirt account or provisioning.
The original failed CI and review remain historical; new exact-head review/CI
and actual preparation/runtime evidence are still required.

## First local preparation attempts

The first native service refused historical root:root0775 image/run directories
before creating a VM. The administrator tightened only those two fixed paths to
0755; the strict authority-storage predicate was retained. The second attempt
started a real1GiB no-NIC KVM guest with the declared1536MiB/64task/CPU50%/zero
swap QEMU controls, AppArmor enforce, seccomp and memory merging disabled.
Guest APT installation failed before the Chrome probe; the controller confirmed
external stop in0.9992s, no remaining QEMU/domain/namespace, unchanged foundation
hash and host guard, and no published browser image. This is a failed preparation,
not browser acceptance. The next diagnostic change reports only the last3000
bytes and exit status of the trusted guest installation log through the existing
bounded channel. No host guest-filesystem mount or real attachment is involved.
