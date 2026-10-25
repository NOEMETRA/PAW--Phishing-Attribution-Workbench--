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
cap, and a512MiB/256-task guest browser job. These values require actual harmless
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

The diagnostic repeat reproduced the cause: APT removed six guest packages
before failing with `Pathname to install is not absolute` for the local
ca-certificates upgrade. Its plan also upgraded GLib from2.80.0-6ubuntu3.9 to
3.10 without the matching `gir1.2-glib-2.0` companion. The signed Noble index
declares an exact GLib dependency for that GIR package; the missing candidate
caused the GIR/Python-GI/apport/cloud-minimal removal chain. The replacement
manifest adds only that matching package (198 total); signatures, seven signed
index hashes and all198 blobs were independently reconciled, with no host
package changes. Historical197-package manifests and failed overlays remain
unchanged. The canonical replacement manifest SHA256 is
`ea06c2f2b01c0f8537ccd92820e2e114a7f523d1d355daa1cc91d6683b8e1f83`.

Preparation now copies and rechecks each approved archive into the guest's
fixed absolute APT cache before invoking APT, retains `--no-download`, and adds
`--no-remove`. Relative/mismatched cached paths and altered/symlinked cache
entries are refused in inert regression tests. The actual replacement guest
installation and Chrome sandbox probe are still pending review/CI and a new
native preparation run; no image or browser input has been accepted yet.

The corrected198-package installation completed and its installed versions were
checked in the next real guest. The owned Chrome probe then failed with renderer
`pthread_create` refusals at the proposed128-task job ceiling. No image was
published; the external stop took1.0092s and the host base/guards remained intact.
This identifies a real thread-creation failure, but its resource cause must be
measured rather than inferred from the stderr message alone.

The next preparation proposes a256-task ceiling only for the guest Chrome
cgroup. Guest RAM1GiB, browser RAM512MiB, QEMU1536MiB/64tasks/CPU50%, host
aggregate2GiB/128tasks and zero swap stay fixed. It first calibrates the owned
probe at128 tasks and records effective limits, PID/memory event counters and
peaks. A failing calibration is tolerated solely as diagnostic data if the PID
controller actually refused tasks and no guest OOM occurred; it is never an
accepted browser result. Other failures stop preparation. A fresh256-task probe
must then independently pass title execution and every renderer sandbox check
before normal shutdown/publication can proceed. Both probe process groups are
externally confirmed empty inside the guest and their temporary profiles removed
between trials. No arbitrary input, sandbox bypass or unlimited budget is added.

Review reproduced a mixed-counter calibration defect before any trial of this
change: PID refusal plus `oom 0` and `oom_kill 1` was incorrectly tolerated.
The [kernel counter contract](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files)
distinguishes cgroup OOM attempts from kills by an OOM killer. Calibration now
requires present, zero `oom`, `oom_kill` and `oom_group_kill` counters; missing
or nonzero counters refuse. The final probe also requires zero PID refusals
and zero OOM counters even if Chrome returned zero and produced the owned title.
Mixed/global/group OOM and missing-counter regressions are inert; no runtime
acceptance is inferred from them.

The first actual128/256 calibration reached a256-task peak of141 and a browser
memory peak of206344192 bytes, with no PID refusals or OOM events at256. Chrome
returned zero and emitted140 DOM bytes, but the aggregate renderer-seccomp flag
was false, so preparation correctly refused publication and stopped the VM
in0.9966s. Other recorded flags were nonroot UID, NNP and separate PID namespace.
These facts do not establish that the seccomp filter was active.

The old observer permanently combined every startup sample with boolean AND;
an inert0→2 sequence therefore stayed false even after filtering was observed.
The replacement records each renderer by PID/start-time identity and exact
argv token. Every observed renderer must itself reach and end at seccomp2,
with NNP, nonroot IDs and its PID namespace; regressions and unsafe filtered
snapshots remain permanent refusals. One filtered renderer cannot lend its
witness to another renderer or a reused PID. Startup modes are retained in the
diagnostics, identity tracking is bounded, and the same helper is seeded for
preparation and the future runtime profile. A new actual trace must distinguish
a startup observation artifact from a renderer that never becomes filtered;
the latter still refuses. No Chrome sandbox switch, host/guest sysctl or
acceptance requirement is disabled by this measurement change.
