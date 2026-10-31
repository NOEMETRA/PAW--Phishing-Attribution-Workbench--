# Owned capture-backend experiment

This is an ordinary-UID experiment, outside the frozen privileged PAW broker.
It uses a readonly existing browser VM base, a disposable overlay, no NIC,
readonly dependency media and standard QEMU/systemd resource limits. No host
package, privilege, Root image, production source or score changes.

The finite comparison is PlaywrightCapture's public API versus the genuine
Lacus HTTP enqueue/result handlers, its LacusCore queue and a private Redis.
The three harmless fixtures cover HTTP JavaScript/DOM, an invalid HTTPS
certificate and a redirect. All servers are loopback **inside the guest**.
`only_global_lookup=False` is explicitly an owned-fixture setting, never
production public-address or rebinding acceptance. Upstream TLS/CSP/sandbox
defaults remain observable. Failed captures and missing artifacts stay visible.

Python dependencies, Chromium and Redis are prepared separately, hash-pinned
and supplied readonly. There is no guest package manager/network installer.
The host imports neither upstream capture engine and never visits a sample.
Use one bounded user PID1 unit:1536MiB, swap0,64 tasks,50%CPU,360s,
NoNewPrivileges, AF_UNIX only, IPAddressDeny=any and KillMode=control-group.
Each guest case has512MiB, swap0,256 tasks,15s and500ms stop. Before/after
image/media hashes, termination and external unit/cgroup readback are required.

Results are experimental observations, not an enrolled Root profile, actual
network egress acceptance, authentication evidence or classifier validation.
Application artifact ceilings are measured after capture; they do not prove
production byte/host/request caps during capture. The UID QEMU experiment does
not inherit libvirt's AppArmor evidence. No real email/target is an input.
The stock capture engine may fail PAW sandbox/TLS/CSP contracts even when its
capture succeeds. Reuse evaluation must preserve that distinction.
