# Sentinel CLI service control

`monitor run --origin ORIGIN` is the Linux foreground entry point for owned laboratory origins. Its installed CLI integration verifies signal shutdown during HTTP, per-database process exclusion, restart continuity and retained evidence. See [the operating guide](../SENTINEL_README.md).

The existing `monitor start` and `monitor stop` actions are explicitly unavailable.
They exit nonzero before importing Sentinel, loading configuration, opening or
initializing a database, creating a thread, or invoking a collector. Optional
campaign/case/URL arguments do not enable them. No stored evidence is modified.
Parser help, `paw help monitor` and general help describe this boundary.

The previous start command created an in-process daemon monitor thread, printed
success and then exited. It did not establish a persistent service. The stop
command constructed a new monitor with a false local running flag, stopped that
new instance and printed success without identifying or controlling a running
service. Both created a fresh database on an empty working directory. Actual
cold CLI processes on empty storage reproduced these behaviors without a target
request under the Python offline guard.

The fix removes these false service-success paths without adding a daemon,
process registry, IPC endpoint or an unverified stop-by-PID mechanism. The
in-process `SentinelMonitor` methods remain unchanged; they are not established
cross-process controls. This disposition does not validate their shutdown,
request/screenshot containment, transition alerts or worker behavior. Those
active lifecycle/collection checks remain S14 work after isolation assessment.
Stored `list`/`status` keep their separately tested passive contracts, including
unknown service state. Other management and local integrity command admission
remains separate S11 work.

`integration_sentinel_lifecycle_real.py` exercises 19 actual cold CLI processes:
start and stop with missing/default/configured, saved active, legacy, corrupt and
pending-journal storage, malformed configuration and a configuration directory,
plus three help surfaces. It checks nonzero rejection, absence of a Sentinel
import or new thread, zero blocked operations and byte-for-byte source-tree
preservation. This is guarded dispatch after normal CLI bootstrap (a cold
urllib3 import probes a local IPv6 socket), not a cold-import no-egress or OS
isolation attestation. No sample URL is accessed and no ongoing service is
started or signalled by this check.
