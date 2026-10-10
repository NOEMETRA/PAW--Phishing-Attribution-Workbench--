# Canary deployment status

Canary deployment is unavailable pending separate observation storage and the
isolated Linux lab. This is a deliberate rejection, not a simulated collection.
Offline `analyze`, `quick`, `full`, `forensic` and `trace` behavior is unchanged.

The legacy collector created a writable `canary` directory inside the selected
case. Its token handler appended `hits.jsonl` without case ownership or inventory
checks. On a newly completed, supervised `full --no-egress` regression case, an
actual token-handler call added that file and changed `verify_case` from true to
false. Original files remained unchanged, but the added file was not in the
sealed inventory. The reproduction substituted only the blocking server listener
and called the actual ASGI handler in memory under the offline policy; no port,
DNS lookup, external target, SMTP delivery or browser was used. The input was a
constructed integrity fixture, not an accuracy sample.

`paw canary --case CASE`, the importable `run_canary(CASE, port)` function and the
module/legacy launcher reject deployment before accessing case files or opening
sockets. The old automatic alert-email and interactive page handlers are removed
from the server module. Existing case observations and report readers are retained;
no evidence is modified, migrated or resealed.

`start_canary.py` is now an inert import and delegates explicit CLI arguments:

```text
python start_canary.py --case CASE --port 8787
```

This reports the unavailable status and exits nonzero. There is no hardcoded
working directory, default example case or interactive error pause. `paw canary
--help` and `paw help canary` describe the unavailable feature.

The regression runs an actual supervised offline analysis, then attempts each
canary entry point against completed, unsealed, blocked-owner metadata and missing
cases as well as absolute/traversal arguments. It checks nonzero rejection, unchanged case and job
bytes, preserved original MIME and valid seals. Imports and direct calls are
checked under the offline policy, with no attempted network or child-process
operations. The guarded CLI-dispatch checks bootstrap the common CLI first,
matching normal CLI startup. A cold `urllib3` dependency import probes local IPv6
socket support; the initial test blocked and identified that probe separately.
The dispatch assertions do not establish socket-free dependency imports.
This verifies rejection and evidence preservation; it does not
validate a live collector, a sandbox, detonation, Sentinel or attribution.
