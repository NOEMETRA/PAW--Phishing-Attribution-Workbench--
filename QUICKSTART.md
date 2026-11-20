# PAW quick start

PAW builds a local forensic case from an email. Start with an EML file and use an offline preset to inspect the message, its attachments and the evidence available locally.

## Install from source

On Linux or macOS with Python 3.11 or later, use a dedicated environment.

```bash
git clone https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--.git paw
cd paw
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
paw --help
```

On Windows, create the environment with `py -3 -m venv .venv` and activate it in PowerShell with `.\.venv\Scripts\Activate.ps1`. See the [installation validation record](docs/linux-r08-validation.md) for tested runtimes and component limitations.

## Analyze an email offline

Run PAW from a working directory where you want to keep the case. Replace `sample.eml` with the path to your message.

```bash
paw quick sample.eml
```

Use the strict review profile to include local report drafts.

```bash
paw full sample.eml --no-egress
```

Use the same offline policy for a directory of messages.

```bash
paw analyze inbox/ --profile strict --no-egress
```

Each invocation creates its own cases. The quick preset always uses the offline policy. Analyze, full, forensic and trace also default to offline. Keep `--no-egress` in development scripts to record intent. Their `--allow-egress` option permits enrichment and automatic URL detonation in an isolated environment. The offline policy skips URL detonation and network enrichment. See the [offline scope and isolation limits](README.md#offline-analysis---no-egress).

## Analyze offline in a Linux container

From a local checkout, point Compose at two existing directories. The input
directory is mounted read-only. The output directory must be writable by
UID 1000, the container's runtime user.

```bash
export PAW_INPUT_DIR=/absolute/path/to/originals
export PAW_OUTPUT_DIR=/absolute/path/to/case-output
docker compose -f compose.offline.yaml build
docker compose -f compose.offline.yaml run --rm paw full /input/sample.eml --no-egress
```

The build downloads the Python base image and dependencies. At runtime this
profile has no external network, drops capabilities and mounts the image
filesystem read-only. Cases are written under `PAW_OUTPUT_DIR/cases`.
`Dockerfile` and `docker-compose.yml` are the legacy encrypted-clicking
profile. Active browser and uplink acceptance are tracked in the
[S14 isolation protocol](docs/s14-controlled-uplink.md).

## Read and verify a case

PAW prints the path of the case it creates. Start with `report/executive.md`. Use `report/score.json` for the scoring profile, decision thresholds and component contributions, and `execution.json` for skipped stages. The score is an uncalibrated heuristic. An inconclusive result leaves the message’s legitimacy unresolved. Sender headers and candidate infrastructure require independent verification before attribution.

Use the actual case path in both commands below.

```bash
paw verify --case cases/CASE_DIRECTORY
paw export --case cases/CASE_DIRECTORY --format zip
```

Verification checks the local evidence inventory and file hashes. The ZIP contains case evidence, including the original email. Review its contents before sharing. Abuse reports are local drafts. STIX generation and canary deployment are currently unavailable.

See the [score explanations](docs/score-explanations.md) for interpretation and the [canary status](docs/canary-status.md) for the collector’s current scope.

For API indicator searches, POST a JSON object with `query_type` and `value` to
`/api/query`. Each page examines up to 100 indexed cases by default. Set
`limit` to 1–1000 to choose a page size. Pass the returned `next_after` as
`after` with the same query to continue until the cursor is null. A page may be
empty while a cursor is present when its cases have active workers.
