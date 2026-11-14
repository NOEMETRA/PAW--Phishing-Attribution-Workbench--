# Handoff PAW — R08 su Windows

Aggiornato il 14 novembre 2026. **R08 è aperto.** Riprendere il collaudo del
pacchetto offline installato su Windows. Il collaudo nativo del browser e di
S14 resta sull'host Linux dell'altro agente.

## Punto di partenza

- Repo: [NOEMETRA/PAW](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--).
  Branch: `codex/windows-r08-acceptance`.
- Il branch con questo handoff parte da `47543dd639b52a4ee6386dd7ea4e853a0def582a`
  ([merge #196](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/196)),
  che era il `main` remoto al momento del passaggio. Prima di ripartire, verificare
  il `main` corrente e fissare lo SHA del candidato da collaudare.
- Il PASS Windows dell'8 novembre riguarda solo
  `6ac415717d72df25721a433f9bfa87e03f1dff81`
  ([merge #187](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/187)).
  Ricostruire e riprovare la wheel sul candidato scelto.

## Risultato già misurato

Windows x64, CPython standard **3.13.5**, ambiente virtuale senza pacchetti di
sistema, wheel non editable con tutte le 26 dipendenze base dichiarate.
`pip check` passato. Wheel `paw-2.0.0-py3-none-any.whl`, SHA-256
`9559082322ae21647ae6fdcf4798aa4c00b6c4e74fc7d27788e6c136ce126d2e`.
L'hash identifica quella build e non è un requisito per una nuova compilazione.

| Prova sul pacchetto installato | Esito |
| --- | --- |
| Import fuori dal clone, console e confronto dei file con la wheel | PASS, 136 file identici |
| `quick`, `analyze`, `full`, `forensic`, `trace` | PASS, un EML pubblico della repo, confronto per preset di score e decisioni, originali, sigilli e ZIP |
| Timeout CLI | PASS, esito `timed_out` e `tree_stopped: true` |
| API su `127.0.0.1`, worker offline, score/ZIP | PASS, coerenza con il preset CLI corrispondente e arresto confermato |
| Pulizia dei dati temporanei | PASS, sette controlli con `tree_stopped: true` prima della rimozione |

Il precedente [collaudo integrato Windows su PR84](integrated-execution-acceptance.md)
è evidenza storica per i test dal sorgente. Il [record Linux R08](linux-r08-validation.md)
descrive le piattaforme verificate e le condizioni per chiudere R08.

## Prossimi passi

1. Installare Python Windows x64 e ripetere la prova del pacchetto sul nuovo
   candidato con un ambiente pulito. Conservare SHA del commit, hash wheel,
   versione Python, freeze, `results.json` e `cleanup.json`. Iniziare con 3.13
   standard e dichiarare gli altri runtime come non misurati finché non provati.
2. Sullo stesso candidato, eseguire in serie i batch misti (EML valido e input
   respinti, inclusi MSG e malformati secondo il contratto), cancellazione API
   in coda e in esecuzione, crash del supervisore e recupero. Verificare
   conteggi, esiti parziali, originali, `tree_stopped` prima di sigillo/export,
   query/report e parità ZIP. Riutilizzare
   `tests/integration_engine_stress_real.py --suite batch`,
   `tests/integration_api_real.py` e `tests/integration_cli_api_real.py`.
   Questi script usano il **sorgente**: registrarli separatamente e coprire i
   percorsi residui anche dalla wheel prima di dichiararli accettati come installati.
   `integration_installed_cleanup_real.py` contiene un controllo di identità
   POSIX (PGID/SID). Per Windows verificare l'identità e l'arresto con il
   contratto Windows Job, senza rimuovere il controllo POSIX.
3. Registrare separatamente installazione, import e disponibilità effettiva
   dei componenti. Verificare `python-magic` con un buffer innocuo e riportare
   eventuale indisponibilità della libreria nativa. Controllare PGPy e la
   risoluzione dell'extra ML in ambiente separato, senza modificare dipendenze
   per ottenere un PASS. Conservare gli esiti espliciti per PGP, Rekor, MSG,
   STIX e funzionalità attive secondo i contratti esistenti.
4. Aggiungere un record PASS/FAIL/non misurato sul candidato esatto e aprire
   una PR con la review richiesta dall'utente per quella PR (ultima richiesta
   esplicita in questo filone: Codex). Riconciliare la chiusura con S13
   e i [contratti R01–R08](residual-consumer-contracts.md). Tenere separato
   il requisito S10 di corpus indipendente e holdout da ogni esito sui fixture.

## Riproduzione rapida su Windows

Da PowerShell nella root del clone, con una directory di lavoro esterna nuova.
Fermarsi se un comando fallisce e usare una nuova directory per ogni prova.
`py -3.13` seleziona Python standard, non `3.13t`.

```powershell
$repo = (Get-Location).Path
$sha = (git rev-parse HEAD).Trim()
$runs = Join-Path $env:LOCALAPPDATA ('paw-r08-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runs | Out-Null
Set-Content -LiteralPath (Join-Path $runs 'commit.txt') -Value $sha
py -3.13 -m venv (Join-Path $runs 'venv')
$python = Join-Path $runs 'venv\Scripts\python.exe'
& $python -I -m pip wheel --no-deps --wheel-dir (Join-Path $runs 'wheels') $repo
$wheel = Join-Path $runs 'wheels\paw-2.0.0-py3-none-any.whl'
Get-FileHash -LiteralPath $wheel -Algorithm SHA256
& $python -I -m pip install $wheel
& $python -I -m pip check
& $python -I -m pip freeze --all | Set-Content -LiteralPath (Join-Path $runs 'freeze.txt')
Push-Location $runs
try {
    & $python -I (Join-Path $repo 'tests\integration_installed_package_real.py') `
        --wheel $wheel --output (Join-Path $runs 'installed-results')
} finally {
    Pop-Location
}
```

Seguire [AGENTS.md](../AGENTS.md). Usare EML pubblici e fixture sintetici,
`--no-egress` (implicito per `quick`) e server di test su loopback.
Evitare URL, DNS dei campioni, esecuzione di allegati, Docker e provider live.
Il guard Python applica una policy di processo. Il collaudo Windows richiede
Python nativo e non dipende da Hyper-V, WSL o dal laboratorio Linux.

## Materiale locale prima della formattazione

Il riepilogo sopra è autosufficiente. Per conservare il confronto grezzo,
copiare su un supporto separato i file `commit.txt`, `freeze-313.txt`,
`wheel-build.log`, `install-313.log`, `acceptance-313.log` e
`results-313/{results,cleanup}.json` da
`C:\Users\dacan\Documents\Codex\2026-10-23\le\work\paw-r08-windows-6ac4157`.
I log possono contenere percorsi o dati di casi e restano fuori da Git.
Il clone Windows contiene anche uno stash Sentinel separato, «Prepared Sentinel
offline completion, separate from PR83». È fuori da questo handoff e va salvato
a parte prima della formattazione se serve recuperare quel lavoro.
