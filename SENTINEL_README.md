# Sentinel · Monitoraggio delle campagne

Sentinel associa una campagna a un caso PAW e conserva in SQLite osservazioni HTTP e avvisi. Per ricostruire le variazioni di una campagna già registrata, eseguire i comandi dalla directory che contiene la configurazione o il database Sentinel.

```bash
paw monitor list
paw monitor status
paw monitor history --campaign ID
```

Sostituire `ID` con l’identificativo della campagna. Lo stato riepiloga campagne e avvisi salvati. La cronologia legge in una transazione gli ultimi dieci controlli e gli ultimi dieci avvisi della campagna, anche dopo la rimozione dall’elenco attivo. Ciascun elenco è ordinato per ID decrescente. Un elenco vuoto indica che per quel tipo di record non ci sono osservazioni. Un identificativo sconosciuto o un archivio illeggibile produce un errore.

Nel JSON, `http_status` è il codice HTTP registrato. `content_hash` è il digest salvato, che può mancare. Un avviso `changed` emesso dal monitor indica una differenza tra contenuti confrontabili. Gli eventi `up` e `down` descrivono transizioni di classe HTTP. L’identità dell’operatore e le cause del cambiamento richiedono altre evidenze. I due elenchi hanno una numerazione indipendente.

Per controllare i casi locali a elaborazione conclusa:

```bash
paw monitor integrity
paw monitor files
```

Il primo comando verifica l’integrità locale. La prima scansione di `files` stabilisce il riferimento del processo corrente. Avviare il comando una seconda volta crea un nuovo riferimento.

## Stato operativo

La raccolta HTTP manuale e il controller Python hanno collaudi su servizi di prova locali. La CLI di consultazione funziona sul database fermo e leggibile. Su Linux il comando `run` rimane in primo piano e riceve SIGINT o SIGTERM dal terminale o dal supervisore. Screenshot, notifiche esterne e impiego su infrastrutture reali hanno criteri di accettazione separati. Gli avvisi locali sono consultabili nello storico.

[Contratti verificati del modulo](docs/sentinel-module-audit.md) · [Stato del controllo di servizio](docs/sentinel-cli-lifecycle.md)

## Collaudo Linux con egress privato

Il collaudo usa due namespace collegati da una coppia veth. Il peer ospita DNS, HTTP e HTTPS; entrambe le estremità hanno soltanto una rotta locale. Il certificato della fixture è valido per `sentinel.test`. Dopo tre osservazioni e un redirect, il test verifica gli errori DNS e TLS, il rifiuto del firewall e il recupero del collegamento. Verifica anche il TTL osservato dal modulo DNS di PAW e il comportamento offline del comando `full` con il peer raggiungibile.

Dalla radice del checkout, indicare il Python di un ambiente virtuale con la wheel corrente installata e una nuova directory per le evidenze.

```bash
bash tests/integration_sentinel_private_link.sh /percorso/venv/bin/python /percorso/nuovo-esito
```

Il test richiede Linux con namespace utente e di rete, iproute2, nftables, OpenSSL, util-linux e sysctl. La directory dei risultati conserva eventi ricevuti, storico SQLite, traccia del contatore firewall e risultato DNS. La prova su uplink pubblico ha un profilo separato nel [protocollo S14](docs/s14-controlled-uplink.md).

## Monitor continuativo di laboratorio

Dalla directory della configurazione e dell’archivio locale già inizializzato,
con la propria fixture HTTP in ascolto e una campagna registrata:

```bash
paw monitor run --origin http://127.0.0.1:8080
```

Ripetere `--origin` per ciascuna origine di laboratorio di proprietà. Il comando
accetta indirizzi IP letterali di loopback, privati o dei prefissi riservati alla
documentazione. Tutte le campagne attive devono usare le origini indicate.
Un lock del kernel sul file SQLite ammette una sola istanza di `run` per archivio
su filesystem locale. Il processo registra eventi JSON su stdout. Per fermarlo,
usare Ctrl+C o il SIGTERM del supervisore e attendere l’uscita. Il processo
emette `stopped` dopo la fine del controller e dei worker. L’evento
`alert_committed` contiene gli ID di campagna, avviso e controllo di origine.
`external_delivery: not_attempted` indica che il processo ha salvato
l’avviso localmente. Nessuna conferma di consegna è disponibile.

Al riavvio il primo controllo usa il precedente ID salvato per la stessa campagna.
I cicli persi durante un fermo rimangono lacune temporali. Un arresto durante
il controllo può lasciare una richiesta visibile al peer senza una nuova riga
nel database. La cronologia può essere consultata tra le scritture; la presenza
di un journal pendente o di un archivio occupato può richiedere un nuovo tentativo.

Nella sezione `storage` di `sentinel_config.json`, `retain_http_bodies: false`
omette il corpo dai nuovi controlli mantenendo metadati e digest. Il default è
`true`. I corpi già salvati scadono insieme alle rispettive osservazioni.

Il processo in primo piano applica la scadenza automatica solo con
`automatic_retention: true`, all’inizio del primo ciclo e poi al primo ciclo
dopo 24 ore. `retention_days` stabilisce la durata delle osservazioni
(default 90 giorni). `alert_retention_days` stabilisce quella degli avvisi,
inclusi quelli da riconoscere (default uguale alle osservazioni). Entrambe le
durate esplicite richiedono giorni interi positivi. L’evento `retention` riporta
le due soglie UTC, le righe eliminate e il numero di date non interpretabili
conservate. La scadenza riguarda i record SQLite e lascia intatti i casi EML.
