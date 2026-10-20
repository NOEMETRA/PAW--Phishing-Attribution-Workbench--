# Stato dell'audit PAW

Riferimento integrato: PR80, commit
`0c4cca06262872bd5b85dfd0235d01bb07566c45`, 20 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi e tre controlli CI verdi su head e merge, con contenuto
identico al revisionato. PR80 registra le disposizioni dei 26 file Python esterni
(25 entry point più una libreria inutilizzata/non validata); restano due launcher
shell e helper non esercitati. La sua prova resta versionata: 772 test,
764 superati e 8 esclusioni, un full originale no-egress e conservazione ZIP.

Il blocco corrente riguarda la [famiglia Sentinel locale](sentinel-local-storage-family.md):
transizioni delle campagne confermate da effetti reali, ammissione API/CLI,
identità della radice dei file, inventario/metadati, limiti e concorrenza della
baseline. Non avvia servizi, raccolta remota o nuove interpretazioni.

Versione corrente: 790 test, 780 superati e 10 esclusioni (8 precedenti più i due
controlli di piattaforma link/FIFO); un full originale no-egress del nuovo blocco,
5 processi API e 6 CLI, verify/ZIP byte per byte. Sono passate anche le regressioni
di campagne/schemi legacy e letture fallite. Sui sorgenti finali sono riconfermati
il nuovo blocco, l'integrazione degli errori file e il flusso CLI/API con worker
live, otto casi completati, cancellazione e recupero dopo crash del supervisore.
La wheel reale corrisponde ai 90 sorgenti correnti, metadata, entrypoint e due
template. Cambiano quattro sorgenti package; gli altri 86 restano invariati.
Le prove circoscritte non chiudono l'accettazione complessiva del motore.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Collaudo complessivo della matrice Windows e degli ingressi/errori; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel locale | Campagne: validazione API condivisa, unicità di caso e rimozione condizionale nella transazione, rollback ed esito confermato. File: radice stabile, ammissione di tipi/percorsi, limiti dichiarati, rilevazione delle mutazioni testate e serializzazione della baseline per istanza. | Ammissione database/initializer e link, risorse generali di dati e publisher, writer di intelligence e snapshot tra processi. Il servizio e la raccolta attiva restano S14. |
| Script e installazione | Disposizione dei 26 file Python esterni: 25 entry point verificati o esplicitamente indisponibili e una libreria inutilizzata/non validata, con import inerte. Pacchetto costruito realmente e confrontato con sorgenti, entrypoint e template. | I 2 launcher shell restano differiti; gli algoritmi helper non esercitati restano aperti. Installazione isolata finale e componenti opzionali sulle piattaforme supportate. La disposizione non equivale alla validazione di ogni funzione. |
| Accuratezza e attribuzione | Pilot privato di 20 originali, con 10 legittimi confermati dal proprietario; algoritmi e ipotesi sono qualificati. | Etichette phishing indipendenti, corpus rappresentativo e holdout, falsi positivi/negativi, calibrazione e correlazione. Lo spam della casella non costituisce da solo ground truth. |
| Egress e interfaccia | Alcuni protocolli locali e meccanismi di raccolta hanno test loopback circoscritti. | Dopo stabilizzazione: valutare la soluzione Windows proposta, verificare isolamento/collector/detonazione; poi completare la UI con parità delle opzioni CLI. |

Le ultime PR hanno corretto consumatori che potevano contraddire JSON già
qualificati: publisher legacy, oggetto delle bozze e grafi. La fase corrente
prosegue per blocchi coerenti di famiglia, ciascuno con difetti riprodotti,
contratti comuni e review sullo stesso head testato; non per singolo file o
rilievo e senza mescolare capacità estranee. Poi serve un collaudo integrato della versione candidata.
Il numero di test o PR non determina una percentuale affidabile di completamento.

I prossimi blocchi hanno criteri di chiusura comuni:

1. **Sentinel locale residuo:** il blocco corrente verifica gli effetti delle
   campagne e le osservazioni dei file. Restano initializer/ammissione database,
   risorse generali di dati e publisher e snapshot tra processi, da riconciliare
   con il collaudo offline integrato; nessun monitoraggio remoto.
2. **Motore offline integrato:** riconciliare le capacità pubblicizzate con
   header/MIME/URL/allegati e report; verificare insieme ingressi malformati,
   omissioni, budget, interruzioni e parità CLI/API/verify/ZIP. Correggere per
   confine condiviso, con prove prima/dopo e review della famiglia interessata.
3. **Versione candidata:** installazione isolata e matrice Windows/POSIX,
   componenti opzionali e capacità indisponibili dichiarate. Valutazione
   indipendente con holdout per eventuali affermazioni di accuratezza.
4. **Fasi successive:** soluzione di isolamento Windows proposta e launcher
   shell, raccolta/arricchimenti/detonazione; UI con parità delle opzioni CLI.

Sentinel resta un'opzione con contratti locali circoscritti; nuove funzionalità
sono separate dal percorso corrente. Ottimizzare la durata delle analisi non è
l'obiettivo di questa fase. Full offline e full con raccolta/detonazione attiva
mantengono ambiti diversi fino alla verifica della successiva fase egress.
