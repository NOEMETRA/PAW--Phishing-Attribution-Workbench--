# Stato dell'audit PAW

Riferimento integrato: PR81, commit
`4b6f4ef0622dcb3ca0560d5841494d05374e5f1b`; checkpoint del 21 ottobre 2026
(Europe/Rome). Review Codex senza rilievi e tre controlli CI verdi su head e merge,
con tree identico al revisionato. La prova PR81 resta versionata: 790 test,
780 superati e 10 esclusioni, full originale no-egress, CLI/API e conservazione ZIP.
Le disposizioni dei 26 file Python esterni restano registrate; due launcher shell
ed helper non esercitati non sono validati per questa sola presenza.

Il blocco corrente copre l'[ammissione dello storage configurato](sentinel-configured-storage.md):
configurazioni presenti non valide/illeggibili falliscono senza fallback; percorsi
ed identità di file restano legati alla sorgente selezionata. Pubblicazione della
configurazione e inizializzazione/migrazioni SQL hanno contratti di errore espliciti.
Un database non riconosciuto non riceve automaticamente tabelle Sentinel.
I target appena creati restano ispezionabili dopo errore, senza unlink del database.

Sui sorgenti finali: 811 test, 799 superati e 12 esclusioni di piattaforma;
46 processi CLI e 4 API di ammissione, più 5 API/6 CLI e un full originale
no-egress della famiglia locale, con supervisore fermato e verify/ZIP byte per
byte. Nel blocco passano anche le regressioni campagne, letture passive e report
geografici. La wheel reale corrisponde ai 90 sorgenti correnti, metadata,
entrypoint e due template. Due sorgenti package cambiano; gli altri 88 non
cambiano nel contenuto Git. Le prove non chiudono l'accettazione globale del motore.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Collaudo complessivo della matrice Windows e degli ingressi/errori; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel locale | Campagne: validazione API condivisa, unicità di caso e rimozione condizionale nella transazione, rollback ed esito confermato. File: radice stabile, ammissione di tipi/percorsi, limiti dichiarati, rilevazione delle mutazioni testate e serializzazione della baseline per istanza. | Storage configurato: sorgenti ammesse/persistenti, schema transazionale e config pubblicata intera verificati nel blocco corrente. Restano risorse generali di dati/publisher, altri writer di intelligence e snapshot tra processi. Il servizio e la raccolta attiva restano S14. |
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
   campagne e le osservazioni dei file. Il blocco di storage configurato verifica
   ammissione database/config e schema. Restano risorse generali di dati e
   publisher, altri writer di intelligence e snapshot tra processi, da riconciliare
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
