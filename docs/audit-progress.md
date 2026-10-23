# Stato dell'audit PAW

Riferimento integrato: PR84, commit
`9a6e9763de568f310548d25aa66b212853279d31`; checkpoint del 23 ottobre 2026
(Europe/Rome). Cinque P2 fondati corretti con prove prima/dopo, review finale
Codex senza rilievi e tre check verdi sullo head `05e28fe` e sul merge reale,
con tree identico. I [contratti offline supportati di Sentinel](sentinel-offline-completion.md)
sono integrati: budget condivisi, viste SQLite e mutatori, config, file/report e
rifiuto preventivo degli ingressi attivi sotto no-egress. Servizio e algoritmi
attivi restano S14; la chiusura riguarda il perimetro offline dichiarato.

Sul precedente head logico `6943305` passano 879 test (866 superati, 13 esclusioni)
e dieci integrazioni. Il seguito cambia solo due diciture runtime della CLI:
18 invocazioni reali con file hidden/`.pyc`, conteggi e sorgenti invariati,
statici e wheel di 91 sorgenti passano prima della review/CI finale.

Il blocco corrente registra l'[accettazione integrata dell'esecuzione](integrated-execution-acceptance.md)
su quel merge: cinque script esistenti passati serialmente, 24 scenari CLI e 95
casi completati con sigillo verificato, preset/batch/rifiuti e flussi HTTP reali,
lettori bloccati durante scritture, timeout/cancellazione e crash/recovery.
Il controllo indipendente finale confronta 95 copie input con digest e sorgenti
ancora presenti e verifica no-egress in manifest/esecuzione. Non prova autenticità,
accuratezza o una storia non osservata dei file. Le prove API confrontano anche
byte originali prima dell'esecuzione e ZIP. Passano inoltre 35 invocazioni standalone
nel quinto script; fixture troncate e crash effettivo sono evidenze distinte.
233 hash runtime/test/workflow invariati, worktree pulita prima di questo checkpoint
solo documentale; nessuna modifica produttiva necessaria per far passare la matrice.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Restano combinazioni residue di ammissione e matrice piattaforme/installazione; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel locale | Campagne: validazione API condivisa, unicità di caso e rimozione condizionale nella transazione, rollback ed esito confermato. File: radice stabile, ammissione di tipi/percorsi, limiti dichiarati, rilevazione delle mutazioni testate e serializzazione della baseline per istanza. | Contratti offline dichiarati integrati e review/CI verdi. Restano riconciliazione con accettazione globale e supporto piattaforme; servizio/raccolta attiva restano S14. |
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

1. **Sentinel offline:** contratti dichiarati integrati con review/CI verdi e
   matrice di disposizioni per tutto il package. La matrice integrata di esecuzione
   è ora registrata sullo stesso merge; piattaforme e perimetri attivi restano separati.
2. **Motore offline integrato:** preset/batch/HTTP/interruzioni e conservazione
   passano nella matrice corrente. Proseguire con EML top-level malformati e relativi esiti/contabilità
   CLI/API, oltre alle combinazioni di ammissione residue e riconciliare le capacità pubblicizzate con
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
