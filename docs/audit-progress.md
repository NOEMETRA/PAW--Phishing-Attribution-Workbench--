# Stato dell'audit PAW

Riferimento integrato: PR85, commit
`2ce5d842cef0c541f48f1ed3e845abfaa624f49d`; 23 ottobre 2026 (Europe/Rome).
Il P2 documentale mantiene esplicita l'ammissione EML malformati; review finale
senza rilievi e tre check verdi su head e merge, con tree identico.
Sentinel offline è integrato nella PR84 con i suoi limiti dichiarati; la
[matrice integrata dell'esecuzione](integrated-execution-acceptance.md) resta
registrata: cinque script passati, 24 scenari CLI/95 casi con sigilli verificati,
HTTP, crash/recovery e byte osservati. Non è una misura di accuratezza.

Il blocco corrente verifica la [famiglia di ammissione degli input](engine-input-admission.md):
percorsi ammessi prima di resolve/stat/open/worker, lettura binaria non bloccante
su descrittori regolari, budget runtime interi senza coercizioni e durate finite.
Le modifiche interessano sei sorgenti package esistenti, con 85 invariati.
Gli EML malformati non vuoti restano osservazioni best-effort con originali,
difetti e copertura parziale; input vuoti/limiti/MSG restano fallimenti espliciti.
Contabilità parziale CLI e risultati/rifiuti HTTP sono verificati realmente.

Sorgenti finali congelati: 887 test (873 superati, 14 esclusioni), cinque
integrazioni seriali passate e wheel di 91 sorgenti. Il nuovo collaudo comprende
50 preflight CLI con barriere prima dell'I/O, sei forme UNC via API, cinque preset,
batch con quattro successi/due fallimenti, tre EML malformati via HTTP e undici
richieste invalide senza job. Firme DKIM, supervisione e CLI/API condivise passano
nei collaudi esistenti.235 hash runtime/test/workflow invariati prima dei documenti;
nessun campione privato incluso. Review/CI del nuovo blocco restano da chiudere.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Contratti correnti di ammissione verificati nel nuovo blocco; restano review/CI e matrice piattaforme/installazione, con evidenze POSIX separate. |
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
   passano nella matrice integrata. Il nuovo blocco verifica ammissione, malformati
   e relativa contabilità; chiudere review/CI, poi riconciliare le capacità pubblicizzate con
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
