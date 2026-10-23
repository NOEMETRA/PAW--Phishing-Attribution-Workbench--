# Stato dell'audit PAW

Riferimento integrato: PR87, commit
`43c5c47fe4cafe62e3168a071aa8861a5663583d`; 23 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi sullo head testato `ab81261f6d0c4d19c1c3b0f5bb21ef6b4703d224`,
nessun thread e tre check verdi su head e merge, con tree identico.
La [rappresentazione letterale dei report](report-evidence-consistency.md) è integrata;
ammissione input (PR86), Sentinel offline (PR84) e matrice integrata di esecuzione
mantengono le loro evidenze e i limiti dichiarati. Non sono misure di accuratezza.

Il blocco corrente copre il [contesto MIME scelto dal parser](mime-context-evidence.md):
dichiarazioni duplicate/difettose e difetti strutturali potevano lasciare
interpretazioni locali o discendenti senza incertezza esplicita. Ora conteggi,
posizioni delle dichiarazioni e contesti parentali parziali accompagnano corpi,
allegati, copertura e report. Le parti sorelle restano indipendenti. Le viste e i
byte scelti dal parser non cambiano e non si aggiungono contributi di rischio.

Sorgenti finali congelati: 898 test (884 superati, 14 esclusioni), sei integrazioni
seriali passate, wheel di 92 sorgenti. Nuovo collaudo: 16 full CLI e quattro
worker HTTP reali, con header selezionati oltre il prefisso conservato, sigilli,
originali, payload e ZIP. Passano anche corpi MIME, inventari header, report
letterali e firme DKIM nei cinque preset/HTTP. Quattro sorgenti package esistenti
modificati, 88 invariati; 238 hash Python/workflow ricontrollati. Documenti dopo
la fine dei validator. Review/CI del nuovo blocco restano da chiudere.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Contratti correnti di ammissione integrati nella PR86 con review/CI verdi; resta la matrice piattaforme/installazione, con evidenze POSIX separate. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione; il [confine Markdown integrato](report-evidence-consistency.md) conserva osservazioni letterali e confrontabili con i JSON. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
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
   passano nella matrice integrata. Ammissione, malformati
   e relativa contabilità sono integrati; chiudere review/CI del contesto MIME,
   poi completare la riconciliazione delle capacità pubblicizzate con
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
