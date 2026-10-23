# Stato dell'audit PAW

Riferimento integrato: PR92, commit
`62040da2898acd523bd0513e944f16069de5455e`; 23 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi sullo head `664954fa1612f95a9bbabcc8c6f7079b9b2079fc`,
entrambi i precedenti thread risolti e tre check verdi su head e merge,
con tree identico. Workflow sul merge: `39974092712`.

La [disposizione di tutto Sentinel](sentinel-module-audit.md) è integrata:
dieci file, contratti locali e HTTP/IP circoscritti, capacità indisponibili
esplicite. Il ciclo review/CI di questa famiglia è chiuso. Restano separate
accettazione operativa, provider reali, isolamento, deployment e piattaforme.
Le 958 prove e la matrice Sentinel registrate nel contratto descrivono quel blocco.

Il blocco corrente corregge i [contesti di testo HTML](html-text-contexts.md):
markup letterale che diventava form/script/iframe/CID, testo perso e interpretazione
CSS applicata fuori contesto. MIME, URL, CID, form, kit e osservazioni HTML usano
confini condivisi. Le parti HTML sono analizzate separatamente e i risultati
rimandano a parte MIME, testo e hash. Un caso malformato di 700.000 byte che
esauriva il limite della regressione ora termina conservando l'intera coda.

Suite finale: 976 test (962 superati, 14 esclusioni previste), 18 nuove prove
mirate. Nove integrazioni/build seriali della famiglia passate; dopo il confine
EOF ripetuti suite, nuovi casi HTML (15 CLI/6 HTTP), liste, fonti URL e wheel
con 95 sorgenti. I dettagli delle revisioni e dei 252 hash congelati sono nel
contratto; review Codex e CI della nuova famiglia restano da chiudere.
I contratti precedenti su [campi URL singoli](html-scalar-url-contexts.md),
[liste HTML](html-url-list-contexts.md) e [CSS letterale](css-url-contexts.md)
restano verificati. DOM/browser, grammatica completa e interpretazioni escluse
restano esplicite. Nessuna visita alle risorse delle email.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Contratti correnti di ammissione integrati nella PR86 con review/CI verdi; resta la matrice piattaforme/installazione, con evidenze POSIX separate. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione; il [confine Markdown integrato](report-evidence-consistency.md) conserva osservazioni letterali e confrontabili con i JSON. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel | Campagne/file/configurazione/report offline, lifecycle per istanza, pubblicazione atomica e osservazioni HTTP/IP hanno contratti integrati con fonti e limiti; tutti i file del modulo hanno una disposizione esplicita. | Review/CI della disposizione chiuse nella PR92. Servizio persistente, browser, provider reali, isolamento e accettazione piattaforme restano separati; nessuna identità o probabilità di rischio è stabilita da questi test. |
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

1. **Sentinel:** audit dei contratti e disposizione di tutto il modulo integrati
   nella PR92 con review/CI verdi. Le capacità indisponibili
   restano dichiarate e le prove reali su provider/browser richiedono la fase egress.
2. **Motore offline integrato:** preset/batch/HTTP/interruzioni e conservazione
   passano nella matrice integrata. Ammissione, malformati
   e relativa contabilità, compresi i campi URL HTML singoli, sono integrati;
   completare i contesti HTML/CSS residui e la riconciliazione delle capacità pubblicizzate con
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
