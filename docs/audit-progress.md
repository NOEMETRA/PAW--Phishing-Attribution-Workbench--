# Stato dell'audit PAW

Riferimento integrato: PR91, commit
`801c268387347cc4793ce274a52561d4c4ec6ffc`; 23 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi sullo head `3f3168ef94b61eec863a1004fa381ee6f78964da`,
nessun thread aperto e tre check verdi su head e merge, con tree identico.
I [campi URL HTML singoli](html-scalar-url-contexts.md), i
[confini delle liste HTML](html-url-list-contexts.md) e i
[confini CSS letterali](css-url-contexts.md) sono integrati. Normalizzazione del
browser, risoluzione relativa, escape CSS e conformità completa restano non valutati.

Il blocco corrente completa la [disposizione di tutto Sentinel](sentinel-module-audit.md):
dieci file e contratti supportati, descrittivi o esplicitamente indisponibili.
Corregge stop/restart dei worker, confronto con le righe precedenti, transazioni
check/alert, conservazione limitata delle risposte HTTP e fonti dei provider IP.
Errori di trasporto non diventano down; prefissi IP, paesi, UA e dati assenti non
producono identità o punteggi inventati. Automatismi di attribuzione e browser
non isolato sono indisponibili; righe e affermazioni storiche restano leggibili.
La disposizione del modulo richiede ancora review/CI della nuova famiglia;
non chiude la fase egress né l'audit dell'intero motore.

Suite finale: 958 test (944 superati, 14 esclusioni previste). Matrice seriale di
25 integrazioni Sentinel/legacy/wheel passata, incluse 18 nuove prove HTTP/PTR su
loopback. Dopo gli ultimi controlli transazionali sono stati ripetuti suite
generale, loopback, viste SQLite tra processi, writer e wheel di 94 sorgenti.
I 29 test mirati includono un blocco indipendente contro processi/socket/scritture
nella prova screenshot. Il P1 della prima review della famiglia è riprodotto e
corretto: i risultati immediati includono ID/confronti committati ed escludono
osservazioni cancellate non pubblicate. Il successivo P2 sulla pubblicazione SQL
in attesa è riprodotto e corretto con ammissione al commit sincronizzata allo stop;
commit già ammessi possono finire e lo stop resta incompleto fino al termine.
Suite e quattro integrazioni ripetute, con 248 hash finali congelati.
Gli originali EML sono analizzati no-egress; arresto, fonti, sigilli e ZIP verificati.
I dettagli e i limiti della matrice sono nel contratto del modulo.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Contratti correnti di ammissione integrati nella PR86 con review/CI verdi; resta la matrice piattaforme/installazione, con evidenze POSIX separate. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione; il [confine Markdown integrato](report-evidence-consistency.md) conserva osservazioni letterali e confrontabili con i JSON. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel | Campagne/file/configurazione/report offline hanno contratti integrati. Il blocco corrente aggiunge lifecycle per istanza, pubblicazione atomica e osservazioni HTTP/IP con fonti e limiti, con disposizione di tutti i file del modulo. | Chiudere review/CI della famiglia corrente. Servizio persistente, browser, provider reali, isolamento e accettazione piattaforme restano separati; nessuna identità o probabilità di rischio è stabilita da questi test. |
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

1. **Sentinel:** audit dei contratti e disposizione di tutto il modulo completati
   nel blocco corrente; chiudere review/CI e integrazione. Le capacità indisponibili
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
