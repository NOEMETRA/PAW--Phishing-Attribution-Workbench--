# Stato dell'audit PAW

Riferimento integrato: PR94, commit
`e7a981131e9898f1c7af6c46db2fd0338fba46b0`; 23 ottobre 2026 (Europe/Rome).
[Review finale Copilot](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/94#pullrequestreview-5631910326)
sullo head `b82104c7a166ba245385fba7b496d5b435f33653`: approval recommended,
nessuna questione aperta. Tre check verdi su head e merge, tree identico.
Workflow: `39992858333` / `39994215958`.

I [contesti di testo HTML](html-text-contexts.md) sono integrati: confini comuni
per MIME, URL, CID, form, kit e osservazioni HTML; documenti MIME separati con
parte/testo/hash; conservazione delle code incomplete e compatibilità dei parser
Python aggiornati. La [disposizione di Sentinel](sentinel-module-audit.md) resta
integrata dalla PR92; accettazione operativa, provider, isolamento e deployment
restano separati.

Sono integrati anche i [confini dei token CSS](css-token-boundaries.md):
nomi hash/at-keyword scambiati per funzioni, escape invalidi che inglobavano il
token successivo, commenti dopo argomenti fra virgolette e funzioni non supportate
troncate dentro commenti/stringhe/blocchi. Le menzioni nei separatori restano
intere, legate alla fonte e senza promozione a destinazioni di rete.

Copilot ha confermato un ulteriore difetto del recupero: punteggiatura dentro
URL/bad-URL non quotati annidati poteva inglobare una funzione successiva.
La correzione condivide il consumo del token, conserva il segmento opaco e
mantiene separata la destinazione successiva, senza interpretare i modificatori.

Suite finale: 993 test (979 superati, 14 esclusioni previste), 16 nuove prove.
Quattro script di integrazione/build seriali passati dopo la correzione su 254
hash congelati: casi CSS 13 CLI/6 HTTP ripetuti su due runtime reali, contratto
CSS precedente, fonti URL e wheel di 95 sorgenti. La matrice iniziale di sette
script, inclusi i contesti HTML, resta registrata nel documento della famiglia.
I conteggi distinguono
URL e segmenti testuali opachi, inclusi 5.000/4.096/904 collegamenti conservati o
omessi. Codex è rimasto senza esito; su richiesta del proprietario Copilot ha
completato la review della correzione, e CI su head e merge è verde.

Il [perimetro finito HTML/CSS](html-css-scope.md) dispone dieci contesti
supportati, sei esclusioni e sei lacune concrete con famiglia responsabile
e criterio di riapertura. Distingue estrazione dei corpi MIME, osservazioni HTML
opzionali e helper kit/form. Chiude l'enumerazione del perimetro corrente,
non la completezza dell'estrazione: HTML/CSS allegati o incorporati, relazioni
CID/Content-Location, grammatiche generiche, estrazione CSS dei kit e diagnostica
degli osservatori HTML opzionali mantengono limiti nominati. Il prossimo blocco
riconcilia capacità pubblicizzate e allegati,
iniziando dalle lacune G01/G02; non estende indefinitamente il parser.

DOM/browser, grammatica completa e interpretazioni escluse restano esplicite.
Nessuna risorsa delle email è stata visitata o risolta.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Contratti correnti di ammissione integrati nella PR86 con review/CI verdi; resta la matrice piattaforme/installazione, con evidenze POSIX separate. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. Perimetro HTML/CSS enumerato in H01-H10, E01-E06 e G01-G06. | Riconciliare capacità pubblicizzate, allegati/formati opachi e limiti/omissioni; G01/G02 restano decisioni di copertura MIME, G03/G04 hanno disposizione generica/esclusa, G05 resta un limite kit e G06 una lacuna diagnostica da riprendere nell'audit evidenze/report. Combinazioni malformate e collaudo integrato restano circoscritti ai contratti supportati. |
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
   mantenere il perimetro HTML/CSS finito e completare la riconciliazione delle
   capacità pubblicizzate con header/MIME/URL/allegati e report, con decisioni
   esplicite per G01/G02 e il limite kit G05; verificare insieme ingressi malformati,
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
