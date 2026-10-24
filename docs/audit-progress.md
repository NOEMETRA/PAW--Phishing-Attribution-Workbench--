# Stato dell'audit PAW

Riferimento integrato corrente: PR98, commit
`62f19daf63eea781e7e6eb3e6a383f88573030a1`; 23 ottobre 2026.
La [validazione Linux/R08](linux-r08-validation.md) registra installazioni reali
su Python 3.13.7/3.14.4, contratti POSIX e collaudo della wheel installata, con
PASS/FAIL e limiti dei componenti. R08 resta aperto; scoring e originali non
sono modificati. Su richiesta del proprietario, S14 prosegue con la
[preparazione chiusa sul solo PC Linux](s14-single-pc-linux.md): prerequisiti
CPU/KVM e prova libvirt sospesa verificati, rete interna senza uscita preparata.
La successiva [matrice con guest fidato](s14-benign-guest-validation.md) passa
immagine verificata, budget, traffico su fixture proprie e guasti: un run
completato, quattro interrotti attesi e due ammissioni rifiutate. Il gate I02–I08
complessivo resta da superare prima di qualsiasi detonazione reale.

Il seguente riferimento di review riguarda la precedente PR97, commit
`ccc946c5f61f197d088a924583e512241fafd56f`; 23 ottobre 2026 (Europe/Rome).
[Review finale Copilot](https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/97#pullrequestreview-5633364558)
sullo head `95f3688a753cb4675f4d34978c0e3896acd928ac`: approval recommended,
nessuna questione aperta. Tre check verdi su head e merge, tree identico.
Workflow: `40010089025` / `40014199646`.

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

Suite finale della famiglia CSS: 993 test (979 superati, 14 esclusioni previste), 16 nuove prove.
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
degli osservatori HTML opzionali mantengono limiti nominati. Le decisioni
G01/G02 sono ora riconciliate con la famiglia allegati; la diagnostica G06
è il confine corretto nel successivo audit evidenze/report.

La [famiglia di copertura degli allegati](attachment-capability-coverage.md)
riproduce un'omissione del consumatore: otto casi CLI completi conservavano 24
payload, ma il report non mostrava errori/limiti ZIP e nessun record nominava la
copertura del contenuto. La correzione aggiunge ambiti non valutati espliciti,
copertura di fase e una vista JSON letterale nel report, senza duplicare i membri
ZIP né trasformare conteggi sconosciuti in zero. G01 conserva l'esclusione
dell'estrazione dai documenti allegati; G02 conserva indisponibile la risoluzione
delle risorse. Metadati, originali e dichiarazioni restano distinti da capacità
di analisi del contenuto. La famiglia è integrata nella PR96 con review Copilot
senza questioni aperte e tre check verdi sia sullo head sia sul merge.

Validazione locale della famiglia allegati: 1.000 test (986 superati, 14
esclusioni previste), 65 contratti selezionati sul secondo runtime reale,
70 casi CLI e 35 worker HTTP loopback nella matrice seriale, incluse ripetizioni
e otto replay degli stessi originali. I 24 payload baseline e gli score numerici
restano invariati; il confronto distingue il timestamp UTC proprio di ciascun
run. Verificati report/API/ZIP, sigilli, originali e wheel di 95 sorgenti, con
284 hash Python/workflow congelati. Il primo verificatore privato del replay
si è fermato sul timestamp; la verifica corretta ha letto gli stessi casi già
completati, senza modificare sorgenti o ripetere le analisi. I dettagli e i limiti
sono nel contratto della famiglia, senza affermazioni di accuratezza.

Il nuovo [audit evidenze → score → consumatori](evidence-score-consumers.md)
registra il percorso numerico e le proiezioni correnti, con otto residui concreti
R01-R08. Riproduce un indicatore di iframe invisibile inventato da dimensioni
assenti e l'assenza di conteggi indipendenti per i limiti degli osservatori HTML.
Il contratto G06, integrato nella PR97, distingue completamento, errore e indisponibilità,
con omissioni per osservatore/documento e una vista comune in JSON, score,
report, bozze e API. Le omissioni non aggiungono rischio; i limiti sono di
pubblicazione dopo enumerazione, non nuovi limiti di parsing/CPU. Review Copilot
senza questioni aperte e CI sullo head/merge sono verdi; l'audit complessivo resta aperto.

Validazione della famiglia PR97: 1.011 test (997 superati, 14 esclusioni previste),
60 contratti sul secondo runtime reale e 52 casi CLI/26 worker HTTP nella matrice
seriale. Replay degli stessi cinque originali, fonti v6, bozze/indice/report/API/
ZIP e wheel di 95 sorgenti verificati, con 286 hash Python/workflow invariati.
Il primo confronto privato si è fermato sul timestamp Received proprio del run;
la verifica corretta ha riletto gli stessi casi completati, distinguendo i due
riferimenti UTC e conservando il log dell'arresto. Nessuno score numerico o caso
storico è stato riscritto per ottenere il confronto.

DOM/browser, grammatica completa e interpretazioni escluse restano esplicite.

La [famiglia dei consumatori residui](residual-consumer-contracts.md) prosegue
R01–R08 con un confine comune di lettura/proiezione/pubblicazione. R01 usa la
decisione coerente con il profilo per i colori; R02 conserva viste storiche senza
inventare campi o zero; R03/R04 pubblicano valori letterali e qualificati, separando
integrità Merkle e inclusione Rekor non valutata. R05 rende PGP esplicitamente
indisponibile prima di chiavi/output; R06 ammette file JSON/testo entro limiti e
tipi dichiarati senza interrompere i vicini sani. R07 conserva la cattura CSS
ristretta con interpretazione risorsa indisponibile; non amplia il parser.
R08 resta il gate finale di installazione/componenti/piattaforme e collaudo della
versione candidata. La famiglia è integrata nella PR98; il contratto conserva
la storia dei gate di review/CI e la validazione Linux corrente resta separata.
Nessuna accuratezza o autenticità è dedotta dai contratti.

Matrice finale dei residui: 1.030 test (1.015 superati, 15 esclusioni previste),
107 contratti selezionati sul secondo runtime (105 superati, due esclusioni).
La nuova integrazione verifica sei casi CLI/tre worker HTTP e una prova diretta
offline con metadati forniti, ripetuti su entrambi gli ambienti reali. Passano
anche le regressioni HTML/report/allegati/URL/bozze, proprietà CLI/API e recupero,
tre replay degli stessi originali e wheel con 96 sorgenti e due template modificati.
I 293 hash Python/template/workflow della matrice finale restano invariati.
La prima matrice è stata fermata da una differenza CRLF nella vista API introdotta
dal lettore; i log sono conservati e la correzione è seguita da un nuovo
congelamento e dall'intera matrice, senza indebolire il confronto precedente.

Nessuna risorsa delle email è stata visitata o risolta.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Matrice Windows integrata registrata sul merge PR84. Contratti correnti di ammissione integrati nella PR86 con review/CI verdi; resta la matrice piattaforme/installazione, con evidenze POSIX separate. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. Perimetro HTML/CSS enumerato in H01-H10, E01-E06 e G01-G06. | La famiglia allegati riconcilia metadati/ZIP e contenuti non valutati con copertura/report espliciti; G01/G02 hanno una decisione corrente di conservazione/indisponibilità, G03/G04 restano generici/esclusi, G05 è un limite kit; il contratto G06 rende espliciti disponibilità/errori/omissioni e li segue nei consumatori, con gate propri di review/CI. Restano corpus allegati e accettazione piattaforme/componenti. Combinazioni malformate e collaudo integrato restano circoscritti ai contratti supportati. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione; il [confine Markdown integrato](report-evidence-consistency.md) conserva osservazioni letterali e confrontabili con i JSON. | R01–R07 hanno disposizioni supportate/indisponibili entro i contratti dei consumatori; R08 resta accettazione finale. Tipi malformati, risorse e renderer restano circoscritti ai contratti verificati; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel | Campagne/file/configurazione/report offline, lifecycle per istanza, pubblicazione atomica e osservazioni HTTP/IP hanno contratti integrati con fonti e limiti; tutti i file del modulo hanno una disposizione esplicita. | Review/CI della disposizione chiuse nella PR92. Servizio persistente, browser, provider reali, isolamento e accettazione piattaforme restano separati; nessuna identità o probabilità di rischio è stabilita da questi test. |
| Script e installazione | Disposizione dei 26 file Python esterni: 25 entry point verificati o esplicitamente indisponibili e una libreria inutilizzata/non validata, con import inerte. Pacchetto costruito realmente e confrontato con sorgenti, entrypoint e template. | I 2 launcher shell restano differiti; gli algoritmi helper non esercitati restano aperti. Installazione isolata finale e componenti opzionali sulle piattaforme supportate. La disposizione non equivale alla validazione di ogni funzione. |
| Accuratezza e attribuzione | Pilot privato di 20 originali, con 10 legittimi confermati dal proprietario; algoritmi e ipotesi sono qualificati. | Etichette phishing indipendenti, corpus rappresentativo e holdout, falsi positivi/negativi, calibrazione e correlazione. Lo spam della casella non costituisce da solo ground truth. |
| Egress e interfaccia | Alcuni protocolli locali e meccanismi di raccolta hanno test loopback circoscritti. | Dopo stabilizzazione: superare il gate di isolamento delle VM locali, poi collector/detonazione; poi completare la UI con parità delle opzioni CLI. |

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
   capacità pubblicizzate con header/MIME/URL/allegati e report, preservando le
   decisioni G01/G02, il limite kit G05, il contratto diagnostico G06 e le disposizioni R01-R08; verificare insieme ingressi malformati,
   omissioni, budget, interruzioni e parità CLI/API/verify/ZIP. Correggere per
   confine condiviso, con prove prima/dopo e review della famiglia interessata.
3. **Versione candidata:** installazione isolata e matrice Windows/POSIX,
   componenti opzionali e capacità indisponibili dichiarate. Valutazione
   indipendente con holdout per eventuali affermazioni di accuratezza.
4. **Fasi successive:** isolamento con VM locali e launcher
   shell, raccolta/arricchimenti/detonazione; UI con parità delle opzioni CLI.

Sentinel resta un'opzione con contratti locali circoscritti; nuove funzionalità
sono separate dal percorso corrente. Ottimizzare la durata delle analisi non è
l'obiettivo di questa fase. Full offline e full con raccolta/detonazione attiva
mantengono ambiti diversi fino alla verifica della successiva fase egress.

S14 update, 24 October 2026: the complete closed 2 GiB profile and actual
post-reboot startup check now pass. The host guard is active before explicit
local libvirt activation; no guests/networks autostart, policy/image/version
hashes match, and source/scoring/originals remain unchanged. See the
[final full-profile and cold-boot record](s14-gateway-validation.md#final-full-profile-and-cold-boot-acceptance).
The broader S14 real-uplink/collector/target-authorization gate and R08 remain
open; no real egress or detonation was run.

The separate [disabled Wi-Fi uplink preparation](s14-uplink-profile.md) adds an
exact public testing-service candidate, address/lease admission and compiled
routing/guard files without activating them. Eight inert methods, sixteen
namespace scenarios and six KVM-to-host-NAT scenarios pass against owned local
fixtures; host policy/routes are restored. Physical Wi-Fi forwarding, real DNS
pins and a supported live coordinator remain unaccepted. The established closed
profile, engine scoring, originals and seals remain unchanged.
