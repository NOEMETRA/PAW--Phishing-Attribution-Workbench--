# Stato dell'audit PAW

Riferimento integrato: PR89, commit
`d387ddbc4673bc40f7f4e5e80c9c554e9f298d49`; 23 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi sullo head corretto `03629d9aeaf8c243555c1511310cc93caa151ff9`,
nessun thread aperto e tre check verdi su head e merge, con tree identico.
I [confini srcset/imagesrcset](html-url-list-contexts.md) e la relativa ammissione
degli URL interi sono integrati. Contesto MIME, ammissione input, report letterali,
Sentinel offline ed esecuzione mantengono le evidenze e i limiti documentati.

Il blocco corrente corregge tre casi di [confine CSS url()](css-url-contexts.md):
sintassi finale inclusa nella destinazione e sottostringhe HTTP promosse da
argomenti data/relativi. Attributi style e testo degli elementi style condividono
lo scanner degli argomenti letterali; le fonti v3 ricostruiscono la stessa vista.
Parentesi quotate, escape percentuali e differenze fra entità negli attributi e
testo raw restano preservati. Espressioni malformate restano evidenza non-target.
Decodifica degli escape CSS, conformità completa, cascade e scelta delle risorse
restano non valutate; questo non chiude tutti i contesti HTML/CSS.

Suite generale: 920 test (906 superati, 14 esclusioni); cinque integrazioni reali
seriali passate e wheel di 93 sorgenti. Nuovo collaudo CSS: otto full CLI e tre
worker HTTP; ripetuti anche HTML liste (11/5), fonti URL (9/5) e identità URL
(11 CLI). Originali/corpi, fonti, coperture, sigilli e ZIP sono confrontati.
Tre sorgenti package esistenti modificati, 89 invariati e un helper aggiunto.
Il wheel è stato ricostruito dopo l'inclusione del nuovo file nell'indice Git.
Tutti i 243 hash Python/workflow restano invariati durante i validator seriali;
documenti aggiornati solo dopo la loro fine. Review/CI del blocco CSS da chiudere.

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
   e relativa contabilità sono integrati; chiudere review/CI dei confini CSS letterali,
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
