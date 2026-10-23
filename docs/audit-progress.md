# Stato dell'audit PAW

Riferimento integrato: PR90, commit
`7d97746bc645b3c67fcff3f1921fc3044a9c8d7a`; 23 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi sullo head testato `0a3b9fac953c29a8d0eb14dfc72694c46dffe64d`,
nessun thread aperto e tre check verdi su head e merge, con tree identico.
I [confini srcset/imagesrcset](html-url-list-contexts.md), l'ammissione degli URL
interi e i [confini CSS letterali](css-url-contexts.md) sono integrati.
Contesto MIME, ammissione input, report letterali,
Sentinel offline ed esecuzione mantengono le evidenze e i limiti documentati.

Il blocco corrente corregge i [campi URL HTML singoli](html-scalar-url-contexts.md):
href/src/action/formaction/poster e data di object. I valori completi, con spazi,
apici o contenitori non HTTP, non diventano più prefissi o sottostringhe validi.
Osservazioni MIME, recupero e fonti v4 condividono il confine del campo;
metadati arbitrari e le altre grammatiche mantengono il contratto precedente.
Normalizzazione del browser, risoluzione relativa, decodifica degli escape CSS,
conformità completa e scelta delle risorse restano non valutate.

Suite generale: 929 test (915 superati, 14 esclusioni); sei integrazioni reali
seriali passate e wheel di 93 sorgenti. Nuovo collaudo campi singoli: otto full CLI
e tre worker HTTP; ripetuti CSS (8/3), HTML liste (11/5), fonti URL (9/5) e identità
URL (11 CLI). Originali/corpi, fonti, coperture, sigilli e ZIP sono confrontati.
Il caso HTTP verifica anche 5.000 collegamenti/4.096 conservati/904 omessi.
Quattro sorgenti package modificati, 89 invariati. La sola aspettativa del
verificatore integrato sui target condivisi è stata corretta e tutte le sei
integrazioni ripetute; runtime e test unitari invariati dopo la suite generale.
245 hash Python/workflow finali verificati. Documenti dopo la fine dei validator;
review/CI della famiglia corrente restano da chiudere.

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
   e relativa contabilità sono integrati; chiudere review/CI dei campi URL HTML singoli,
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
