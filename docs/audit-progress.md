# Stato dell'audit PAW

Riferimento integrato: PR79, commit
`c2057368a497b2b7c8bb1aeaf55abe2b797cbcd0`, 20 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi e tre controlli CI verdi sia sullo head sia sul merge;
il merge ha lo stesso contenuto revisionato. La versione PR79 è stata verificata
con 765 test (757 superati, 8 esclusioni di piattaforma), un full EML originale
no-egress con verify/ZIP, 55 processi legacy controllati, 19 invocazioni dirette
e una wheel confrontata con i 90 sorgenti invariati del pacchetto.

Il blocco corrente completa la disposizione dei sei file Python esterni residui:
cinque [publisher di conclusioni legacy](legacy-conclusion-publication.md)
rifiutano prima di fonti/profili/token/output e sedici API principali prima degli
argomenti; la libreria inutilizzata `util/validators.py` resta esplicitamente
non validata, senza CLI o consumer di produzione identificato. I cinque publisher
sovrascrivevano note, invalidavano sigilli e pubblicavano attribuzione o servizi
non dimostrati. Nessuno dei 90 sorgenti Python del pacchetto cambia.
Sulla versione corrente: 772 test, 764 superati e 8 esclusioni di piattaforma;
un full EML originale no-egress con verify/ZIP, 200 processi legacy controllati,
31 invocazioni dirette stdlib e import inerte della libreria. Nessun accesso
alle fonti protette o tentativo di rete nei processi controllati. La wheel reale
corrisponde ai 90 sorgenti, metadati, entrypoint e template. Cinquanta helper
residui conservano lo stesso AST e la libreria cambia solo documentazione.
Le prove PR79 restano riferimenti versionati, non accettazione finale congiunta.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Collaudo complessivo della matrice Windows e degli ingressi/errori; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
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

1. **Sentinel locale residuo:** writer/API delle campagne, inventario e metadati,
   limiti di risorse e concorrenza. Conservazione delle fonti e comportamento
   uniforme di errori, lettori e output; nessun monitoraggio remoto.
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
