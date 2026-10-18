# Stato dell'audit PAW

Riferimento integrato: PR73, commit
`799ae8207a02a612bcf3cc47535fcb5f7a649f18`, 19 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi e tre controlli CI verdi sull'head PR73;
il merge ha lo stesso contenuto. Il pacchetto PR73 è stato verificato con
732 test (724 superati, 8 esclusioni di piattaforma), due analisi full EML con
errori di lettura iniettati e recupero, 29 processi API/CLI dedicati, 18 scenari
CLI locali e wheel reale. Queste sono evidenze circoscritte, senza attestare
ogni funzione dei 90 file Python del pacchetto.

La correzione corrente dei [lettori delle campagne](sentinel-campaign-columns.md)
tocca soltanto le due proiezioni SELECT: una diversa disposizione fisica delle
colonne non deve scambiare ID, caso, URL, stato o metadati. Schemi, writer,
filtri e decoder JSON restano invariati. Le prove della PR73 sono riferimenti
precedenti e non sostituiscono la verifica della versione corrente o
l'accettazione finale su tutte le piattaforme.
Sulla versione corrente passano 738 test (730 superati, 8 esclusioni), cinque
processi API e 70 CLI sui consumatori di campagne e una wheel reale confrontata
con i 90 sorgenti del pacchetto. Anche la CI del merge PR73 è tutta verde.
Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Collaudo complessivo della matrice Windows e degli ingressi/errori; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Script e installazione | Dodici dei 26 script operativi Python hanno una disposizione verificata, inclusi i due entry point del prototipo di prove forensi, ora esplicitamente indisponibili senza modificare il caso. Pacchetto costruito realmente e confrontato con sorgenti, entrypoint e template. | Altri 14 script Python e 2 launcher shell; helper non esercitati; installazione isolata finale e componenti opzionali sulle piattaforme supportate. |
| Accuratezza e attribuzione | Pilot privato di 20 originali, con 10 legittimi confermati dal proprietario; algoritmi e ipotesi sono qualificati. | Etichette phishing indipendenti, corpus rappresentativo e holdout, falsi positivi/negativi, calibrazione e correlazione. Lo spam della casella non costituisce da solo ground truth. |
| Egress e interfaccia | Alcuni protocolli locali e meccanismi di raccolta hanno test loopback circoscritti. | Dopo stabilizzazione: valutare la soluzione Windows proposta, verificare isolamento/collector/detonazione; poi completare la UI con parità delle opzioni CLI. |

Le ultime PR hanno corretto consumatori che potevano contraddire JSON già
qualificati: publisher legacy, oggetto delle bozze e grafi. La fase corrente
prosegue su questa lista finita di output e sugli ingressi residui, con correzioni
riprodotte e review mirate. Poi serve un collaudo integrato della versione candidata.
Il numero di test o PR non determina una percentuale affidabile di completamento.

Sentinel resta un'opzione con contratti locali circoscritti; nuove funzionalità
sono separate dal percorso corrente. Ottimizzare la durata delle analisi non è
l'obiettivo di questa fase. Full offline e full con raccolta/detonazione attiva
mantengono ambiti diversi fino alla verifica della successiva fase egress.
