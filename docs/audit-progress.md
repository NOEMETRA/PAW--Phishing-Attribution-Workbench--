# Stato dell'audit PAW

Riferimento integrato: PR70, commit
`03e893c3bbe10b7159caeb87c52c8ff7ed73b305`, 18 ottobre 2026.
Review Codex senza rilievi e tre controlli CI verdi sull'head PR70;
il merge ha lo stesso contenuto. Il precedente riferimento del pacchetto PR64/65
è stato verificato con 19 analisi CLI/HTTP, 715 test
(707 passati e 8 esclusioni di piattaforma) e wheel reale. Queste sono evidenze
circoscritte, senza attestare ogni funzione dei 90 file Python del pacchetto.

La correzione corrente degli [errori di lettura hash](sentinel-file-hash-failures.md)
tocca soltanto il monitor dei file nel pacchetto e preserva le baseline dopo errori;
le prove precedenti non sostituiscono la verifica di questa versione.
Su questa versione passano 720 test (712 superati, 8 esclusioni di piattaforma),
una nuova analisi completa EML offline con errori/recupero API e CLI, ZIP,
18 scenari CLI locali esistenti e il confronto della wheel con i 90 sorgenti
Python del pacchetto. Non è una nuova installazione isolata o la chiusura
dell'accettazione finale su tutte le piattaforme.
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
