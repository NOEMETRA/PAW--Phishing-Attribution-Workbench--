# Stato dell'audit PAW

Riferimento integrato: PR78, commit
`35da73c8d0f556d564efaf9cc202da0f82b25c5d`, 20 ottobre 2026 (Europe/Rome).
Review Codex senza rilievi e tre controlli CI verdi sull'head PR78;
il merge ha lo stesso contenuto. La versione PR78 è stata verificata con
759 test (751 superati, 8 esclusioni di piattaforma), un full EML originale
no-egress con verify/ZIP, 34 processi legacy controllati, 12 invocazioni dirette
e una wheel confrontata con i 90 sorgenti invariati del pacchetto.

La correzione corrente dei [predittori operativi legacy](legacy-operational-predictions.md)
rifiuta pubblicazione e API principali prima di fonti/output: sovrascrivevano
note o il CSV sorgente e generavano date/percentuali anche senza caso. NumPy
non viene caricato per rifiutare una capacità indisponibile. Nessuno dei 90
sorgenti Python del pacchetto cambia. Le prove della PR78 restano riferimenti
versionati; l'accettazione finale congiunta resta aperta.
Sulla versione corrente passano 765 test (757 superati, 8 esclusioni), un full
EML originale no-egress con verify/ZIP, 55 processi legacy controllati e 19
invocazioni dirette stdlib. La wheel corrisponde ai 90 sorgenti invariati
del pacchetto. Anche la CI del merge PR78 è verde.
Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Collaudo complessivo della matrice Windows e degli ingressi/errori; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Script e installazione | Venti dei 26 script operativi Python hanno una disposizione verificata, inclusi i due entry point del prototipo di prove forensi, ora esplicitamente indisponibili senza modificare il caso, i due publisher legacy dei tracker, i due host/IP/ASN, i due mapper dei kit e i due predittori operativi. Pacchetto costruito realmente e confrontato con sorgenti, entrypoint e template. | Altri 6 script Python e 2 launcher shell; helper non esercitati; installazione isolata finale e componenti opzionali sulle piattaforme supportate. |
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
