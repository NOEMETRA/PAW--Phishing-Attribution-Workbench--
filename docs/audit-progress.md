# Stato dell'audit PAW

Riferimento integrato: PR83, commit
`17803da09691674fff2e5811e500f890767b6800`; checkpoint del 23 ottobre 2026
(Europe/Rome). I due P2 fondati della review sono corretti: timestamp di controlli
e aggiornamenti di intelligence campionati dentro il lock di scrittura.
Review finale Codex senza rilievi sullo head `6e113d3e92ca53bed2ce9f90b111e47dd31eb491`,
con tre controlli CI verdi su head e merge e tree identico al revisionato.
La prova PR83 è di 838 test, 826 superati e 12 esclusioni, con writer effettivi,
full originale no-egress, conservazione verify/ZIP e wheel di 90 sorgenti.

Il blocco corrente completa i [contratti offline supportati di Sentinel](sentinel-offline-completion.md)
come famiglia: tutti gli otto moduli esistenti, helper condiviso, CLI e alias.
Copre budget di query/JSON/output, viste SQLite transazionali, mutatori
stato/conferma/retention, config condivisa e copie dei getter, pubblicazione
geografica e inventari di tutti i file regolari ammessi. Ventitré ingressi/helper
attivi rifiutano sotto no-egress prima di I/O o thread; servizio e algoritmi attivi
restano S14. La chiusura è del perimetro offline dichiarato, soggetta alla review/CI
del nuovo blocco, non di ogni algoritmo del modulo o dell'intero motore.

Sullo head revisionato `6943305`: 879 test in 95,797 secondi, 866 superati e 13
esclusioni Windows. Quattro P2 fondati della review #84 sono corretti, con cinque
regressioni aggiuntive (41 nuovi contratti nella famiglia): null configurato,
alias mutabili dopo il salvataggio, limite HTML e budget directory condiviso.
Un quinto P2 allinea poi le due diciture CLI al perimetro senza esclusioni:
18 invocazioni reali verificano file nascosti/`.pyc`, conteggi e sorgenti invariati;
statici e wheel sono ripetuti dopo questa sola modifica di testo runtime.
I primi 36 nuovi contratti sul baseline PR83 riproducono 51 asserzioni
fallite e 24 errori, includendo sottocasi; non sono 75 difetti indipendenti.
Passano il nuovo collaudo freddo (2 API/11 CLI e un writer SQL separato), il full
originale no-egress (5 API/6 CLI, supervisore fermato, verify/ZIP byte per byte)
e la wheel reale di 91 sorgenti, metadata, entrypoint e due template.
Durante il blocco passano anche gli altri collaudi Sentinel/alias della matrice;
la ripetizione finale e i limiti sono distinti nel documento di completamento.
Nove sorgenti package esistenti cambiano, uno condiviso si aggiunge e 81 conservano
il contenuto Git. Le disposizioni dei 26 file Python esterni restano registrate;
i due launcher shell e gli helper non esercitati non sono validati per presenza.

Il lavoro corrente stabilizza il motore offline e la profondità delle evidenze.
Il [registro per famiglia](engine-stabilization-checkpoint.md) distingue contratti
verificati, audit aperti, capacità indisponibili e fasi successive.

| Area | Evidenze già disponibili | Cosa resta per chiuderla |
| --- | --- | --- |
| Esecuzione e conservazione | Cinque preset CLI e worker HTTP effettivi; no-egress applicativo, timeout/cancel/recovery, lettori bloccati durante scritture, originali, inventari, sigilli e ZIP verificati nei flussi registrati. | Collaudo complessivo della matrice Windows e degli ingressi/errori; evidenze POSIX separate in CI. |
| Estrazione offline | Contratti su header/MIME, Received e tempi dichiarati, corpi e messaggi incorporati, URL e trasformazioni, CID, allegati/ZIP; osservazioni statiche separate dalle interpretazioni. | Combinazioni malformate e contesti residui, limiti/omissioni, copertura di allegati e riconciliazione delle capacità pubblicizzate. |
| Risultati e pubblicazione | Contributi numerici e decisioni non arrotondate, bozze locali, query/export e grafi con fonti e limiti verificati nei casi documentati. Il [riepilogo del terminale](terminal-summary-evidence.md) riusa il report di autenticazione per evitare interpretazioni divergenti. | Altri report/publisher/consumer, tipi malformati, risorse e renderer; autenticità di firme/ancoraggi e conformità STIX/ARF/X-ARF non stabilite dai sigilli. |
| Sentinel locale | Campagne: validazione API condivisa, unicità di caso e rimozione condizionale nella transazione, rollback ed esito confermato. File: radice stabile, ammissione di tipi/percorsi, limiti dichiarati, rilevazione delle mutazioni testate e serializzazione della baseline per istanza. | Il blocco corrente completa i contratti offline dichiarati: budget dati/output, mutatori, config, file e vista transazionale con writer separato. Restano review/CI del blocco, riconciliazione con accettazione globale e supporto piattaforme; servizio/raccolta attiva restano S14. |
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

1. **Sentinel offline:** completati nel blocco corrente i contratti residui
   dichiarati, con matrice di disposizioni per tutto il package. Chiudere review/CI
   sullo stesso head e riconciliare con accettazione integrata e piattaforme;
   servizio, provider e raccolta attiva restano S14.
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
