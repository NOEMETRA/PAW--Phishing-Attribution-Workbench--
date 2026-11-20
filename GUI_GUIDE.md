# Guida alla GUI di PAW

## Introduzione

PAW (Phishing Analysis Workstation) è uno strumento completo per l'analisi di campagne di phishing. La GUI fornisce un'interfaccia grafica intuitiva per gestire l'analisi, il monitoraggio e l'intelligence geografica delle vittime.

## Come Avviare la GUI

Per avviare la GUI, assicurati di essere nella directory principale del progetto PAW e esegui il seguente comando:

```bash
python -c "import sys, os; os.chdir(r'C:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\PAW'); sys.path.insert(0, '.'); from paw.gui.tk_gui import main; main()"
```

In alternativa, puoi usare il modulo Python:

```bash
python -m paw.gui.tk_gui
```

## Struttura della GUI

La GUI è organizzata in diversi tab, ciascuno dedicato a una funzionalità specifica:

### 1. Tab Analisi (Analysis)

Questo tab permette di analizzare file EML di phishing:

- **Seleziona File EML**: Clicca su "Sfoglia" per selezionare un file .eml da analizzare
- **Analizza**: Avvia l'analisi del file selezionato
- **Risultati**: Visualizza i risultati dell'analisi, inclusi punteggi di rischio, indicatori di compromissione e raccomandazioni

### 2. Tab Geografico (Geographic)

Fornisce analisi geografica delle vittime e identificazione degli attaccanti:

- **Analizza Vittime**: Mostra statistiche sulle vittime per paese, città e provider ISP
- **Identifica Attaccanti**: Analizza pattern geografici per identificare possibili origini degli attacchi
- **Mappa delle Vittime**: Visualizza una rappresentazione geografica delle interazioni delle vittime
- **Esporta Dati**: Salva i dati geografici in formato CSV per ulteriori analisi

### 3. Tab Auto Tunnel

Gestisce l'esposizione pubblica del server Canary tramite tunneling:

- **Ngrok**: Configura e avvia un tunnel ngrok per esporre la porta del server Canary
- **Cloudflared**: Opzione alternativa con Cloudflare Tunnel
- **Localtunnel**: Tunnel basato su Node.js per ambienti locali
- **Stato Tunnel**: Monitora lo stato attivo dei tunnel e gli URL pubblici generati

### 4. Tab Dashboard in Tempo Reale (Real-time Dashboard)

Monitora in tempo reale le campagne e le attività delle vittime:

- **Campagne Attive**: Elenco delle campagne di phishing attualmente monitorate
- **Vittime**: Numero totale di vittime e statistiche di interazione
- **Alert**: Notifiche in tempo reale per nuove attività sospette
- **Auto-refresh**: Aggiornamento automatico ogni 30 secondi (può essere disabilitato)

## Funzionalità Principali

### Analisi EML
- Parsing completo dei file EML
- Estrazione di URL, allegati e metadati
- Scoring automatico del rischio
- Generazione di report dettagliati

### Monitoraggio Vittime
- Tracking dei click sulle URL di phishing
- Raccolta di fingerprinting (IP, User-Agent, timestamp)
- Geolocalizzazione automatica
- Integrazione con database Sentinel

### Intelligence Geografica
- Mappatura delle posizioni delle vittime
- Analisi dei pattern di attacco
- Identificazione di cluster geografici
- Esportazione dati per analisi esterne

### Tunneling Automatico
- Configurazione rapida di tunnel pubblici
- Supporto multi-provider (ngrok, cloudflared, localtunnel)
- Monitoraggio dello stato dei tunnel
- URL pubblici per testing e monitoraggio

## Configurazione e Prerequisiti

### Dipendenze
Assicurati di avere installate le seguenti dipendenze:

```bash
pip install -r requirements.txt
```

### Configurazione Ngrok
Per utilizzare il tunneling automatico:

1. Installa ngrok dal sito ufficiale
2. Configura il token di autenticazione: `ngrok config add-authtoken YOUR_TOKEN`
3. La GUI gestirà automaticamente l'avvio e l'arresto dei tunnel

### Database Sentinel
Il sistema utilizza SQLite per il monitoraggio. Il database viene creato automaticamente al primo avvio.

## Troubleshooting

### Problemi Comuni

**GUI non si avvia**
- Verifica che tutte le dipendenze siano installate
- Controlla che Python sia nella versione corretta (3.13+)
- Assicurati di essere nella directory corretta del progetto

**Errori di encoding Unicode (es. 'charmap' codec can't encode character)**
- ✅ **RISOLTO**: La GUI ora forza automaticamente l'encoding UTF-8 per tutti i processi
- Questo problema si verificava su Windows quando PAW usava caratteri Unicode (→, ✓, etc.)
- La correzione garantisce che l'output venga visualizzato correttamente nella dashboard

**Errore di connessione al database**
- Verifica che il file del database non sia corrotto
- Controlla i permessi di scrittura nella directory del progetto

**Tunnel non funziona**
- Verifica che ngrok sia installato e configurato
- Controlla che la porta del server Canary sia libera
- Assicurati che non ci siano firewall bloccanti

**Analisi EML fallisce**
- Verifica che il file EML sia valido e non corrotto
- Controlla che il file non sia troppo grande
- Assicurati che l'estensione sia .eml
- Se vedi errori di DNS (getaddrinfo failed), verifica la connessione internet

### Log e Debug
I log dettagliati sono disponibili nella console quando avvii la GUI. Per debug avanzato, puoi:

1. Aprire un terminale separato
2. Navigare nella directory PAW
3. Eseguire: `python -c "import logging; logging.basicConfig(level=logging.DEBUG); exec(open('paw/gui/tk_gui.py').read())"`

## Esempi di Utilizzo

### Analisi Completa di una Campagna
1. Avvia la GUI
2. Nel tab Analisi, seleziona un file EML
3. Clicca "Analizza" per ottenere il report iniziale
4. Nel tab Auto Tunnel, avvia un tunnel ngrok
5. Condividi l'URL pubblico per testing
6. Monitora i click nel tab Dashboard
7. Analizza i pattern geografici nel tab Geografico

### Monitoraggio in Tempo Reale
1. Avvia il server Canary separatamente
2. Nella GUI, vai al tab Dashboard
3. Abilita l'auto-refresh
4. Osserva l'arrivo di nuovi dati dalle vittime

## Supporto e Contributi

Per segnalare bug o richiedere funzionalità, apri un issue nel repository GitHub.

## Licenza

Per i termini applicabili a questa versione, consultare il file LICENSE.