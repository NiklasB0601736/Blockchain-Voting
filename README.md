# Blockchain-basiertes Wahlsystem

Lokale Demo fuer ein transparentes Wahlsystem mit FastAPI, einfacher
Blockchain-Integritaetspruefung und einem HTML-Frontend.

Wichtig: Die Python-App ist aktuell eine Demo-Implementierung. Der Solidity
Contract zeigt die Richtung fuer Ethereum, zkSync und Semaphore, ist aber noch
nicht vollstaendig mit echter Zero-Knowledge-Proof-Verifikation angebunden.

## Funktionen

- Oeffentliche Ergebnisse nach Wahlende: `GET /api/results/{election_id}`
- Oeffentliche Integritaetspruefung: `GET /api/verify/{election_id}`
- Admin-Funktionen fuer Wahl erstellen und beenden
- Registrierung per anonymem Commitment
- Schutz gegen doppelte Registrierung und doppelte Abstimmung
- Browser-Frontend fuer die vorhandenen Backend-Endpunkte

## Projektdateien

- `blockchainV1.py` - Python Backend mit Blockchain-Core und FastAPI
- `frontend.html` - Web-Interface fuer die FastAPI
- `test_voting.py` - Demo-Testlauf fuer die Kernlogik
- `contracts/VotingContract.sol` - Solidity-Entwurf fuer On-Chain Voting
- `hardhat.config.js` - Hardhat-Konfiguration
- `QUICK_START.txt` - kurze Bedienungsanleitung

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Start

```bash
ADMIN_KEY=dev_admin_key python3 blockchainV1.py
```

Die API laeuft danach unter:

```text
http://127.0.0.1:5000
```

Die interaktive FastAPI-Dokumentation ist erreichbar unter:

```text
http://127.0.0.1:5000/docs
```

Falls Port 5000 auf deinem Mac schon belegt ist:

```bash
PORT=5001 ADMIN_KEY=dev_admin_key python3 blockchainV1.py
```

Dann im Frontend die API URL auf `http://127.0.0.1:5001` setzen.

Das Frontend kann direkt im Browser geoeffnet werden:

```bash
open frontend.html
```

Wenn kein `ADMIN_KEY` gesetzt ist, verwendet die Demo den lokalen Default
`your_secret_admin_key_here`.

## Tests

```bash
python3 test_voting.py
```

## API

### Oeffentlich

```http
GET /api/elections
GET /api/elections/{election_id}
GET /api/results/{election_id}
GET /api/verify/{election_id}
GET /api/blockchain/chain
GET /api/blockchain/valid
GET /api/health
```

### Admin

Admin-Endpunkte erwarten den Header `X-Admin-Key`.

```http
POST /api/elections
POST /api/elections/{election_id}/finalize
```

### Benutzer

```http
POST /api/voters/register
POST /api/vote
```

## Beispielablauf

1. Wahl erstellen.
2. Wahl-ID in Registrierung, Abstimmung und Verifikation uebernehmen.
3. Waehler-Commitment erzeugen oder eintragen.
4. Waehler registrieren.
5. Stimme abgeben.
6. Wahl finalisieren.
7. Ergebnisse und Integritaet oeffentlich abrufen.

## Naechste Ausbaustufe

- Echte Semaphore-Proof-Erzeugung und Verifikation anbinden
- Solidity Contract kompilierbar testen und Deployment-Script ergaenzen
- Persistente Speicherung statt In-Memory-Daten
- Automatisierte API-Tests mit `pytest`
