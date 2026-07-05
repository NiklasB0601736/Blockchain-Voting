# Blockchain-basiertes Wahlsystem

Praesentationsfaehiger Demo-Prototyp fuer ein transparentes, verteilbares
Wahlsystem. Der aktuelle Stand kombiniert eine eigene Python-Blockchain,
mehrere lokale Nodes, verschluesselte Petlib-Ballots, Nullifier gegen Double
Voting, homomorphe Auszaehlung und eine Threshold-Entschluesselung durch ein
Wahlkomitee.

Wichtig: Das Projekt ist bewusst ein Lern- und Demo-Prototyp, kein
produktives E-Voting-System. Es zeigt den technischen Ablauf und macht die
naechsten Sicherheitsbausteine sichtbar. Echte Semaphore-Proofs, echte
Ballot-ZK-Proofs, produktive Schluesselverwaltung, Metadaten-Schutz, Audits und
rechtliche Zertifizierung sind nicht implementiert.

## Aktueller Stand

Der Prototyp besteht aus zwei Ebenen:

1. `blockchainV1.py` bleibt als einfache lokale Lern-Demo erhalten.
2. Die neue v2-Chain unter `/api/v2` ist der eigentliche
   praesentationsfaehige Stand.

Die v2-Demo kann aktuell:

- lokale Node 1/2/3 mit getrennten `DATA_DIR`s starten
- Blocks per Proof-of-Authority und Ed25519 signieren
- valide Transaktionen zuerst im Mempool anzeigen
- nach Mining committed Blocks anzeigen
- Nodes per Peer-/Sync-Endpunkt synchronisieren
- Wahlen mit Kandidaten-Indizes erstellen
- Voter getrennt vom Node Dashboard registrieren
- Stimmen als verschluesselte Petlib-Ballots speichern
- Double Voting per `nullifier_hash` ablehnen
- keine Namen und keine Klarstimmen auf der v2-Chain speichern
- encrypted Ballots homomorph aggregieren
- Threshold-Auszaehlung durch ein Committee veroeffentlichen
- Partial Decryptions und Chaum-Pedersen-Proofs oeffentlich pruefen
- im Dashboard zeigen, ob Chain, Nullifier, encrypted Tally, Proofs und
  Plaintext Result zusammenpassen

## Grenzen des Prototyps

Diese Punkte sind bewusst nicht fertig implementiert und gehoeren in den
Ausblick der Praesentation:

- echte Semaphore-/Membership-Proofs fuer anonyme Wahlberechtigung
- echte ZK-Proofs, dass ein encrypted Ballot genau eine gueltige Option enthaelt
- produktive, getrennte Ausgabe und Speicherung von Committee-Shares
- Schutz gegen Netzwerk-Metadaten wie IP-Adresse, Timing und Reihenfolge
- robuster produktiver Konsens statt einfacher PoA-Demo
- echte Auditierbarkeit, formale Sicherheitsanalyse und rechtliche Zulassung
- Ethereum-/Solana-/Smart-Contract-Deployment

## Architektur-Grafiken

### Schichtenmodell

![Zero-Trust Voting Schichtenmodell](docs/diagrams/layered-architecture.svg)

### Verschluesselte Auszaehlung

![Encrypted Tally Flow](docs/diagrams/encrypted-tally-flow.svg)

### Projektdateien

- `blockchainV1.py` - Python Backend mit Blockchain-Core und FastAPI
- `distributed_blockchain.py` - v2 Chain-Core mit PoA-Nodes, Mempool,
  JSON-Persistenz und verschluesselten Vote-Transaktionen
- `frontend.html` - Web-Interface fuer die FastAPI
- `frontend_v2.html` - Live-Dashboard fuer v2 Nodes, Mempool, Chain,
  verschluesselte Ballots und Verify-Status
- `voter_client.html` - getrennte Voter-Ansicht fuer Registrierung und
  verschluesselte Stimmabgabe
- `committee_client.html` - getrennte Committee-Ansicht fuer Threshold-Tally,
  Ergebnis-Publish und Proof-Verifikation
- `v2_demo_client.py` - separates Demo-Programm fuer Voter-/Committee-Aktionen
- `v2_node_launcher.py` - GUI-Launcher fuer eine einzelne lokale Node
- `run_v2_demo_network.py` - startet Node 1/2/3 als lokale Multi-Node-Demo
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

Falls `petlib` auf macOS keine OpenSSL-Header findet:

```bash
CPPFLAGS=-I/opt/homebrew/opt/openssl@3/include LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib pip install -r requirements.txt
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

## V2: Verteilte Python-Chain

Die neue v2-Chain laeuft neben der bisherigen Demo unter `/api/v2`. Sie nutzt
Proof-of-Authority mit Ed25519-Blocksignaturen, einen Mempool, JSON-Persistenz
pro Node und speichert verschluesselte Petlib-Ballots statt Klarstimmen.

Validator-Key fuer lokale Tests erzeugen:

```bash
python3 - <<'PY'
from distributed_blockchain import generate_validator_keypair
print(generate_validator_keypair())
PY
```

Eine lokale Validator-Node starten:

```bash
NODE_ID=node1 \
NODE_PRIVATE_KEY=<private_key_hex> \
VALIDATORS_JSON='{"node1":"<public_key_hex>"}' \
DATA_DIR=.node-data/node1 \
PORT=5001 \
ADMIN_KEY=dev_admin_key \
python3 blockchainV1.py
```

Weitere Nodes bekommen ein eigenes `NODE_ID`, `DATA_DIR` und optional `PEERS`,
z.B. `PEERS=http://127.0.0.1:5001`. Die wichtigsten v2-Endpunkte:

```http
GET  /api/v2/node/info
GET  /api/v2/chain
GET  /api/v2/mempool
POST /api/v2/transactions
POST /api/v2/blocks/mine
POST /api/v2/peers
POST /api/v2/sync
GET  /api/v2/elections/{election_id}/verify
```

Grenze des Prototyps: Semaphore und echte Ballot-ZK-Proofs sind noch
Platzhalter-Felder. Die Chain prueft aber bereits Nullifier, verschluesselte
Ballot-Formate, Blocksignaturen und veroeffentlichte Threshold-Tally-Proofs.

### V2 visuell demonstrieren

Einfachster Start per Launcher-GUI:

```bash
python3 v2_node_launcher.py
```

Im Launcher sind Node-ID, Port, Data-Dir, Validator-Key, Validator-Liste und
Peers sichtbar editierbar. Der Button `Node starten` startet die API mit diesen
Werten, ohne dass der lange Env-Aufruf per Hand getippt werden muss.

Wenn du einen neuen Validator-Key erzeugst, aber dasselbe `DATA_DIR`
weiterverwendest, koennen alte Bloeke nicht mehr zur neuen Signatur passen. Der
Launcher erkennt das und bietet an, den lokalen Demo-State unter `.node-data`
zurueckzusetzen.

Dashboard oeffnen:

```text
http://127.0.0.1:5001/dashboard
```

Das Dashboard zeigt Node-Status, Mempool, neuesten Block, committed Elections,
encrypted Ballots, encrypted Tally, Published Result, Multi-Node-Vergleich und
Verify-Checks.

Getrennte Voter-Ansicht oeffnen:

```text
http://127.0.0.1:5001/voter
```

Der Voter Client zeigt Wahl, Kandidaten-Indizes, lokales Demo-Secret,
One-Hot-Vorschau, Nullifier und die verschluesselte Vote-Transaktion getrennt
von der Node-Ansicht.

Getrennte Committee-Ansicht oeffnen:

```text
http://127.0.0.1:5001/committee
```

Der Committee Client zeigt encrypted Ballots, lokale Demo-Committee-Shares,
Threshold-Status, encrypted Tally, plaintext Tally und publisht
`publish_tally_result` mit Partial Decryptions und Proofs auf die Chain.

Lokales Drei-Node-Netzwerk fuer die Praesentation starten:

```bash
python3 run_v2_demo_network.py --reset
```

Das Skript startet:

```text
node1: http://127.0.0.1:5001  Validator, kann minen
node2: http://127.0.0.1:5002  Observer, kann syncen
node3: http://127.0.0.1:5003  Observer, kann syncen
```

Jede Node nutzt ein eigenes `DATA_DIR` unter `.node-data/v2-demo-network`.
`--reset` loescht nur diesen Demo-Netzwerk-State, damit alte Chains oder alte
Validator-Keys die Vorfuehrung nicht stoeren.

Ein kompletter Demo-Ablauf gegen eine laufende Validator-Node:

```bash
python3 v2_demo_client.py --api-url http://127.0.0.1:5001 full-demo
```

Der Demo-Client erzeugt lokal ein Committee, legt eine Wahl an, registriert
Demo-Waehler, verschluesselt Stimmen, mined Bloeke, finalisiert die Wahl und
publisht das Threshold-Tally. Die private Committee-State-Datei bleibt lokal
unter `.node-data/v2-demo-client-state.json`.

Die Rollen koennen auch einzeln gezeigt werden:

```bash
python3 v2_demo_client.py --api-url http://127.0.0.1:5001 create-election --mine
python3 v2_demo_client.py --api-url http://127.0.0.1:5001 register --voter alice --mine
python3 v2_demo_client.py --api-url http://127.0.0.1:5001 vote --voter alice --candidate-index 0 --mine
python3 v2_demo_client.py --api-url http://127.0.0.1:5001 finalize --mine
python3 v2_demo_client.py --api-url http://127.0.0.1:5001 publish-tally --members 1,2,3 --mine
```

## Tests

```bash
python3 test_voting.py
```

Fuer die automatisierten Regressionstests:

```bash
python3 -m unittest test_crypto_tally.py test_crypto_elgamal_tally.py test_crypto_petlib_elgamal_tally.py test_distributed_blockchain.py test_voting.py
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
- Produktivere Persistenz/DB statt JSON-Dateien
- Echte Ballot-ZK-Proofs statt Platzhalter-Felder
- LAN-/Internet-Demo mit Firewall-/Tunnel-Setup aus `LAN_NODE_TEST_PLAN.txt`
