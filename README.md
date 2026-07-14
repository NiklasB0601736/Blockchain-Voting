# Blockchain-basiertes Wahlsystem

Praesentationsfaehiger Lernprototyp fuer ein verteiltes und oeffentlich
pruefbares Wahlsystem. Der aktuelle V2-Weg kombiniert eine eigene
Python-Blockchain, drei getrennte Nodes, lokale Browser-Verschluesselung,
homomorphe Auszaehlung und 3-aus-5-Threshold-Decryption.

Das Projekt ist kein produktives E-Voting-System. Es demonstriert den
technischen Datenfluss und benennt die fehlenden Sicherheitsbausteine offen.

## Was der Prototyp zeigt

- getrennte Validator- und Observer-Nodes mit eigenen `DATA_DIR`s
- Mempool, signierte PoA-Blocks, Peer-Sync und JSON-Persistenz
- Wahlverwaltung mit Kandidaten-Indizes und Committee-Public-Key
- lokale P-256-EC-ElGamal-Verschluesselung im Voter-Browser
- keine Namen, Voter-Secrets oder Klarstimmen in Node-Requests und Chain
- deterministisch an ein registriertes Commitment gebundene Demo-Nullifier
- homomorphe Addition aller encrypted Ballots
- private Committee-Shares als einzelne lokale JSON-Dateien
- clientseitige Partial Decryptions und Chaum-Pedersen-Proofs
- Petlib-Verifikation des veroeffentlichten Ergebnisses auf jeder Node
- separater Voter-Server; Dashboard und Committee bleiben auf der Node

Der aktuelle Nullifier ist absichtlich nur eine robuste Demo-Loesung: Seine
Bindung an das oeffentliche Commitment verhindert frei erfundene Nullifier,
ist aber nicht anonym. Ein produktives System braucht dafuer einen echten
ZK-Membership-/Nullifier-Proof, zum Beispiel nach dem Semaphore-Prinzip.

## Datenfluss

1. Das Dashboard erzeugt Committee-Keymaterial lokal im Browser.
2. Nur Public Key und Public Shares gehen in `create_election` auf die Chain.
3. Jeder private Member-Share wird als eigene Datei gespeichert.
4. Der separat ausgelieferte Voter-Browser liest die Wahldaten von einer Node
   und bildet One-Hot, Commitment und Nullifier lokal.
5. Die Node erhaelt nur `encrypted_ballot`, Hashes und Proof-Platzhalter.
6. Der Validator committed gueltige Mempool-Transaktionen in einen Block.
7. Committee-Mitglieder laden mindestens den Threshold einzelner Share-Dateien.
8. Der Committee-Browser aggregiert, entschluesselt den Tally und erzeugt Proofs.
9. Jede Node prueft Tally, Partial Decryptions und Klarergebnis mit Petlib.

## Rollen

- **Admin:** darf `create_election` und `finalize_election` einreichen.
- **Node Operator:** darf Peers aendern, synchronisieren und Blocks minen.
- **Voter:** registriert ein Demo-Commitment und sendet encrypted Ballots.
- **Committee:** publiziert nur einen kryptografisch gueltigen Threshold-Tally.
- **Observer:** liest Chain-Daten und verifiziert das Ergebnis ohne private Shares.

Die V2-API verwendet fuer die beiden privilegierten Rollen die Header
`X-Admin-Key` und `X-Node-Key`. Defaults der lokalen Demo sind
`dev_admin_key` und `dev_node_key`.

## Projektstruktur

```text
voting_system/     FastAPI, Chain-Core und Petlib-Kryptografie
web/               Dashboard, Voter, Committee und Browser-Crypto
scripts/           Node Controller, Demo-Netzwerk und CLI-Client
tests/             Python-, HTTPS-Prozess- und Interoperabilitaetstests
tests_js/          Browser-Kryptografie-Tests
docs/              Anleitungen und Architekturdiagramme
archive/           historische Python- und Ethereum-Prototypen
```

Der aktive Node-Einstieg ist `voting_system/node_server.py`; der Chain-Core
liegt in `voting_system/distributed_blockchain.py`. Historische V1-, Paillier-,
Pure-Python-ElGamal- und Ethereum-Entwuerfe liegen ausschliesslich im Archiv.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/pip3 install -r requirements.txt
```

Das fertige Browser-Crypto-Bundle liegt unter
`web/assets/voting_crypto.bundle.js`. Nur fuer Aenderungen daran werden Node.js
und npm benoetigt:

```bash
npm install
npm run build:web-crypto
```

## Start

Empfohlen fuer die Praesentation:

```bash
.venv/bin/python scripts/v2_node_launcher.py
```

Im Controller `3-Node-Demo starten` waehlen. Danach:

```text
Dashboard: https://127.0.0.1:5001/dashboard
Voter:     https://127.0.0.1:7000/?node=https://127.0.0.1:5001
Committee: https://127.0.0.1:5001/committee
Node 2:    https://127.0.0.1:5002/dashboard
Node 3:    https://127.0.0.1:5003/dashboard
API Docs:  https://127.0.0.1:5001/docs
```

Alternativ direkt:

```bash
.venv/bin/python scripts/run_v2_demo_network.py --reset
```

### Lokales HTTPS-Zertifikat

Beim ersten Start erzeugt das Projekt unter `.node-data/tls/` eine lokale
Entwicklungs-CA und ein von ihr signiertes Zertifikat fuer `localhost` und
`127.0.0.1`. Nodes, Voter-Server und Python-Clients verwenden HTTPS; auch die
Peer-Synchronisation prueft dieses Zertifikat gegen die lokale CA.

Damit der Browser keine Zertifikatswarnung zeigt, muss
`.node-data/tls/development-ca.pem` einmal als vertrauenswuerdige Root-CA in den
lokalen Zertifikatsspeicher importiert werden. Auf macOS geht das ueber
`Schluesselbundverwaltung -> System -> Zertifikate importieren`; danach fuer
dieses Entwicklungszertifikat `Immer vertrauen` setzen. Diese CA ist nur fuer
die lokale Demo bestimmt und darf nicht fuer produktive Systeme verwendet
werden.

Zertifikate koennen auch vor dem Start explizit erzeugt werden:

```bash
npm run tls:generate
```

Fuer einen LAN-Test muss die verwendete IP-Adresse als SAN aufgenommen werden:

```bash
.venv/bin/python scripts/generate_dev_tls.py --force --host 192.168.178.42
```

Der zweite Rechner muss derselben `development-ca.pem` vertrauen. Die private
Datei `development-ca-key.pem` darf den erzeugenden Rechner nicht verlassen.

Der Demo-Start erzeugt vier getrennte HTTPS-Prozesse: drei Blockchain-Nodes und den
zustandslosen Voter-Server auf Port `7000`. Eine einzelne Node und der Voter
koennen auch separat gestartet werden:

```bash
.venv/bin/python -m voting_system.node_server
.venv/bin/python -m voting_system.voter_client_server
```

Die Node liefert bewusst keine `/voter`-Route mehr aus. Der Voter kommuniziert
ueber die sichtbare HTTPS-Node-API mit einer ausgewaehlten Node; CORS ist fuer
diese Cross-Origin-Anfragen im Prototyp aktiviert.

Eine einzelne Node:

```bash
PORT=5001 \
V2_ADMIN_KEY=dev_admin_key \
V2_NODE_KEY=dev_node_key \
.venv/bin/python -m voting_system.node_server
```

Optionale TLS-Konfiguration fuer eigene Zertifikate:

```text
TLS_CERT_FILE=/absoluter/pfad/server-cert.pem
TLS_KEY_FILE=/absoluter/pfad/server-key.pem
TLS_CA_CERT=/absoluter/pfad/ca-cert.pem
TLS_EXTRA_HOSTS=localhost,192.168.178.42
```

Ohne diese Variablen wird automatisch das lokale Material unter
`.node-data/tls/` verwendet. `TLS_EXTRA_HOSTS` wirkt nur bei der erstmaligen
Erzeugung; fuer eine nachtraeglich hinzugefuegte LAN-IP das Zertifikat mit
`scripts/generate_dev_tls.py --force --host ...` neu erzeugen.

## Bedienung

1. Im Dashboard Wahl erstellen und jeden Committee-Share einzeln speichern.
2. Im Voter Client Wahl laden, Secret eingeben und registrieren.
3. Dashboard: Mempool als Block minen.
4. Voter Client: Kandidat waehlen und encrypted Vote senden.
5. Dashboard: Vote-Block minen und Observer-Nodes synchronisieren.
6. Dashboard: `finalize_election` mit Admin-Key senden und minen.
7. Committee Client: mindestens Threshold Share-Dateien laden und Tally senden.
8. Dashboard: Tally-Block minen und `Verify` ausfuehren.

`result_status=verified` und `complete=true` bedeuten, dass ein publiziertes
Ergebnis vollstaendig gegen die committed encrypted Ballots geprueft wurde.
Ein offener Wahlzustand kann eine gueltige Chain haben, ist aber noch kein
verifiziertes Endergebnis.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests
npm run test:web-crypto
```

Die Tests umfassen unter anderem:

- Petlib EC-ElGamal und Threshold-Proofs
- Browser-Noble-Payloads gegen Python/Petlib
- Nullifier-Bindung und Double-Voting-Ablehnung
- Admin-/Node-Rollenkeys
- drei echte FastAPI-Prozesse mit HTTPS-Sync
- Auslieferung aller drei GUIs und des Crypto-Bundles

## Bewusste Grenzen

- keine echten Semaphore-/Membership-Proofs
- kein ZK-Ballot-Proof fuer genau eine verschluesselte Auswahl
- Demo-Registrierung ist keine reale Ausgabe von Wahlberechtigungen
- das Dashboard erzeugt bei der Wahlerstellung kurzzeitig alle privaten
  Committee-Shares gemeinsam im Browser des Administrators; ein Produktivsystem
  braucht ein Distributed Key Generation Protocol (DKG), damit die Mitglieder
  den gemeinsamen Public Key verteilt erzeugen und keine einzelne Stelle jemals
  alle privaten Schluesselanteile besitzt
- private Share-Dateien haben noch keinen Hardware-/Passwortschutz
- einfacher PoA-Konsens und manuell angestossener Peer-Sync
- keine BFT-Fork-Aufloesung, Datenbank oder parallele Transaktionssperren
- kein Schutz gegen IP-, Timing- und Reihenfolge-Metadaten
- lokale Entwicklungs-CA statt produktiver PKI, Zertifikatsrotation oder
  automatisierter Geheimnisverwaltung
- keine formale Sicherheitsanalyse, Audits oder rechtliche Zulassung

Historische Entwuerfe liegen nur noch als Lern- und Forschungsreferenzen unter
`archive/` und gehoeren nicht zum aktiven Startpfad.

## Grafiken

![Schichtenmodell](docs/diagrams/layered-architecture.svg)

![Encrypted Tally Flow](docs/diagrams/encrypted-tally-flow.svg)
