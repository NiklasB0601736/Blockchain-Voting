# Blockchain-basiertes Wahlsystem

Dieses Projekt ist ein praesentationsfaehiger Lernprototyp fuer ein verteiltes,
verschluesseltes und oeffentlich pruefbares Wahlsystem. Es kombiniert eine
eigene Python-Blockchain mit mehreren Nodes, lokale EC-ElGamal-Verschluesselung
im Browser, homomorphe Auszaehlung und eine Threshold-Entschluesselung durch ein
Committee.

Der Prototyp bildet einen vollstaendigen technischen Wahlablauf ab. Er ist
jedoch kein produktionsreifes E-Voting-System und darf nicht fuer reale Wahlen
oder echte personenbezogene Daten eingesetzt werden.

## Funktionsumfang

Der aktuelle Stand unterstuetzt:

- einen Validator und mehrere getrennte Observer-Nodes
- eigene Chain-, Mempool- und Peer-Dateien pro Node
- Proof-of-Authority-Blocks mit Ed25519-Signaturen
- HTTPS-Kommunikation mit einer lokalen Entwicklungs-CA
- manuelle Peer-Registrierung und Synchronisation
- Erstellen und vorzeitiges Beenden einer Wahl
- frei definierbare, eindeutig nummerierte Kandidaten
- lokale Erzeugung eines Threshold-Committees
- Registrierung eines pseudonymen Demo-Commitments
- lokale One-Hot-Verschluesselung einer Stimme im Voter-Browser
- Ablehnung eines erneut verwendeten, an das Commitment gebundenen Nullifiers
- homomorphe Aggregation der verschluesselten Stimmen
- Threshold-Auszaehlung mit mindestens `t` von `n` Committee-Shares
- Chaum-Pedersen-Beweise fuer korrekte Partial Decryptions
- Veroeffentlichung und unabhaengige Pruefung des Gesamtergebnisses
- getrennte Oberflaechen fuer Node/Admin, Voter und Committee

## Systemgrenze

Der Prototyp zeigt den Datenfluss und die kryptografischen Grundideen. Folgende
Aussagen gelten bewusst **nicht**:

- Eine Registrierung beweist keine reale Wahlberechtigung.
- Der Platzhalter fuer den Eligibility-Proof ist kein anonymer
  Zero-Knowledge-Membership-Proof.
- Der Platzhalter fuer den Ballot-Proof beweist nicht gegenueber der Node, dass
  der Ciphertext genau eine gueltige One-Hot-Stimme enthaelt.
- Ein einfacher PoA-Validator bietet keinen dezentralen BFT-Konsens.
- Lokale JSON-Dateien und Entwicklungsschluessel sind keine produktive
  Schluessel- oder Datenbankinfrastruktur.

Diese Grenzen sind keine versteckten Fehler, sondern abgegrenzte Ausbaustufen
des Lernprototyps. Eine vollstaendige Liste steht unter
[Bewusste Grenzen](#bewusste-grenzen).

## Architektur

Das System besteht aus vier logisch getrennten Bereichen:

1. **Blockchain-Nodes**
   Jede Node verwaltet eine eigene persistierte Chain, einen Mempool und eine
   Peer-Liste. Alle Nodes validieren Blocks, Signaturen und Transaktionen
   selbst. In der Standarddemo besitzt nur Node 1 den Validator-Private-Key.

2. **Node-Dashboard**
   Das Dashboard dient der Administration und Beobachtung. Es erstellt Wahlen,
   zeigt Mempool und Chain, mined Blocks, synchronisiert Peers und startet die
   oeffentliche Ergebnispruefung.

3. **Separater Voter Client**
   Der Voter Client laeuft auf einem eigenen zustandslosen HTTPS-Server. Er
   liest oeffentliche Wahldaten von einer ausgewaehlten Node und erzeugt
   Commitment, Nullifier und verschluesselten Stimmzettel lokal im Browser.

4. **Committee Client**
   Der Committee Client wird von einer Node ausgeliefert, verarbeitet private
   Share-Dateien aber ausschliesslich im Browser. Er aggregiert die Ballots,
   erstellt Partial Decryptions und publiziert das pruefbare Gesamtergebnis.

### Datenfluss einer Wahl

1. Das Dashboard erzeugt Committee-Keymaterial lokal im Browser.
2. Nur Public Key, Public Shares und Wahlmetadaten gelangen in den Mempool.
3. Der Validator nimmt die Transaktion in einen signierten Block auf.
4. Der Voter registriert ein Commitment und verschluesselt seine Wahl lokal.
5. Die Node erhaelt nur Ciphertexts, Commitment-Bezug, Nullifier und die beiden
   explizit markierten Proof-Platzhalter.
6. Der Validator committed die Vote-Transaktion in die Chain.
7. Nach der Finalisierung aggregiert das Committee alle committed Ballots.
8. Mindestens der konfigurierte Threshold erzeugt Partial Decryptions.
9. Das Committee publiziert encrypted Tally, Klarergebnis und Proofs.
10. Jede Node rekonstruiert den Wahlzustand aus der Chain und prueft das
    publizierte Ergebnis ohne private Committee-Shares.

## Kryptografisches Modell

### Stimmenverschluesselung

Die Browser-Implementierung verwendet EC-ElGamal auf P-256. Fuer `k` Kandidaten
wird eine Stimme als One-Hot-Vektor verschluesselt, zum Beispiel:

```text
Kandidat 0: [1, 0, 0]
Kandidat 1: [0, 1, 0]
Kandidat 2: [0, 0, 1]
```

Jede Komponente wird separat und mit frischer Zufallszahl verschluesselt. Die
Ciphertexts koennen punktweise addiert werden. Dadurch entsteht fuer jeden
Kandidaten ein verschluesselter Gesamtwert, ohne einzelne Stimmen zu
entschluesseln.

### Threshold-Entschluesselung

Der gemeinsame geheime Schluessel wird per Shamir Secret Sharing in `n` Shares
aufgeteilt. Zur Entschluesselung reichen beliebige `t` unterschiedliche Shares.
Weniger als `t` Shares koennen das Ergebnis nicht rekonstruieren.

Die Standarddemo verwendet `3 aus 5`. Die privaten Shares werden bei der
Wahlerstellung als getrennte JSON-Dateien gespeichert und gehoeren nicht auf
die Chain.

### Chaum-Pedersen-Proofs

Ein Committee-Mitglied mit geheimem Share `s_i` besitzt den oeffentlichen Share
`Y_i = s_i * G`. Fuer die aggregierte Ciphertext-Komponente `A` veroeffentlicht
es den Entschluesselungsfaktor `D_i = s_i * A`.

Der Chaum-Pedersen-Beweis zeigt ohne Offenlegung von `s_i`, dass in beiden
Gleichungen derselbe geheime Share verwendet wurde:

```text
log_G(Y_i) = log_A(D_i)
```

Dieser Beweis sichert die korrekte **Teilentschluesselung des aggregierten
Tallys**. Er beweist weder Wahlberechtigung noch die Gueltigkeit eines einzelnen
One-Hot-Ballots.

### Was die Chain sieht

Gespeichert werden:

- Wahl-ID, Titel, Kandidaten und Zeitfenster
- Committee-Public-Key, Threshold und Public Shares
- Commitment-Hashes und gebundene Nullifier-Hashes
- EC-ElGamal-Ciphertexts
- encrypted Tally, Klarergebnis, Partial Decryptions und Proofs
- Transaktions-, Block- und Verkettungshashes
- Validator-ID und Blocksignatur

Nicht an die Node gesendet oder auf der Chain gespeichert werden:

- Name oder reale Identitaet des Voters
- Voter-Secret
- Kandidatenauswahl als Klarwert
- private Committee-Shares
- einzelne entschluesselte Stimmen

## Rollen und Schluessel

| Rolle | Aufgabe | Berechtigung |
| --- | --- | --- |
| Admin | Wahl erstellen und finalisieren | `X-Admin-Key` |
| Node Operator | Peers, Sync und Mining bedienen | `X-Node-Key` |
| Validator | Blocks kryptografisch signieren | Ed25519 `NODE_PRIVATE_KEY` |
| Observer-Node | Chain lesen, synchronisieren und validieren | kein Validator-Private-Key |
| Voter | Commitment registrieren und encrypted Vote senden | keine privilegierte API-Berechtigung |
| Committee | Tally mit privaten Shares erzeugen | gueltige Shares und Proofs statt API-Key |
| Observer | Chain und Ergebnis oeffentlich pruefen | nur Lesezugriff |

`X-Admin-Key` und `X-Node-Key` sind einfache Demo-Zugriffsschluessel fuer
API-Aktionen. Sie sind nicht mit dem Ed25519-Validator-Key oder den privaten
Committee-Shares identisch.

Die lokalen Standardwerte sind:

```text
Admin Key: dev_admin_key
Node Key:  dev_node_key
```

## Projektstruktur

```text
voting_system/
  node_server.py                     FastAPI-Node und HTML-Auslieferung
  voter_client_server.py             separater Voter-Webserver
  distributed_blockchain.py          Chain, Mempool, PoA, Sync und Wahlregeln
  crypto_petlib_elgamal_tally.py      Petlib-Krypto und Public Verify

web/
  frontend_v2.html                    Node- und Admin-Dashboard
  voter_client.html                   separater Voting Client
  committee_client.html               Committee-Auszaehlung
  src/voting_crypto.js                Browser-Krypto-Quellcode
  assets/voting_crypto.bundle.js      fertiges Browser-Bundle

scripts/
  v2_node_launcher.py                 grafischer Node Controller
  run_v2_demo_network.py              Start der lokalen Drei-Node-Demo
  v2_demo_client.py                   optionaler CLI-Democlient
  generate_dev_tls.py                 lokale TLS-CA und Zertifikate

tests/                                Python- und Prozessintegrationstests
tests_js/                             Tests der Browser-Kryptografie
docs/guides/                          Kurzstart und technische Referenz
```

`contracts/` ist kein Bestandteil des aktiven Python-Chain-Ablaufs. Das aktuelle
System verwendet weder Ethereum noch einen Smart Contract.

## Voraussetzungen und Installation

Vorausgesetzt werden Python, `venv` und fuer Aenderungen an der Browser-Krypto
zusaetzlich Node.js mit npm.

```bash
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/pip install -r requirements.txt
```

Das fertige JavaScript-Bundle ist eingecheckt. Fuer den normalen Start ist
deshalb kein `npm install` erforderlich. Nur nach Aenderungen an
`web/src/voting_crypto.js`:

```bash
npm install
npm run build:web-crypto
```

## HTTPS und lokale Zertifikate

Beim ersten Start erzeugt das Projekt unter `.node-data/tls/`:

```text
development-ca.pem       oeffentliches CA-Zertifikat
development-ca-key.pem   privater CA-Key, nicht weitergeben
server-cert.pem          lokales Serverzertifikat
server-key.pem           lokaler Server-Key
```

Python-Nodes und Python-Clients vertrauen dieser CA automatisch. Browser kennen
die lokale CA dagegen noch nicht und zeigen deshalb zunaechst eine
Zertifikatswarnung. Damit Safari und andere Browser die Demo ohne Warnung
oeffnen, muss `development-ca.pem` einmal in den Zertifikatsspeicher des
Betriebssystems importiert und als vertrauenswuerdig markiert werden.

Auf macOS:

1. `Schluesselbundverwaltung` oeffnen.
2. Den Schluesselbund `System` auswaehlen.
3. `.node-data/tls/development-ca.pem` importieren.
4. Das Zertifikat oeffnen und unter `Vertrauen` auf `Immer vertrauen` setzen.
5. Browser vollstaendig neu starten.

Material vorab erzeugen:

```bash
npm run tls:generate
```

Die Entwicklungs-CA ist ausschliesslich fuer die lokale Demo bestimmt. Wird sie
mit `--force` neu erzeugt, muss das alte CA-Zertifikat im Schluesselbund ersetzt
werden.

## Start der Demo

Der einfachste Start erfolgt ueber den grafischen Node Controller:

```bash
.venv/bin/python scripts/v2_node_launcher.py
```

Im Controller:

1. `Demo-State vorher resetten` aktivieren, wenn eine neue Wahl gewuenscht ist.
2. `3-Node-Demo starten` auswaehlen.
3. Warten, bis alle Prozesse als gestartet gemeldet werden.
4. `Demo Links oeffnen` auswaehlen.

Die Demo startet vier getrennte HTTPS-Prozesse:

| Dienst | Adresse |
| --- | --- |
| Node 1 Dashboard, Validator | `https://127.0.0.1:5001/dashboard` |
| Node 2 Dashboard, Observer | `https://127.0.0.1:5002/dashboard` |
| Node 3 Dashboard, Observer | `https://127.0.0.1:5003/dashboard` |
| Committee auf Node 1 | `https://127.0.0.1:5001/committee` |
| Separater Voter Client | `https://127.0.0.1:7000/?node=https://127.0.0.1:5001` |
| FastAPI-Dokumentation | `https://127.0.0.1:5001/docs` |

Alternativ ohne GUI:

```bash
.venv/bin/python scripts/run_v2_demo_network.py --reset
```

Eine einzelne Node und der Voter-Server koennen separat gestartet werden:

```bash
.venv/bin/python -m voting_system.node_server
.venv/bin/python -m voting_system.voter_client_server
```

Die Node besitzt absichtlich keine `/voter`-Route. Der Voter Client laeuft auf
Port `7000` und kommuniziert ueber die sichtbar ausgewaehlte Node-API.

## Vollstaendiger Wahlablauf

1. **Wahl erstellen**
   Im Dashboard Titel, Kandidaten, Zeitfenster, Member-Anzahl und Threshold
   setzen. `Wahl und Committee erzeugen` ausfuehren und jede Share-Datei
   speichern.

2. **Wahl-Block minen**
   Die `create_election`-Transaktion liegt zuerst im Mempool. Mit dem Node Key
   einen Block minen.

3. **Voter registrieren**
   Im separaten Voter Client die Wahl laden, ein Demo-Secret eingeben und
   registrieren. Nur dessen Hash-Commitment wird gesendet.

4. **Registrierung committen**
   Im Dashboard den Pending Block minen. Dieser separate Block ist fuer die
   Praesentation gut sichtbar, technisch aber nicht zwingend: Registrierung und
   Vote duerfen in dieser Reihenfolge auch im selben Mempool und Block liegen.

5. **Verschluesselt waehlen**
   Kandidaten auswaehlen und die Stimme absenden. Der Client zeigt die
   Transaktions-ID und ob sie noch im Mempool oder bereits committed ist.

6. **Vote-Block minen und synchronisieren**
   Auf Node 1 minen. Danach Node 2 und Node 3 mit ihrem Node Key synchronisieren.
   Alle Nodes sollten dieselbe Chain-Laenge und denselben letzten Blockhash
   anzeigen.

7. **Wahl finalisieren**
   Im Dashboard `Wahl beenden` mit dem Admin Key ausfuehren und die Transaktion
   minen. Alternativ wird ein Tally nach Ablauf des Endzeitpunkts erlaubt.

8. **Committee auszaehlen lassen**
   Im Committee Client mindestens so viele unterschiedliche Share-Dateien
   laden, wie der Threshold verlangt. Anschliessend den Tally publizieren.

9. **Tally committen und pruefen**
   Die `publish_tally_result`-Transaktion minen und im Dashboard `Verify`
   ausfuehren.

Erwartetes Endergebnis:

```text
result_status = verified
complete      = true
```

## Bedeutung der oeffentlichen Verifikation

`GET /api/v2/elections/{election_id}/verify` prueft:

- die komplette lokale Chain inklusive Hashverkettung und Signaturen
- Eindeutigkeit der committed Nullifier
- Importierbarkeit der verschluesselten Ballots
- Uebereinstimmung des publizierten encrypted Tallys mit allen Ballots
- ausreichende, unterschiedliche Partial Decryptions pro Kandidat
- Gueltigkeit der Chaum-Pedersen-Proofs
- Uebereinstimmung des Klarergebnisses mit der Threshold-Entschluesselung

`valid=true` bedeutet, dass im bisher vorhandenen Zustand kein gepruefter
Fehler erkannt wurde. Es bedeutet nicht automatisch, dass die Wahl beendet und
ausgezaehlt ist.

`complete=true` und `result_status=verified` bedeuten, dass die Wahl finalisiert,
das Ergebnis committed und vollstaendig gegen die committed Ballots und Proofs
geprueft wurde.

## API-Uebersicht

| Methode | Route | Zweck |
| --- | --- | --- |
| `GET` | `/api/v2/node/info` | Node, Validatoren, Peers und Chain-Status |
| `GET` | `/api/v2/chain` | vollstaendige lokale Chain |
| `GET` | `/api/v2/blocks/{index}` | einzelner Block |
| `GET` | `/api/v2/mempool` | lokale Pending-Transaktionen |
| `GET` | `/api/v2/transactions/{tx_id}` | Mempool-/Blockstatus einer Transaktion |
| `POST` | `/api/v2/peers` | Peer hinzufuegen, Node Key erforderlich |
| `POST` | `/api/v2/sync` | von Peers synchronisieren, Node Key erforderlich |
| `POST` | `/api/v2/transactions` | validierte Transaktion in den Mempool legen |
| `POST` | `/api/v2/blocks/mine` | Mempool signieren und committen, Node Key erforderlich |
| `POST` | `/api/v2/blocks` | von Peer erhaltenen Block pruefen und annehmen |
| `GET` | `/api/v2/elections` | alle Wahlen |
| `GET` | `/api/v2/elections/{id}` | oeffentlicher Wahlzustand |
| `GET` | `/api/v2/elections/{id}/encrypted-ballots` | committed Ciphertexts |
| `GET` | `/api/v2/elections/{id}/encrypted-tally` | lokal aggregierter Ciphertext |
| `GET` | `/api/v2/elections/{id}/published-result` | committed Committee-Ergebnis |
| `GET` | `/api/v2/elections/{id}/verify` | oeffentliche Gesamtpruefung |

`create_election` und `finalize_election` benoetigen beim Einreichen den
`X-Admin-Key`. `register_voter`, `cast_encrypted_vote` und ein kryptografisch
gueltiges `publish_tally_result` koennen ohne privilegierten API-Key eingereicht
werden.

Die interaktive OpenAPI-Ansicht ist unter `/docs` jeder laufenden Node verfuegbar.

## Konfiguration

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `NODE_ID` | `node-local` | eindeutige lokale Node-ID |
| `HOST` | `127.0.0.1` | Bind-Adresse der Node |
| `PORT` | `5001` | HTTPS-Port der Node |
| `DATA_DIR` | `.node-data/<NODE_ID>` | persistierter Node-Zustand |
| `VALIDATORS_JSON` | abhaengig von Key | Zuordnung Validator-ID zu Public Key |
| `NODE_PRIVATE_KEY` | leer | Ed25519-Key; nur Validator-Nodes |
| `PEERS` | leer | kommaseparierte HTTPS-Peer-URLs |
| `V2_ADMIN_KEY` | `dev_admin_key` | Admin-API-Key |
| `V2_NODE_KEY` | `dev_node_key` | Node-Operator-API-Key |
| `VOTER_CLIENT_HOST` | `127.0.0.1` | Bind-Adresse des Voter-Servers |
| `VOTER_CLIENT_PORT` | `7000` | HTTPS-Port des Voter-Servers |
| `TLS_CERT_FILE` | automatisch | eigenes Serverzertifikat |
| `TLS_KEY_FILE` | automatisch | eigener Server-Private-Key |
| `TLS_CA_CERT` | automatisch | CA fuer ausgehende Peer-Pruefung |
| `TLS_EXTRA_HOSTS` | leer | zusaetzliche SANs bei Ersterzeugung |

Ein `.env`-Loader wird nicht verwendet. Der Launcher setzt diese Werte fuer
seine Kindprozesse; beim manuellen Start werden sie als echte
Umgebungsvariablen gesetzt.

## Persistenz und Synchronisation

Jede Node speichert in ihrem `DATA_DIR` getrennte JSON-Dateien fuer Chain,
Mempool und Peers. Der fachliche Wahlzustand wird nicht als eigene Wahrheit
gespeichert, sondern deterministisch aus den committed Transaktionen
rekonstruiert.

Beim Sync fragt eine Node Chain und Mempool ihrer Peers ab. Eine laengere Chain
wird nur nach vollstaendiger lokaler Validierung uebernommen. Die aktuelle
Fork-Regel lautet lediglich `laengere gueltige Chain`; automatische
Blockverteilung und BFT-Finalitaet sind nicht implementiert.

## Tests

Alle Python-Tests:

```bash
.venv/bin/python -m unittest discover -s tests
```

Browser-Kryptografie:

```bash
npm run test:web-crypto
```

Die Testabdeckung umfasst:

- EC-ElGamal, zufaellige Ciphertexts und homomorphe Aggregation
- Shamir Threshold und verschiedene gueltige Share-Kombinationen
- Chaum-Pedersen-Proofs und manipulierte Ergebnisse
- Kompatibilitaet zwischen Noble-Browser-Payloads und Petlib
- kanonische Transaktions- und Blockhashes
- Ed25519-Signaturen und manipulierte Blocks
- Mempool, Nullifier-Bindung und Double-Voting-Ablehnung
- Admin- und Node-Rollenkeys
- HTML-Routen, CORS und Browser-Crypto-Bundle
- echte Drei-Node-Prozesse mit verifiziertem HTTPS-Sync

## Bewusste Grenzen

Fuer ein produktives Wahlsystem fehlen insbesondere:

- eine vertrauenswuerdige reale Identitaets- und Wahlberechtigungspruefung
- anonyme Credentials sowie ein echter ZK-Membership-/Nullifier-Proof
- ein ZK-Ballot-Proof fuer genau eine gueltige verschluesselte Auswahl
- Distributed Key Generation, sodass nie eine Stelle alle Shares erzeugt
- passwort-, Smartcard-, HSM- oder anderweitig geschuetzte private Shares
- sichere Ausgabe, Widerruf und Wiederherstellung von Schluesseln
- mehrere unabhaengige Validatoren mit BFT-Konsens und klarer Finalitaet
- automatische Peer-Erkennung, Gossip und robuste Fork-Behandlung
- transaktionale Datenbank, Nebenlaeufigkeitsschutz und Backups
- Rate Limits, gehaertete Autorisierung und sichere Geheimnisverwaltung
- Schutz gegen IP-, Timing-, Reihenfolge- und weitere Netzwerkmetadaten
- produktive PKI, Zertifikatsrotation und abgesicherter Client-Update-Pfad
- reproduzierbare Builds und Schutz vor manipuliertem Browser-Code
- Last-, Skalierungs-, Ausfall- und Recovery-Tests
- externe Kryptografie- und Code-Audits
- formale Sicherheitsanalyse, Datenschutzkonzept und rechtliche Zulassung

Insbesondere werden die privaten Committee-Shares aktuell gemeinsam im Browser
des Wahladministrators erzeugt. Ein Produktivsystem braeuchte ein DKG-Protokoll,
bei dem die Mitglieder den gemeinsamen Public Key verteilt erzeugen und keine
einzelne Stelle jemals den gesamten privaten Schluessel kennt.

## Fehlerbehebung

### Browser meldet, die Verbindung sei nicht privat

Das lokale CA-Zertifikat wurde noch nicht vertraut oder nach `--force` neu
erzeugt. `development-ca.pem` erneut in den System-Schluesselbund importieren,
auf `Immer vertrauen` setzen und den Browser neu starten.

### Dashboard von Node 2 oder Node 3 zeigt Node 1

Die URL muss den richtigen Port enthalten. Das Dashboard nutzt standardmaessig
`window.location.origin`; bei Node 2 ist das `https://127.0.0.1:5002`, bei Node
3 entsprechend Port `5003`. Gegebenenfalls die API-URL im Dashboard pruefen und
die Seite ohne alten Browser-Cache neu laden.

### Node startet mit `invalid validator signature` nicht

Das vorhandene `DATA_DIR` enthaelt Blocks, die mit einem anderen Validator-Key
signiert wurden. Entweder den urspruenglichen Key verwenden oder nur fuer eine
neue Demo den betroffenen State ueber den Launcher beziehungsweise `--reset`
zuruecksetzen.

### Stimme ist nur im Mempool

Eine angenommene Transaktion ist noch kein Chain-Eintrag. Erst ein Validator
nimmt sie mit `Mine` in einen signierten Block auf. Der Voter Client kann den
Status ueber die Transaktions-ID erneut laden.

## Weitere Dokumentation

- [Quick Start](docs/guides/QUICK_START.txt)
- [Technische Implementierungsreferenz](docs/guides/IMPLEMENTATION_SUMMARY.txt)
