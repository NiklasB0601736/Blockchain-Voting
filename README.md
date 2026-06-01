Blockchain-basiertes Anonymes Wahlsystem

Ein dezentralisiertes, sicheres Wahlsystem mit vollständiger Anonymität und öffentlicher Auswertbarkeit.

## 🎯 Anforderungen

✅ **Alle Nutzer können die Wahl auswerten** - Öffentliche API ohne Authentifizierung
✅ **Alle Nutzer sind anonym** - Semaphore Zero-Knowledge Proofs
✅ **Blockchain-Sicherheit** - Ethereum-basierte Integrität
✅ **Skalierbarkeit** - zkSync L2 für schnelle Transaktionen

---

## 🏗️ Architektur

| Komponente | Rolle |
|-----------|-------|
| **Ethereum** | Sicherheit & Wahrheit |
| **zkSync** | Skalierung |
| **Solidity** | Smart Contract Regeln |
| **Semaphore** | Anonymität der Wähler |
| **MetaMask** | Wallet-Integration |
| **Hardhat** | Test-Umgebung |
| **Frontend** | Benutzerinterface |

---

## 📁 Dateien

- lockchainV1.py - Python Blockchain-Core mit Flask API
- contracts/VotingContract.sol - Solidity Smart Contract
- rontend.html - Web-Interface mit MetaMask
- hardhat.config.js - Hardhat-Konfiguration

---

## 🚀 Verwendung

\\\ash
# Server starten
python blockchainV1.py

# Frontend öffnen
open frontend.html
\\\

**API läuft auf:** http://127.0.0.1:5000

---

## 💻 API-Endpunkte

### Öffentlich (keine Authentifizierung erforderlich!)

\\\ash
# Wahlergebnisse auswerten - JEDER kann aufrufen!
GET /api/results/{election_id}

# Integrität verifizieren
GET /api/verify/{election_id}

# Blockchain auslesen
GET /api/blockchain/chain

# Blockchain validieren
GET /api/blockchain/valid
\\\

### Admin (benötigt X-Admin-Key Header)

\\\ash
# Neue Wahl erstellen
POST /api/elections
X-Admin-Key: your_secret_admin_key_here

# Wahl beenden
POST /api/elections/{election_id}/finalize
\\\

### Benutzer

\\\ash
# Wähler registrieren
POST /api/voters/register

# Vote abgeben (anonym)
POST /api/vote
\\\

---

## 🔐 Sicherheit

- ✓ Semaphore für Anonymous Zero-Knowledge Proofs
- ✓ SHA-256 Blockchain Hashing
- ✓ Proof-of-Work Konsens
- ✓ Doppelabstimmung verhindert
- ✓ Dezentralisierte Verifizierung

---

**Dezentralisierte Wahlen für die Zukunft! 🚀**
=======
# Blockchain-Voting
Voting System based on blockchain to secure anonymity and security

https://www.geeksforgeeks.org/software-engineering/blockchain/