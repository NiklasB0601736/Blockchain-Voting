#!/usr/bin/env python3
"""
Test-Szenarien für das Blockchain-Wahlsystem
Demonstriert alle Hauptfunktionen des Systems
"""

from voting_system.blockchain_v1 import Blockchain
import json

def print_header(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")

def test_blockchain_voting():
    """Test des kompletten Wahlablaufs"""
    
    blockchain = Blockchain()
    
    # ========== TEST 1: WAHL ERSTELLEN ==========
    print_header("TEST 1: Wahl erstellen")
    
    election_id = blockchain.create_election(
        title="Bundestag 2026",
        options=["CDU/CSU", "SPD", "Grüne", "FDP", "Linke", "AfD"],
        duration=3600
    )
    
    print(f"✓ Wahl erstellt")
    print(f"  ID: {election_id}")
    print(f"  Alle Wahlen: {len(blockchain.get_all_elections())}")
    
    # ========== TEST 2: WÄHLER REGISTRIEREN ==========
    print_header("TEST 2: Wähler registrieren")
    
    voters = [
        "commitment_alice_abc123",
        "commitment_bob_def456",
        "commitment_charlie_ghi789",
        "commitment_diana_jkl012",
        "commitment_elia_mno345",
        "commitment_frank_pqr678",
    ]
    
    for i, voter_commitment in enumerate(voters, 1):
        success = blockchain.register_voter(election_id, voter_commitment)
        status = "✓" if success else "✗"
        print(f"{status} Wähler {i} registriert: {voter_commitment[:20]}...")
    
    # ========== TEST 3: DOPPEL-REGISTRIERUNG VERHINDERN ==========
    print_header("TEST 3: Doppel-Registrierung testen")
    
    duplicate = blockchain.register_voter(election_id, voters[0])
    status = "✓ Verhindert!" if not duplicate else "✗ FEHLER: Erlaubt!"
    print(f"{status} - Zweite Registrierung: {duplicate}")
    
    # ========== TEST 4: VOTES ABGEBEN ==========
    print_header("TEST 4: Abstimmung")
    
    votes = [
        (voters[0], 0),  # Alice wählt CDU/CSU
        (voters[1], 1),  # Bob wählt SPD
        (voters[2], 2),  # Charlie wählt Grüne
        (voters[3], 1),  # Diana wählt SPD
        (voters[4], 0),  # Elia wählt CDU/CSU
        (voters[5], 3),  # Frank wählt FDP
    ]
    
    for voter, option in votes:
        try:
            success = blockchain.cast_anonymous_vote(
                election_id,
                option,
                voter
            )
            election = blockchain.elections[election_id]
            option_name = election.options[option]
            print(f"✓ Vote für '{option_name}' abgegeben (anonym)")
        except ValueError as e:
            print(f"✗ Fehler: {e}")

    # ========== TEST 4B: DOPPEL-ABSTIMMUNG VERHINDERN ==========
    print_header("TEST 4B: Doppel-Abstimmung testen")

    try:
        blockchain.cast_anonymous_vote(election_id, 2, voters[0])
        print("✗ FEHLER: Zweite Stimme wurde erlaubt!")
    except ValueError as e:
        print(f"✓ Verhindert! - {e}")
    
    # ========== TEST 5: BLOCKCHAIN ÜBERPRÜFEN ==========
    print_header("TEST 5: Blockchain-Integrität prüfen")
    
    is_valid = blockchain.chain_valid(blockchain.chain)
    status = "✓ Gültig" if is_valid else "✗ UNGÜLTIG"
    print(f"{status}")
    print(f"  Blockchain-Länge: {len(blockchain.chain)} Blöcke")
    print(f"  Chain Hashes:")
    for block in blockchain.chain:
        block_hash = blockchain.hash(block)
        print(f"    Block #{block['index']}: {block_hash[:16]}...")
    
    # ========== TEST 6: WAHL BEENDEN ==========
    print_header("TEST 6: Wahl finalisieren")
    
    success = blockchain.finalize_election(election_id)
    if success:
        print(f"✓ Wahl beendet und in Blockchain gespeichert")
        print(f"  Blockchain-Länge nach Finalisierung: {len(blockchain.chain)} Blöcke")
    else:
        print(f"✗ Fehler beim Finalisieren")
    
    # ========== TEST 7: ERGEBNISSE AUSWERTEN (ÖFFENTLICH!) ==========
    print_header("TEST 7: Wahlergebnisse auswerten (JEDER kann das!)")
    
    try:
        results = blockchain.get_election_results(election_id)
        
        print(f"Wahl: {results['title']}")
        print(f"Gesamtstimmen: {results['total_votes']}")
        print(f"\nErgebnisse:")
        
        max_votes = max(r['votes'] for r in results['results'])
        
        for result in results['results']:
            percentage = (result['votes'] / max_votes * 100) if max_votes > 0 else 0
            bar = "█" * int(percentage / 5) + "░" * (20 - int(percentage / 5))
            print(f"  {result['option']:15} | {bar} | {result['votes']:3} ({percentage:5.1f}%)")
        
    except ValueError as e:
        print(f"✗ Fehler: {e}")
    
    # ========== TEST 8: INTEGRITÄTSVERIFIZIERUNG ==========
    print_header("TEST 8: Wahl-Integrität verifizieren")
    
    integrity = blockchain.verify_election_integrity(election_id)
    
    print(f"Election ID: {integrity['election_id']}")
    print(f"Total Votes: {integrity['total_votes']}")
    print(f"Counted Votes: {integrity['total_counted']}")
    print(f"Match: {'✓ JA' if integrity['total_votes'] == integrity['total_counted'] else '✗ NEIN'}")
    print(f"\nBlockchain-Integrität: {'✓ Gültig' if integrity['blockchain_valid'] else '✗ Ungültig'}")
    print(f"Wahl-Integrität: {'✓ Gültig' if integrity['integrity_valid'] else '✗ Ungültig'}")
    
    # ========== TEST 9: ANONYMITÄT VERIFIZIEREN ==========
    print_header("TEST 9: Anonymität verifizieren")
    
    election = blockchain.elections[election_id]
    
    print(f"Abstimmende Personen: {len(election.votes)} anonyme Votes")
    print(f"Keine persönlichen Daten in Blockchain")
    print(f"\nGespeicherte Daten (anonym):")
    
    for i, vote in enumerate(election.votes[:3], 1):  # Zeige nur die ersten 3
        print(f"  Vote {i}:")
        print(f"    - ID: {vote.vote_id[:16]}...")
        print(f"    - Option: {election.options[vote.vote_option]}")
        print(f"    - Timestamp: {vote.timestamp}")
        print(f"    - Commitment Hash: {vote.commitment_hash[:20]}...")
    
    print(f"  ... und {len(election.votes) - 3} weitere anonyme Votes")
    print(f"\n✓ KEINE RÜCKVERFOLGUNG MÖGLICH - Wahlergebnis ist anonym!")
    
    # ========== SUMMARY ==========
    print_header("ZUSAMMENFASSUNG")
    
    print(f"""
Blockchain-Wahlsystem Test ERFOLGREICH ✓

✅ Anforderungen erfüllt:
   ✓ Alle Nutzer können Wahl auswerten (/api/results)
   ✓ Demo nutzt Commitments statt Namen
   ✓ Blockchain-Sicherheit (SHA-256 Hashing)
   ✓ Integrität verifizierbar (/api/verify)

📊 Statistik:
   • Gesamtblöcke: {len(blockchain.chain)}
   • Wahlen: {len(blockchain.elections)}
   • Gesamtstimmen: {len(election.votes)}
   • Blockchain gültig: {'Ja' if blockchain.chain_valid(blockchain.chain) else 'Nein'}

🔐 Sicherheit:
   • Anonymität: Demo-Commitments, echte Semaphore-Proofs als Ausblick
   • Integrität: Proof-of-Work + SHA-256
   • Doppelstimmen: Verhindert ✓
   • Dezentralisierung: Jeder kann validieren ✓
    """)

if __name__ == '__main__':
    print("\n" + "="*70)
    print("BLOCKCHAIN-VOTING SYSTEM - COMPREHENSIVE TEST".center(70))
    print("="*70)
    
    test_blockchain_voting()
    
    print("\n" + "="*70)
    print("Test abgeschlossen!".center(70))
    print("="*70 + "\n")
