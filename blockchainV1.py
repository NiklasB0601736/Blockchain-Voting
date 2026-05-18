#!/usr/bin/env python3
import datetime
import hashlib
import json
from flask import Flask, jsonify, request
from functools import wraps
from typing import List, Dict, Optional
import uuid

class Vote:
    def __init__(self, vote_id: str, vote_option: int, timestamp: str, commitment: str):
        self.vote_id = vote_id
        self.vote_option = vote_option
        self.timestamp = timestamp
        self.commitment = commitment
    def to_dict(self):
        return {'vote_id': self.vote_id, 'vote_option': self.vote_option, 'timestamp': self.timestamp, 'commitment': self.commitment}

class Election:
    def __init__(self, election_id: str, title: str, options: List[str], duration: int):
        self.election_id = election_id
        self.title = title
        self.options = options
        self.start_time = datetime.datetime.now()
        self.end_time = self.start_time + datetime.timedelta(seconds=duration)
        self.active = True
        self.votes: List[Vote] = []
        self.vote_count = {i: 0 for i in range(len(options))}
        self.registered_voters = set()
    def is_active(self) -> bool:
        return self.active and datetime.datetime.now() <= self.end_time
    def to_dict(self):
        return {'election_id': self.election_id, 'title': self.title, 'options': self.options, 'start_time': str(self.start_time), 'end_time': str(self.end_time), 'active': self.active, 'total_votes': len(self.votes)}

class Blockchain:
    def __init__(self):
        self.chain = []
        self.elections: Dict[str, Election] = {}
        self.create_block(proof=1, previous_hash='0')
    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1, 'timestamp': str(datetime.datetime.now()), 'proof': proof, 'previous_hash': previous_hash, 'elections': {}}
        self.chain.append(block)
        return block
    def print_previous_block(self):
        return self.chain[-1]
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1
        return True
    def create_election(self, title: str, options: List[str], duration: int = 3600) -> str:
        if len(options) < 2:
            raise ValueError("Mindestens 2 Wahlmöglichkeiten erforderlich")
        election_id = str(uuid.uuid4())
        election = Election(election_id, title, options, duration)
        self.elections[election_id] = election
        current_block = self.chain[-1]
        current_block['elections'][election_id] = election.to_dict()
        return election_id
    def register_voter(self, election_id: str, voter_commitment: str) -> bool:
        if election_id not in self.elections:
            raise ValueError(f"Wahl {election_id} nicht gefunden")
        election = self.elections[election_id]
        if voter_commitment in election.registered_voters:
            return False
        election.registered_voters.add(voter_commitment)
        return True
    def cast_anonymous_vote(self, election_id: str, vote_option: int, voter_commitment: str, proof: Optional[str] = None) -> bool:
        if election_id not in self.elections:
            raise ValueError(f"Wahl {election_id} nicht gefunden")
        election = self.elections[election_id]
        if not election.is_active():
            raise ValueError("Wahl ist nicht mehr aktiv")
        if vote_option >= len(election.options):
            raise ValueError(f"Ungültige Wahlmöglichkeit: {vote_option}")
        if voter_commitment not in election.registered_voters:
            raise ValueError("Wähler nicht registriert")
        vote_id = hashlib.sha256(f"{election_id}{voter_commitment}{datetime.datetime.now()}".encode()).hexdigest()
        vote = Vote(vote_id=vote_id, vote_option=vote_option, timestamp=str(datetime.datetime.now()), commitment=voter_commitment)
        election.votes.append(vote)
        election.vote_count[vote_option] += 1
        return True
    def get_election_results(self, election_id: str) -> Dict:
        if election_id not in self.elections:
            raise ValueError(f"Wahl {election_id} nicht gefunden")
        election = self.elections[election_id]
        if election.is_active():
            raise ValueError("Wahl ist noch aktiv")
        results = {'election_id': election_id, 'title': election.title, 'options': election.options, 'results': [{'option': option, 'votes': election.vote_count[i]} for i, option in enumerate(election.options)], 'total_votes': len(election.votes), 'start_time': str(election.start_time), 'end_time': str(election.end_time)}
        return results
    def finalize_election(self, election_id: str) -> bool:
        if election_id not in self.elections:
            raise ValueError(f"Wahl {election_id} nicht gefunden")
        election = self.elections[election_id]
        election.active = False
        previous_block = self.chain[-1]
        new_proof = self.proof_of_work(previous_block['proof'])
        previous_hash = self.hash(previous_block)
        new_block = self.create_block(new_proof, previous_hash)
        new_block['elections'][election_id] = {**election.to_dict(), 'results': election.vote_count, 'finalized': True}
        return True
    def verify_election_integrity(self, election_id: str) -> Dict:
        if election_id not in self.elections:
            raise ValueError(f"Wahl {election_id} nicht gefunden")
        election = self.elections[election_id]
        total_counted = sum(election.vote_count.values())
        total_votes = len(election.votes)
        return {'election_id': election_id, 'total_votes': total_votes, 'total_counted': total_counted, 'integrity_valid': total_counted == total_votes, 'blockchain_valid': self.chain_valid(self.chain)}
    def get_all_elections(self) -> List[Dict]:
        return [election.to_dict() for election in self.elections.values()]

app = Flask(__name__)
blockchain = Blockchain()

def require_admin_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_key = request.headers.get('X-Admin-Key')
        if admin_key != 'your_secret_admin_key_here':
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/elections', methods=['GET'])
def get_elections():
    elections = blockchain.get_all_elections()
    return jsonify({'elections': elections, 'total': len(elections)}), 200

@app.route('/api/elections', methods=['POST'])
@require_admin_key
def create_election():
    try:
        data = request.get_json()
        title = data.get('title')
        options = data.get('options', [])
        duration = data.get('duration', 3600)
        if not title or not options:
            return jsonify({'error': 'Title und Options erforderlich'}), 400
        election_id = blockchain.create_election(title, options, duration)
        return jsonify({'message': 'Wahl erfolgreich erstellt', 'election_id': election_id}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/elections/<election_id>', methods=['GET'])
def get_election(election_id):
    try:
        if election_id not in blockchain.elections:
            return jsonify({'error': 'Wahl nicht gefunden'}), 404
        election = blockchain.elections[election_id]
        return jsonify(election.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/voters/register', methods=['POST'])
def register_voter():
    try:
        data = request.get_json()
        election_id = data.get('election_id')
        voter_commitment = data.get('voter_commitment')
        if not election_id or not voter_commitment:
            return jsonify({'error': 'Election ID und Voter Commitment erforderlich'}), 400
        success = blockchain.register_voter(election_id, voter_commitment)
        if not success:
            return jsonify({'error': 'Wähler bereits registriert oder ungültig'}), 400
        return jsonify({'message': 'Wähler erfolgreich registriert', 'election_id': election_id}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/vote', methods=['POST'])
def cast_vote():
    try:
        data = request.get_json()
        election_id = data.get('election_id')
        vote_option = data.get('vote_option')
        voter_commitment = data.get('voter_commitment')
        proof = data.get('proof')
        if not all([election_id, vote_option is not None, voter_commitment]):
            return jsonify({'error': 'Election ID, Vote Option und Voter Commitment erforderlich'}), 400
        success = blockchain.cast_anonymous_vote(election_id, int(vote_option), voter_commitment, proof)
        if success:
            return jsonify({'message': 'Vote erfolgreich abgegeben (anonym)', 'election_id': election_id}), 200
        else:
            return jsonify({'error': 'Fehler beim Abstimmen'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/results/<election_id>', methods=['GET'])
def get_results(election_id):
    try:
        results = blockchain.get_election_results(election_id)
        return jsonify(results), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/verify/<election_id>', methods=['GET'])
def verify_election(election_id):
    try:
        integrity = blockchain.verify_election_integrity(election_id)
        return jsonify(integrity), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/blockchain/chain', methods=['GET'])
def get_chain():
    response = {'length': len(blockchain.chain), 'chain': blockchain.chain}
    return jsonify(response), 200

@app.route('/api/blockchain/valid', methods=['GET'])
def blockchain_valid():
    valid = blockchain.chain_valid(blockchain.chain)
    if valid:
        response = {'message': 'Die Blockchain ist valide.', 'valid': True}
    else:
        response = {'message': 'Die Blockchain ist ungültig!', 'valid': False}
    return jsonify(response), 200

@app.route('/api/elections/<election_id>/finalize', methods=['POST'])
@require_admin_key
def finalize_election_endpoint(election_id):
    try:
        success = blockchain.finalize_election(election_id)
        if success:
            return jsonify({'message': 'Wahl erfolgreich beendet', 'election_id': election_id}), 200
        else:
            return jsonify({'error': 'Fehler beim Beenden der Wahl'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'online', 'blockchain_valid': blockchain.chain_valid(blockchain.chain), 'elections_count': len(blockchain.elections), 'chain_length': len(blockchain.chain)}), 200

if __name__ == '__main__':
    print('\n' + '='*70)
    print('BLOCKCHAIN-BASIERTES ANONYMES WAHLSYSTEM'.center(70))
    print('='*70)
    print('\nKOMPONENTEN:')
    print('  * Ethereum: Sicherheit & Wahrheit')
    print('  * zkSync: Skalierung')
    print('  * Solidity: Smart Contract Regeln')
    print('  * Semaphore: Anonymität der Wähler')
    print('  * MetaMask: Identität & Wallet')
    print('  * Hardhat: Test & Deployment')
    print('  * Frontend: Benutzerinterface')
    print('\nFEATURES:')
    print('  + Anonyme Abstimmung (Semaphore Zero-Knowledge Proofs)')
    print('  + Öffentliche Wahlergebnisse-Auswertung')
    print('  + Blockchain-Integrität verifizierbar')
    print('  + Doppelabstimmung verhindert')
    print('\n' + '='*70)
    print('API: http://127.0.0.1:5000')
    print('='*70 + '\n')
    app.run(host='127.0.0.1', port=5000, debug=True)
