import datetime
import hashlib
import json
import os
import uuid
from functools import wraps
from typing import Dict, List, Optional


DEFAULT_ADMIN_KEY = "your_secret_admin_key_here"
POW_DIFFICULTY = 4


class Vote:
    def __init__(self, vote_id: str, vote_option: int, timestamp: str, commitment_hash: str):
        self.vote_id = vote_id
        self.vote_option = vote_option
        self.timestamp = timestamp
        self.commitment_hash = commitment_hash

    def to_dict(self):
        return {
            "vote_id": self.vote_id,
            "vote_option": self.vote_option,
            "timestamp": self.timestamp,
            "commitment_hash": self.commitment_hash,
        }


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
        self.voted_commitments = set()

    def is_active(self) -> bool:
        return self.active and datetime.datetime.now() <= self.end_time

    def to_dict(self):
        return {
            "election_id": self.election_id,
            "title": self.title,
            "options": self.options,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "active": self.is_active(),
            "total_votes": len(self.votes),
            "registered_voters": len(self.registered_voters),
        }


class Blockchain:
    def __init__(self):
        self.chain = []
        self.elections: Dict[str, Election] = {}
        self.create_block(proof=1, previous_hash="0")

    def create_block(self, proof, previous_hash):
        block = {
            "index": len(self.chain) + 1,
            "timestamp": datetime.datetime.now().isoformat(),
            "proof": proof,
            "previous_hash": previous_hash,
            "elections": {},
        }
        self.chain.append(block)
        return block

    def print_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        target = "0" * POW_DIFFICULTY
        while True:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation.startswith(target):
                return new_proof
            new_proof += 1

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        if not chain:
            return False

        previous_block = chain[0]
        block_index = 1
        target = "0" * POW_DIFFICULTY
        while block_index < len(chain):
            block = chain[block_index]
            if block["previous_hash"] != self.hash(previous_block):
                return False

            previous_proof = previous_block["proof"]
            proof = block["proof"]
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if not hash_operation.startswith(target):
                return False

            previous_block = block
            block_index += 1

        return True

    def create_election(self, title: str, options: List[str], duration: int = 3600) -> str:
        clean_title = self._validate_title(title)
        clean_options = self._validate_options(options)
        clean_duration = self._validate_duration(duration)

        election_id = str(uuid.uuid4())
        election = Election(election_id, clean_title, clean_options, clean_duration)
        self.elections[election_id] = election
        self.chain[-1]["elections"][election_id] = election.to_dict()
        return election_id

    def register_voter(self, election_id: str, voter_commitment: str) -> bool:
        election = self._get_election(election_id)
        clean_commitment = self._validate_commitment(voter_commitment)

        if not election.is_active():
            raise ValueError("Wahl ist nicht aktiv")
        if clean_commitment in election.registered_voters:
            return False

        election.registered_voters.add(clean_commitment)
        return True

    def cast_anonymous_vote(
        self,
        election_id: str,
        vote_option: int,
        voter_commitment: str,
        proof: Optional[str] = None,
    ) -> bool:
        election = self._get_election(election_id)
        clean_commitment = self._validate_commitment(voter_commitment)
        clean_vote_option = self._validate_vote_option(vote_option, election)

        if not election.is_active():
            raise ValueError("Wahl ist nicht mehr aktiv")
        if clean_commitment not in election.registered_voters:
            raise ValueError("Waehler nicht registriert")
        if clean_commitment in election.voted_commitments:
            raise ValueError("Waehler hat bereits abgestimmt")

        now = datetime.datetime.now().isoformat()
        vote_id = hashlib.sha256(f"{election_id}{clean_commitment}{now}".encode()).hexdigest()
        vote = Vote(
            vote_id=vote_id,
            vote_option=clean_vote_option,
            timestamp=now,
            commitment_hash=self._commitment_hash(clean_commitment),
        )
        election.votes.append(vote)
        election.vote_count[clean_vote_option] += 1
        election.voted_commitments.add(clean_commitment)
        return True

    def get_election_results(self, election_id: str) -> Dict:
        election = self._get_election(election_id)
        if election.is_active():
            raise ValueError("Wahl ist noch aktiv")

        return {
            "election_id": election_id,
            "title": election.title,
            "options": election.options,
            "results": [
                {"option_index": i, "option": option, "votes": election.vote_count[i]}
                for i, option in enumerate(election.options)
            ],
            "total_votes": len(election.votes),
            "start_time": election.start_time.isoformat(),
            "end_time": election.end_time.isoformat(),
        }

    def finalize_election(self, election_id: str) -> bool:
        election = self._get_election(election_id)
        if not election.active:
            raise ValueError("Wahl wurde bereits beendet")

        election.active = False
        previous_block = self.chain[-1]
        new_proof = self.proof_of_work(previous_block["proof"])
        previous_hash = self.hash(previous_block)
        new_block = self.create_block(new_proof, previous_hash)
        new_block["elections"][election_id] = {
            **election.to_dict(),
            "results": election.vote_count,
            "votes": [vote.to_dict() for vote in election.votes],
            "finalized": True,
        }
        return True

    def verify_election_integrity(self, election_id: str) -> Dict:
        election = self._get_election(election_id)
        total_counted = sum(election.vote_count.values())
        total_votes = len(election.votes)
        unique_voters = len(election.voted_commitments)

        return {
            "election_id": election_id,
            "total_votes": total_votes,
            "total_counted": total_counted,
            "unique_voters": unique_voters,
            "integrity_valid": total_counted == total_votes == unique_voters,
            "blockchain_valid": self.chain_valid(self.chain),
        }

    def get_all_elections(self) -> List[Dict]:
        return [election.to_dict() for election in self.elections.values()]

    def _get_election(self, election_id: str) -> Election:
        if election_id not in self.elections:
            raise ValueError(f"Wahl {election_id} nicht gefunden")
        return self.elections[election_id]

    def _validate_title(self, title: str) -> str:
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Titel erforderlich")
        return title.strip()

    def _validate_options(self, options: List[str]) -> List[str]:
        if not isinstance(options, list):
            raise ValueError("Options muss eine Liste sein")

        clean_options = [option.strip() for option in options if isinstance(option, str) and option.strip()]
        if len(clean_options) < 2:
            raise ValueError("Mindestens 2 Wahlmoeglichkeiten erforderlich")
        if len(set(clean_options)) != len(clean_options):
            raise ValueError("Wahlmoeglichkeiten muessen eindeutig sein")
        return clean_options

    def _validate_duration(self, duration: int) -> int:
        try:
            clean_duration = int(duration)
        except (TypeError, ValueError):
            raise ValueError("Dauer muss eine Zahl in Sekunden sein")

        if clean_duration <= 0:
            raise ValueError("Dauer muss groesser als 0 sein")
        return clean_duration

    def _validate_vote_option(self, vote_option: int, election: Election) -> int:
        try:
            clean_vote_option = int(vote_option)
        except (TypeError, ValueError):
            raise ValueError("Ungueltige Wahlmoeglichkeit")

        if clean_vote_option < 0 or clean_vote_option >= len(election.options):
            raise ValueError(f"Ungueltige Wahlmoeglichkeit: {vote_option}")
        return clean_vote_option

    def _validate_commitment(self, voter_commitment: str) -> str:
        if not isinstance(voter_commitment, str) or not voter_commitment.strip():
            raise ValueError("Voter Commitment erforderlich")
        return voter_commitment.strip()

    def _commitment_hash(self, voter_commitment: str) -> str:
        return hashlib.sha256(voter_commitment.encode()).hexdigest()


def create_app(blockchain_instance: Optional[Blockchain] = None):
    from flask import Flask, jsonify, request

    app = Flask(__name__)
    app.config["ADMIN_KEY"] = os.environ.get("ADMIN_KEY", DEFAULT_ADMIN_KEY)
    chain = blockchain_instance or Blockchain()

    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    def require_admin_key(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            admin_key = request.headers.get("X-Admin-Key")
            if admin_key != app.config["ADMIN_KEY"]:
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, **kwargs)

        return decorated

    def get_json_body():
        data = request.get_json(silent=True)
        if data is None:
            raise ValueError("Ungueltiger oder fehlender JSON-Body")
        return data

    @app.route("/api/elections", methods=["GET"])
    def list_elections():
        elections = chain.get_all_elections()
        return jsonify({"elections": elections, "total": len(elections)}), 200

    @app.route("/api/elections", methods=["POST"])
    @require_admin_key
    def create_election():
        try:
            data = get_json_body()
            election_id = chain.create_election(
                data.get("title"),
                data.get("options", []),
                data.get("duration", 3600),
            )
            return jsonify({"message": "Wahl erfolgreich erstellt", "election_id": election_id}), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/elections/<election_id>", methods=["GET"])
    def get_election(election_id):
        try:
            election = chain._get_election(election_id)
            return jsonify(election.to_dict()), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    @app.route("/api/voters/register", methods=["POST"])
    def register_voter():
        try:
            data = get_json_body()
            success = chain.register_voter(data.get("election_id"), data.get("voter_commitment"))
            if not success:
                return jsonify({"error": "Waehler bereits registriert"}), 400
            return jsonify({"message": "Waehler erfolgreich registriert"}), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/vote", methods=["POST"])
    def cast_vote():
        try:
            data = get_json_body()
            chain.cast_anonymous_vote(
                data.get("election_id"),
                data.get("vote_option"),
                data.get("voter_commitment"),
                data.get("proof"),
            )
            return jsonify({"message": "Vote erfolgreich abgegeben (anonym)"}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/results/<election_id>", methods=["GET"])
    def get_results(election_id):
        try:
            return jsonify(chain.get_election_results(election_id)), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/verify/<election_id>", methods=["GET"])
    def verify_election(election_id):
        try:
            return jsonify(chain.verify_election_integrity(election_id)), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/blockchain/chain", methods=["GET"])
    def get_chain():
        return jsonify({"length": len(chain.chain), "chain": chain.chain}), 200

    @app.route("/api/blockchain/valid", methods=["GET"])
    def blockchain_valid():
        valid = chain.chain_valid(chain.chain)
        message = "Die Blockchain ist valide." if valid else "Die Blockchain ist ungueltig!"
        return jsonify({"message": message, "valid": valid}), 200

    @app.route("/api/elections/<election_id>/finalize", methods=["POST"])
    @require_admin_key
    def finalize_election_endpoint(election_id):
        try:
            chain.finalize_election(election_id)
            return jsonify({"message": "Wahl erfolgreich beendet", "election_id": election_id}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify(
            {
                "status": "online",
                "blockchain_valid": chain.chain_valid(chain.chain),
                "elections_count": len(chain.elections),
                "chain_length": len(chain.chain),
            }
        ), 200

    app.blockchain = chain
    return app


try:
    app = create_app()
except ModuleNotFoundError as exc:
    if exc.name != "flask":
        raise
    app = None


if __name__ == "__main__":
    if app is None:
        raise SystemExit("Flask fehlt. Installiere die Abhaengigkeiten mit: pip install -r requirements.txt")

    print("\n" + "=" * 70)
    print("BLOCKCHAIN-BASIERTES ANONYMES WAHLSYSTEM".center(70))
    print("=" * 70)
    port = int(os.environ.get("PORT", "5000"))
    print(f"\nAPI: http://127.0.0.1:{port}")
    print("Admin-Key: ueber ADMIN_KEY setzen (Default nur fuer lokale Demo)")
    print("=" * 70 + "\n")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
