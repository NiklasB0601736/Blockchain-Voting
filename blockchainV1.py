import datetime
import hashlib
import json
import os
import uuid
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
    from fastapi import Depends, FastAPI, Header, HTTPException, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field

    class CreateElectionRequest(BaseModel):
        title: str
        options: List[str]
        duration: int = Field(default=3600)

    class RegisterVoterRequest(BaseModel):
        election_id: str
        voter_commitment: str

    class VoteRequest(BaseModel):
        election_id: str
        vote_option: int
        voter_commitment: str
        proof: Optional[str] = None

    app = FastAPI(
        title="Blockchain Voting API",
        description="Lokale Demo-API fuer ein blockchain-basiertes Wahlsystem.",
        version="1.0.0",
    )
    admin_key = os.environ.get("ADMIN_KEY", DEFAULT_ADMIN_KEY)
    chain = blockchain_instance or Blockchain()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Admin-Key"],
    )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        detail = exc.detail if isinstance(exc.detail, str) else "Request fehlgeschlagen"
        return JSONResponse(status_code=exc.status_code, content={"error": detail})

    def api_error(message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        raise HTTPException(status_code=status_code, detail=message)

    def require_admin_key(x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
        if x_admin_key != admin_key:
            api_error("Unauthorized", status.HTTP_401_UNAUTHORIZED)

    @app.get("/api/elections")
    def list_elections():
        elections = chain.get_all_elections()
        return {"elections": elections, "total": len(elections)}

    @app.post("/api/elections", status_code=status.HTTP_201_CREATED)
    def create_election(data: CreateElectionRequest, _admin=Depends(require_admin_key)):
        try:
            election_id = chain.create_election(
                data.title,
                data.options,
                data.duration,
            )
            return {"message": "Wahl erfolgreich erstellt", "election_id": election_id}
        except ValueError as e:
            api_error(str(e))

    @app.get("/api/elections/{election_id}")
    def get_election(election_id):
        try:
            election = chain._get_election(election_id)
            return election.to_dict()
        except ValueError as e:
            api_error(str(e), status.HTTP_404_NOT_FOUND)

    @app.post("/api/voters/register", status_code=status.HTTP_201_CREATED)
    def register_voter(data: RegisterVoterRequest):
        try:
            success = chain.register_voter(data.election_id, data.voter_commitment)
            if not success:
                api_error("Waehler bereits registriert")
            return {"message": "Waehler erfolgreich registriert"}
        except ValueError as e:
            api_error(str(e))

    @app.post("/api/vote")
    def cast_vote(data: VoteRequest):
        try:
            chain.cast_anonymous_vote(
                data.election_id,
                data.vote_option,
                data.voter_commitment,
                data.proof,
            )
            return {"message": "Vote erfolgreich abgegeben (anonym)"}
        except ValueError as e:
            api_error(str(e))

    @app.get("/api/results/{election_id}")
    def get_results(election_id):
        try:
            return chain.get_election_results(election_id)
        except ValueError as e:
            api_error(str(e))

    @app.get("/api/verify/{election_id}")
    def verify_election(election_id):
        try:
            return chain.verify_election_integrity(election_id)
        except ValueError as e:
            api_error(str(e))

    @app.get("/api/blockchain/chain")
    def get_chain():
        return {"length": len(chain.chain), "chain": chain.chain}

    @app.get("/api/blockchain/valid")
    def blockchain_valid():
        valid = chain.chain_valid(chain.chain)
        message = "Die Blockchain ist valide." if valid else "Die Blockchain ist ungueltig!"
        return {"message": message, "valid": valid}

    @app.post("/api/elections/{election_id}/finalize")
    def finalize_election_endpoint(election_id, _admin=Depends(require_admin_key)):
        try:
            chain.finalize_election(election_id)
            return {"message": "Wahl erfolgreich beendet", "election_id": election_id}
        except ValueError as e:
            api_error(str(e))

    @app.get("/api/health")
    def health_check():
        return {
            "status": "online",
            "blockchain_valid": chain.chain_valid(chain.chain),
            "elections_count": len(chain.elections),
            "chain_length": len(chain.chain),
        }

    app.state.blockchain = chain
    return app


try:
    app = create_app()
except ModuleNotFoundError as exc:
    if exc.name not in {"fastapi", "pydantic"}:
        raise
    app = None


if __name__ == "__main__":
    if app is None:
        raise SystemExit("FastAPI fehlt. Installiere die Abhaengigkeiten mit: pip install -r requirements.txt")

    print("\n" + "=" * 70)
    print("BLOCKCHAIN-BASIERTES ANONYMES WAHLSYSTEM".center(70))
    print("=" * 70)
    port = int(os.environ.get("PORT", "5000"))
    print(f"\nAPI: http://127.0.0.1:{port}")
    print("Admin-Key: ueber ADMIN_KEY setzen (Default nur fuer lokale Demo)")
    print("=" * 70 + "\n")
    import uvicorn

    reload = os.environ.get("API_RELOAD", "0") == "1"
    uvicorn.run("blockchainV1:app", host="127.0.0.1", port=port, reload=reload)
