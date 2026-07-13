"""
Distributed Python blockchain prototype for encrypted voting.

This module is the v2 chain core. It intentionally lives next to the existing
`blockchainV1.py` demo instead of replacing it. The old file is still useful as
the small local learning version; this module models the pieces that make the
project feel like a real distributed ledger:

- transactions are the source of truth,
- blocks are signed by Proof-of-Authority validators,
- each node can persist its own chain and mempool as JSON,
- encrypted Petlib ballots are stored instead of plaintext votes,
- tally publication is publicly verifiable from chain data.

Security boundary for the prototype:
PoA validators decide which valid transactions enter blocks and in which order.
They do not get to make invalid votes valid, because every node replays the
chain and checks transaction rules, nullifiers, encrypted ballot shape, block
hashes, validator signatures, and published tally proofs.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from petlib.bn import Bn

from voting_system.crypto_petlib_elgamal_tally import (
    EncryptedBallot,
    EncryptedTally,
    PetlibPublicKey,
    ThresholdPublishedTallyResult,
    aggregate_encrypted_ballots,
    combine_partial_decryption_factors,
    public_shares_from_payload,
    remove_decryption_factor,
    verify_partial_decryption_proof,
    verify_threshold_tally_result,
)


CHAIN_FILE = "chain.json"
MEMPOOL_FILE = "mempool.json"
PEERS_FILE = "peers.json"
GENESIS_VALIDATOR_ID = "genesis"


def utc_now() -> str:
    """Return a timezone-aware timestamp so nodes serialize time consistently."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    """
    Serialize JSON-compatible data into a deterministic string.

    Hashes and signatures must be computed over exactly the same byte sequence
    on every node. `sort_keys=True` plus compact separators gives us a simple
    canonical encoding for this prototype.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(value: Any) -> str:
    """Hash a JSON-compatible value with the canonical representation."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_time(value: str) -> dt.datetime:
    """
    Parse an ISO timestamp and normalize naive timestamps to UTC.

    Existing project code used naive timestamps. The v2 chain prefers explicit
    UTC, but accepting naive input makes tests and simple clients less brittle.
    """
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def generate_validator_keypair() -> dict:
    """
    Generate an Ed25519 keypair for a PoA validator node.

    The private key is encoded as a raw 32-byte hex string so it can be placed in
    `NODE_PRIVATE_KEY` for local demos. The public key goes into
    `VALIDATORS_JSON`.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "private_key": private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex(),
    }


def private_key_from_hex(value: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from the raw hex form used in env config."""
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))


def public_key_from_hex(value: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from the raw hex form used in validators config."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


def public_key_hex_from_private(private_key_hex: str) -> str:
    """Derive the raw public key hex for a private key hex string."""
    return private_key_from_hex(private_key_hex).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def normalize_validators(validators_json: Optional[str], node_id: str, node_private_key: Optional[str]) -> dict[str, str]:
    """
    Build the validator registry from env-style configuration.

    Supported shapes:
    - {"node-a": "<public-key-hex>", "node-b": "<public-key-hex>"}
    - [{"node_id": "node-a", "public_key": "<public-key-hex>"}]

    If no registry is supplied but the local node has a private key, the module
    configures a one-validator dev network. That keeps local demos pleasant
    while still using real signatures.
    """
    if validators_json:
        parsed = json.loads(validators_json)
        if isinstance(parsed, dict):
            return {str(node): str(public_key) for node, public_key in parsed.items()}
        if isinstance(parsed, list):
            return {str(item["node_id"]): str(item["public_key"]) for item in parsed}
        raise ValueError("VALIDATORS_JSON must be a dict or list")

    if node_private_key:
        return {node_id: public_key_hex_from_private(node_private_key)}

    return {}


def make_transaction(tx_type: str, payload: dict, timestamp: Optional[str] = None) -> dict:
    """
    Create a deterministic transaction envelope.

    User transactions are intentionally unsigned in this prototype. Consensus is
    provided by signed blocks, and vote eligibility is represented by the
    placeholder proof fields. The `tx_id` is the hash of the type, timestamp and
    payload, making duplicate detection simple across nodes.
    """
    transaction = {
        "type": tx_type,
        "timestamp": timestamp or utc_now(),
        "payload": copy.deepcopy(payload),
    }
    transaction["tx_id"] = sha256_hex(transaction)
    return transaction


def block_signing_payload(block: dict) -> dict:
    """
    Extract the exact block fields that are signed by a PoA validator.

    Signatures and block hashes are excluded because they are derived from the
    content. Every node recomputes this payload before verifying a block.
    """
    return {
        "index": block["index"],
        "timestamp": block["timestamp"],
        "previous_hash": block["previous_hash"],
        "validator_id": block["validator_id"],
        "transactions": block["transactions"],
    }


def block_content_hash(block: dict) -> str:
    """Hash the validator-signed block content."""
    return sha256_hex(block_signing_payload(block))


def block_hash(block: dict) -> str:
    """
    Hash the full committed block.

    The full block hash includes the signature, so two validators cannot produce
    the same final block hash for the same content unless they use the same key.
    """
    return sha256_hex(
        {
            **block_signing_payload(block),
            "signature": block.get("signature", ""),
        }
    )


def create_genesis_block() -> dict:
    """Create the fixed first block used by every local v2 node."""
    block = {
        "index": 1,
        "timestamp": "1970-01-01T00:00:00+00:00",
        "previous_hash": "0",
        "validator_id": GENESIS_VALIDATOR_ID,
        "transactions": [],
        "signature": "",
    }
    block["block_hash"] = block_hash(block)
    return block


def sign_block(block: dict, private_key_hex: str) -> dict:
    """
    Return a signed block copy.

    The validator signs the content hash, not a Python object directly. That
    keeps the signature independent from dictionary insertion order.
    """
    signed_block = copy.deepcopy(block)
    private_key = private_key_from_hex(private_key_hex)
    signature = private_key.sign(block_content_hash(signed_block).encode("utf-8"))
    signed_block["signature"] = signature.hex()
    signed_block["block_hash"] = block_hash(signed_block)
    return signed_block


def verify_block_signature(block: dict, validators: dict[str, str]) -> bool:
    """
    Verify that a non-genesis block was signed by a configured validator.

    This is the core Proof-of-Authority check. A block signed by an unknown key
    or with a signature over different content is rejected.
    """
    validator_id = block.get("validator_id")
    if validator_id not in validators:
        return False

    try:
        public_key = public_key_from_hex(validators[validator_id])
        public_key.verify(
            bytes.fromhex(block["signature"]),
            block_content_hash(block).encode("utf-8"),
        )
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


@dataclass
class ElectionState:
    """
    Deterministic state reconstructed from committed chain transactions.

    Nothing in this object is treated as the source of truth. It is a replay
    cache built from blocks whenever a node needs to validate or answer queries.
    """

    election_id: str
    title: str
    options: List[str]
    start_time: str
    end_time: str
    committee: dict
    finalized: bool = False
    registered_commitments: set[str] = field(default_factory=set)
    used_nullifiers: set[str] = field(default_factory=set)
    encrypted_ballots: List[dict] = field(default_factory=list)
    published_result: Optional[dict] = None

    def is_open_at(self, timestamp: str) -> bool:
        """Return whether a vote/register transaction timestamp is in the election window."""
        moment = parse_time(timestamp)
        return not self.finalized and parse_time(self.start_time) <= moment <= parse_time(self.end_time)

    def is_publishable_at(self, timestamp: str) -> bool:
        """Return whether a tally publication is allowed for this election."""
        return self.finalized or parse_time(timestamp) >= parse_time(self.end_time)

    def public_dict(self) -> dict:
        """Expose public election state without leaking any private committee material."""
        return {
            "election_id": self.election_id,
            "title": self.title,
            "options": self.options,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "committee": self.committee,
            "finalized": self.finalized,
            "registered_voters": len(self.registered_commitments),
            "encrypted_votes": len(self.encrypted_ballots),
            "has_published_result": self.published_result is not None,
        }


class DistributedVotingBlockchain:
    """
    V2 node-local blockchain engine.

    One instance represents one node. Multiple instances with different
    `data_dir` values model separate nodes. A node accepts transactions into a
    mempool, validators sign blocks, and every node independently validates any
    block or longer chain before accepting it.
    """

    def __init__(
        self,
        node_id: str,
        data_dir: str | Path,
        validators: Optional[dict[str, str]] = None,
        private_key_hex: Optional[str] = None,
        peers: Optional[Iterable[str]] = None,
    ):
        self.node_id = node_id
        self.data_dir = Path(data_dir)
        self.validators = validators or {}
        self.private_key_hex = private_key_hex
        self.peers = list(dict.fromkeys(peers or []))
        self.chain: List[dict] = []
        self.mempool: List[dict] = []
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._load_or_initialize()

    @classmethod
    def from_env(cls) -> "DistributedVotingBlockchain":
        """Create a node from the environment variables defined in the plan."""
        node_id = os.environ.get("NODE_ID", "node-local")
        private_key_hex = os.environ.get("NODE_PRIVATE_KEY")
        validators = normalize_validators(os.environ.get("VALIDATORS_JSON"), node_id, private_key_hex)
        peers = [peer.strip() for peer in os.environ.get("PEERS", "").split(",") if peer.strip()]
        data_dir = os.environ.get("DATA_DIR", f".node-data/{node_id}")
        return cls(
            node_id=node_id,
            data_dir=data_dir,
            validators=validators,
            private_key_hex=private_key_hex,
            peers=peers,
        )

    def node_info(self) -> dict:
        """Return public operational information about this node."""
        return {
            "node_id": self.node_id,
            "is_validator": self.node_id in self.validators and bool(self.private_key_hex),
            "validators": self.validators,
            "peers": self.peers,
            "chain_length": len(self.chain),
            "mempool_size": len(self.mempool),
            "latest_block_hash": self.chain[-1]["block_hash"],
            "data_dir": str(self.data_dir),
        }

    def submit_transaction(self, tx_type: str, payload: dict) -> dict:
        """
        Validate and add a transaction to the local mempool.

        The validation state includes committed blocks plus already pending
        mempool transactions, so the same node will reject duplicate nullifiers
        before a block is mined.
        """
        transaction = make_transaction(tx_type, payload)
        if any(tx["tx_id"] == transaction["tx_id"] for tx in self.mempool):
            raise ValueError("transaction already in mempool")

        state = self.reconstruct_state(extra_transactions=self.mempool)
        self._validate_transaction(transaction, state)
        self.mempool.append(transaction)
        self._persist_mempool()
        return transaction

    def mine_block(self) -> dict:
        """
        Create, sign and commit a block from the current mempool.

        Only configured validators with a private key can mine. The method
        revalidates all pending transactions against committed state before
        signing, because mempool contents may have become stale after sync.
        """
        if self.node_id not in self.validators:
            raise ValueError("this node is not configured as a validator")
        if not self.private_key_hex:
            raise ValueError("validator private key is missing")
        if not self.mempool:
            raise ValueError("mempool is empty")

        state = self.reconstruct_state()
        valid_transactions = []
        for transaction in self.mempool:
            self._validate_transaction(transaction, state)
            self._apply_transaction(transaction, state)
            valid_transactions.append(transaction)

        unsigned_block = {
            "index": len(self.chain) + 1,
            "timestamp": utc_now(),
            "previous_hash": self.chain[-1]["block_hash"],
            "validator_id": self.node_id,
            "transactions": valid_transactions,
        }
        block = sign_block(unsigned_block, self.private_key_hex)
        self.accept_block(block)
        return block

    def accept_block(self, block: dict) -> bool:
        """
        Validate and append a block received locally or from a peer.

        A block is accepted only if it extends the current tip, has a valid PoA
        signature, has the expected hash, and all contained transactions replay
        cleanly from the current state.
        """
        self._validate_next_block(block)
        transaction_ids = {transaction["tx_id"] for transaction in block["transactions"]}
        self.chain.append(copy.deepcopy(block))
        self.mempool = [transaction for transaction in self.mempool if transaction["tx_id"] not in transaction_ids]
        self._persist_all()
        return True

    def replace_chain_if_valid(self, candidate_chain: List[dict]) -> bool:
        """
        Replace the local chain with a longer valid chain.

        This is the simple v1 fork rule from the plan. It is intentionally not a
        full BFT consensus protocol; it is enough to demonstrate sync and public
        validation for the prototype.
        """
        if len(candidate_chain) <= len(self.chain):
            return False
        self._validate_chain(candidate_chain)
        self.chain = copy.deepcopy(candidate_chain)
        committed_ids = {
            transaction["tx_id"]
            for block in self.chain
            for transaction in block["transactions"]
        }
        self.mempool = [transaction for transaction in self.mempool if transaction["tx_id"] not in committed_ids]
        self._persist_all()
        return True

    def add_peer(self, peer_url: str) -> None:
        """Add a peer base URL to the local peer list."""
        clean_peer = peer_url.rstrip("/")
        if clean_peer and clean_peer not in self.peers:
            self.peers.append(clean_peer)
            self._persist_peers()

    def sync_from_peers(self) -> dict:
        """
        Pull chain and mempool data from configured HTTP peers.

        The method accepts a longer chain only after full validation. Mempool
        transactions from peers are revalidated locally before being added.
        """
        adopted_chain = False
        imported_transactions = 0
        errors = []
        for peer in self.peers:
            try:
                chain_response = self._get_json(f"{peer}/api/v2/chain")
                adopted_chain = self.replace_chain_if_valid(chain_response["chain"]) or adopted_chain

                mempool_response = self._get_json(f"{peer}/api/v2/mempool")
                for transaction in mempool_response["transactions"]:
                    if self._add_peer_transaction(transaction):
                        imported_transactions += 1
            except (urllib.error.URLError, ValueError, KeyError, json.JSONDecodeError) as exc:
                errors.append({"peer": peer, "error": str(exc)})

        return {
            "adopted_chain": adopted_chain,
            "imported_transactions": imported_transactions,
            "errors": errors,
        }

    def get_block(self, index: int) -> dict:
        """Return one block by its 1-based chain index."""
        if index < 1 or index > len(self.chain):
            raise ValueError("block not found")
        return self.chain[index - 1]

    def reconstruct_state(self, extra_transactions: Optional[List[dict]] = None) -> dict[str, ElectionState]:
        """
        Replay the chain into election state.

        The method is deliberately deterministic: public APIs and validators use
        this same replay path, so a published result is checked against the same
        state that accepted the original vote transactions.
        """
        state: dict[str, ElectionState] = {}
        for block in self.chain[1:]:
            for transaction in block["transactions"]:
                self._validate_transaction(transaction, state)
                self._apply_transaction(transaction, state)

        for transaction in extra_transactions or []:
            self._validate_transaction(transaction, state)
            self._apply_transaction(transaction, state)

        return state

    def list_elections(self) -> List[dict]:
        """Return all public election states reconstructed from the chain."""
        return [election.public_dict() for election in self.reconstruct_state().values()]

    def get_election(self, election_id: str) -> ElectionState:
        """Return reconstructed state for one election."""
        state = self.reconstruct_state()
        if election_id not in state:
            raise ValueError("election not found")
        return state[election_id]

    def encrypted_ballots(self, election_id: str) -> List[dict]:
        """Return all encrypted ballot payloads for one election."""
        return self.get_election(election_id).encrypted_ballots

    def encrypted_tally(self, election_id: str) -> Optional[dict]:
        """
        Recompute and return the encrypted tally for one election.

        If no encrypted ballots exist yet, there is no meaningful tally.
        """
        election = self.get_election(election_id)
        if not election.encrypted_ballots:
            return None
        public_key = PetlibPublicKey.from_payload(election.committee)
        ballots = [
            EncryptedBallot.from_chain_payload(public_key, ballot_payload)
            for ballot_payload in election.encrypted_ballots
        ]
        return aggregate_encrypted_ballots(public_key, ballots).to_chain_payload()

    def published_result(self, election_id: str) -> Optional[dict]:
        """Return the published committee result, if one exists."""
        return self.get_election(election_id).published_result

    def transaction_status(self, tx_id: str) -> dict:
        """
        Locate a transaction in the mempool or committed chain.

        This is mostly for the visual demo clients. After a voter submits a
        ballot, the UI can show whether the vote is still pending in the mempool
        or already committed inside a signed block.
        """
        clean_tx_id = str(tx_id).strip()
        if not clean_tx_id:
            raise ValueError("tx_id is required")

        for transaction in self.mempool:
            if transaction["tx_id"] == clean_tx_id:
                return {
                    "tx_id": clean_tx_id,
                    "status": "mempool",
                    "transaction": transaction,
                    "block": None,
                }

        for block in self.chain:
            for transaction_index, transaction in enumerate(block["transactions"]):
                if transaction["tx_id"] == clean_tx_id:
                    return {
                        "tx_id": clean_tx_id,
                        "status": "committed",
                        "transaction": transaction,
                        "transaction_index": transaction_index,
                        "block": {
                            "index": block["index"],
                            "block_hash": block["block_hash"],
                            "previous_hash": block["previous_hash"],
                            "validator_id": block["validator_id"],
                            "timestamp": block["timestamp"],
                        },
                    }

        return {
            "tx_id": clean_tx_id,
            "status": "not_found",
            "transaction": None,
            "block": None,
        }

    def verify_election(self, election_id: str) -> dict:
        """
        Publicly verify the chain-derived state for one election.

        This endpoint-style method checks the pieces that any observer can
        independently recompute: unique nullifiers, encrypted tally consistency,
        and published threshold decryption proofs when a result exists. The
        returned check names are deliberately presentation-friendly, because the
        dashboard uses them to explain what the verifier is doing.
        """
        election = self.get_election(election_id)
        checks = {
            "chain_valid": self.is_chain_valid(),
            "nullifiers_unique": len(election.used_nullifiers) == len(election.encrypted_ballots),
            "encrypted_ballots_importable": True,
            "encrypted_tally_matches_ballots": False,
            "published_encrypted_tally_matches_ballots": None,
            "partial_decryption_proofs_valid": None,
            "plaintext_tally_matches_decryption": None,
            "published_result_valid": None,
        }
        published_details: dict[str, Any] = {}

        public_key = PetlibPublicKey.from_payload(election.committee)
        if election.encrypted_ballots:
            try:
                ballots = [
                    EncryptedBallot.from_chain_payload(public_key, ballot_payload)
                    for ballot_payload in election.encrypted_ballots
                ]
                aggregate_encrypted_ballots(public_key, ballots)
                checks["encrypted_tally_matches_ballots"] = True
            except Exception:
                checks["encrypted_ballots_importable"] = False
                checks["encrypted_tally_matches_ballots"] = False
        else:
            checks["encrypted_tally_matches_ballots"] = True

        if election.published_result:
            published_details = self._verify_published_tally_details(election)
            checks.update(
                {
                    "published_encrypted_tally_matches_ballots": published_details[
                        "published_encrypted_tally_matches_ballots"
                    ],
                    "partial_decryption_proofs_valid": published_details["partial_decryption_proofs_valid"],
                    "plaintext_tally_matches_decryption": published_details["plaintext_tally_matches_decryption"],
                    "published_result_valid": published_details["published_result_valid"],
                }
            )

        checks_passed = all(value is not False for value in checks.values())
        result_complete = bool(
            election.finalized
            and election.published_result
            and checks.get("published_result_valid") is True
        )
        return {
            "election_id": election_id,
            "checks": checks,
            "published_details": published_details,
            "valid": checks_passed,
            "complete": result_complete,
            "result_status": (
                "verified" if result_complete
                else "awaiting_tally" if election.finalized
                else "election_open"
            ),
        }

    def is_chain_valid(self) -> bool:
        """Return whether the current local chain validates from genesis to tip."""
        try:
            self._validate_chain(self.chain)
            return True
        except ValueError:
            return False

    def _load_or_initialize(self) -> None:
        """Load chain, mempool and peers from disk, or create a fresh genesis chain."""
        chain_path = self.data_dir / CHAIN_FILE
        mempool_path = self.data_dir / MEMPOOL_FILE
        peers_path = self.data_dir / PEERS_FILE

        if chain_path.exists():
            self.chain = json.loads(chain_path.read_text())
            self._validate_chain(self.chain)
        else:
            self.chain = [create_genesis_block()]
            self._persist_chain()

        if mempool_path.exists():
            self.mempool = json.loads(mempool_path.read_text())
        else:
            self.mempool = []
            self._persist_mempool()

        if peers_path.exists():
            self.peers = list(dict.fromkeys(json.loads(peers_path.read_text()) + self.peers))
        self._persist_peers()

    def _persist_all(self) -> None:
        """Persist all node-local JSON files."""
        self._persist_chain()
        self._persist_mempool()
        self._persist_peers()

    def _persist_chain(self) -> None:
        """Persist the local chain JSON file."""
        self._write_json(self.data_dir / CHAIN_FILE, self.chain)

    def _persist_mempool(self) -> None:
        """Persist the local mempool JSON file."""
        self._write_json(self.data_dir / MEMPOOL_FILE, self.mempool)

    def _persist_peers(self) -> None:
        """Persist the peer list JSON file."""
        self._write_json(self.data_dir / PEERS_FILE, self.peers)

    def _write_json(self, path: Path, value: Any) -> None:
        """Write JSON in a stable, human-readable form for debugging demos."""
        path.write_text(json.dumps(value, indent=2, sort_keys=True))

    def _validate_chain(self, chain: List[dict]) -> None:
        """Validate a complete chain from genesis to tip."""
        if not chain:
            raise ValueError("chain is empty")
        if chain[0] != create_genesis_block():
            raise ValueError("invalid genesis block")

        state: dict[str, ElectionState] = {}
        for index, block in enumerate(chain[1:], start=2):
            previous = chain[index - 2]
            self._validate_block_against_previous(block, previous, expected_index=index)
            for transaction in block["transactions"]:
                self._validate_transaction(transaction, state)
                self._apply_transaction(transaction, state)

    def _validate_next_block(self, block: dict) -> None:
        """Validate a candidate block against the local current tip."""
        self._validate_block_against_previous(block, self.chain[-1], expected_index=len(self.chain) + 1)
        state = self.reconstruct_state()
        for transaction in block["transactions"]:
            self._validate_transaction(transaction, state)
            self._apply_transaction(transaction, state)

    def _validate_block_against_previous(self, block: dict, previous: dict, expected_index: int) -> None:
        """Check structural, hash and PoA signature rules for one block."""
        if block.get("index") != expected_index:
            raise ValueError("block index does not extend chain")
        if block.get("previous_hash") != previous["block_hash"]:
            raise ValueError("previous hash mismatch")
        if block.get("block_hash") != block_hash(block):
            raise ValueError("block hash mismatch")
        if not verify_block_signature(block, self.validators):
            raise ValueError("invalid validator signature")

    def _validate_transaction(self, transaction: dict, state: dict[str, ElectionState]) -> None:
        """Dispatch transaction validation by type."""
        expected_tx_id = sha256_hex(
            {
                "type": transaction["type"],
                "timestamp": transaction["timestamp"],
                "payload": transaction["payload"],
            }
        )
        if transaction.get("tx_id") != expected_tx_id:
            raise ValueError("transaction hash mismatch")

        tx_type = transaction["type"]
        payload = transaction["payload"]
        if tx_type == "create_election":
            self._validate_create_election(payload, state)
        elif tx_type == "register_voter":
            self._validate_register_voter(transaction, payload, state)
        elif tx_type == "cast_encrypted_vote":
            self._validate_cast_encrypted_vote(transaction, payload, state)
        elif tx_type == "finalize_election":
            self._validate_finalize_election(payload, state)
        elif tx_type == "publish_tally_result":
            self._validate_publish_tally_result(transaction, payload, state)
        else:
            raise ValueError(f"unknown transaction type: {tx_type}")

    def _apply_transaction(self, transaction: dict, state: dict[str, ElectionState]) -> None:
        """Apply an already validated transaction to reconstructed state."""
        tx_type = transaction["type"]
        payload = transaction["payload"]
        if tx_type == "create_election":
            state[payload["election_id"]] = ElectionState(
                election_id=payload["election_id"],
                title=payload["title"].strip(),
                options=list(payload["options"]),
                start_time=payload["start_time"],
                end_time=payload["end_time"],
                committee=copy.deepcopy(payload["committee"]),
            )
        elif tx_type == "register_voter":
            state[payload["election_id"]].registered_commitments.add(payload["commitment_hash"])
        elif tx_type == "cast_encrypted_vote":
            election = state[payload["election_id"]]
            election.used_nullifiers.add(payload["nullifier_hash"])
            election.encrypted_ballots.append(copy.deepcopy(payload["encrypted_ballot"]))
        elif tx_type == "finalize_election":
            state[payload["election_id"]].finalized = True
        elif tx_type == "publish_tally_result":
            state[payload["election_id"]].published_result = copy.deepcopy(payload)

    def _validate_create_election(self, payload: dict, state: dict[str, ElectionState]) -> None:
        """Validate election metadata and public committee material."""
        election_id = str(payload.get("election_id", "")).strip()
        title = str(payload.get("title", "")).strip()
        options = payload.get("options")
        if not election_id:
            raise ValueError("election_id is required")
        if election_id in state:
            raise ValueError("election already exists")
        if not title:
            raise ValueError("title is required")
        if not isinstance(options, list) or len(options) < 2:
            raise ValueError("at least two options are required")
        clean_options = [str(option).strip() for option in options]
        if any(not option for option in clean_options) or len(set(clean_options)) != len(clean_options):
            raise ValueError("options must be non-empty and unique")

        start_time = parse_time(payload["start_time"])
        end_time = parse_time(payload["end_time"])
        if end_time <= start_time:
            raise ValueError("end_time must be after start_time")

        committee = payload["committee"]
        public_key = PetlibPublicKey.from_payload(committee)
        public_shares = public_shares_from_payload(public_key, committee)
        threshold = int(committee["threshold"])
        member_count = int(committee["member_count"])
        if threshold < 1 or threshold > member_count:
            raise ValueError("invalid committee threshold")
        if len(public_shares) != member_count:
            raise ValueError("public share count does not match member_count")

    def _validate_register_voter(self, transaction: dict, payload: dict, state: dict[str, ElectionState]) -> None:
        """Validate demo eligibility registration."""
        election = self._existing_election(payload["election_id"], state)
        commitment_hash = str(payload.get("commitment_hash", "")).strip()
        if not commitment_hash:
            raise ValueError("commitment_hash is required")
        if not election.is_open_at(transaction["timestamp"]):
            raise ValueError("election is not open for registration")
        if commitment_hash in election.registered_commitments:
            raise ValueError("commitment already registered")

    def _validate_cast_encrypted_vote(self, transaction: dict, payload: dict, state: dict[str, ElectionState]) -> None:
        """Validate encrypted vote shape, nullifier uniqueness and placeholder proofs."""
        election = self._existing_election(payload["election_id"], state)
        if not election.is_open_at(transaction["timestamp"]):
            raise ValueError("election is not open for voting")

        nullifier_hash = str(payload.get("nullifier_hash", "")).strip()
        if not nullifier_hash:
            raise ValueError("nullifier_hash is required")
        if nullifier_hash in election.used_nullifiers:
            raise ValueError("nullifier already used")

        eligibility_proof = payload.get("eligibility_proof_placeholder")
        ballot_proof = payload.get("ballot_validity_proof_placeholder")
        if not isinstance(eligibility_proof, dict) or not eligibility_proof.get("accepted"):
            raise ValueError("eligibility proof placeholder is missing or rejected")
        if not isinstance(ballot_proof, dict) or not ballot_proof.get("accepted"):
            raise ValueError("ballot validity proof placeholder is missing or rejected")

        commitment_hash = str(eligibility_proof.get("commitment_hash", "")).strip()
        if commitment_hash not in election.registered_commitments:
            raise ValueError("eligibility commitment is not registered")
        if eligibility_proof.get("type") != "deterministic-nullifier-demo-v2":
            raise ValueError("unsupported eligibility proof placeholder")
        expected_nullifier = hashlib.sha256(
            f"{election.election_id}:{commitment_hash}:nullifier".encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(nullifier_hash, expected_nullifier):
            raise ValueError("nullifier is not bound to the registered commitment")
        if ballot_proof.get("type") != "local-one-hot-encryption-demo-v2":
            raise ValueError("unsupported ballot validity proof placeholder")

        public_key = PetlibPublicKey.from_payload(election.committee)
        encrypted_ballot = EncryptedBallot.from_chain_payload(public_key, payload["encrypted_ballot"])
        if encrypted_ballot.candidate_count != len(election.options):
            raise ValueError("encrypted ballot candidate_count does not match election options")
        if len(encrypted_ballot.ciphertexts) != len(election.options):
            raise ValueError("encrypted ballot ciphertext count does not match election options")

    def _validate_finalize_election(self, payload: dict, state: dict[str, ElectionState]) -> None:
        """Validate the small admin-style transaction that closes an election."""
        election = self._existing_election(payload["election_id"], state)
        if election.finalized:
            raise ValueError("election already finalized")

    def _validate_publish_tally_result(self, transaction: dict, payload: dict, state: dict[str, ElectionState]) -> None:
        """Validate a public threshold tally publication."""
        election = self._existing_election(payload["election_id"], state)
        if election.published_result is not None:
            raise ValueError("tally result already published")
        if not election.is_publishable_at(transaction["timestamp"]):
            raise ValueError("election is not ready for tally publication")
        if not election.encrypted_ballots:
            raise ValueError("cannot publish tally without encrypted ballots")
        if not self._verify_published_tally_payload(election, payload):
            raise ValueError("published tally result does not verify")

    def _verify_published_tally_payload(self, election: ElectionState, payload: Optional[dict] = None) -> bool:
        """Verify encrypted tally consistency and threshold decryption proofs."""
        details = self._verify_published_tally_details(election, payload)
        return bool(details["published_result_valid"])

    def _verify_published_tally_details(self, election: ElectionState, payload: Optional[dict] = None) -> dict:
        """
        Verify a published tally and explain each public verification step.

        The boolean helper above is useful for transaction validation, but the
        dashboard needs a more transparent result. This method keeps the same
        security checks and exposes the intermediate public claims separately:
        encrypted tally consistency, partial proof validity, and plaintext
        reconstruction.
        """
        payload = payload or election.published_result
        details = {
            "published_result_present": payload is not None,
            "published_encrypted_tally_matches_ballots": False,
            "enough_partial_decryptions": False,
            "partial_decryption_proofs_valid": False,
            "plaintext_tally_matches_decryption": False,
            "published_result_valid": False,
            "published_plaintext_tally": None,
            "error": None,
        }
        if payload is None:
            details["error"] = "no published result"
            return details

        try:
            public_key = PetlibPublicKey.from_payload(election.committee)
            ballots = [
                EncryptedBallot.from_chain_payload(public_key, ballot_payload)
                for ballot_payload in election.encrypted_ballots
            ]
            computed_tally = aggregate_encrypted_ballots(public_key, ballots)
            published_encrypted_tally = EncryptedTally.from_chain_payload(public_key, payload["encrypted_tally"])
            details["published_encrypted_tally_matches_ballots"] = (
                computed_tally.to_chain_payload() == published_encrypted_tally.to_chain_payload()
            )
            if not details["published_encrypted_tally_matches_ballots"]:
                details["error"] = "published encrypted tally does not match committed ballots"
                return details

            threshold = int(election.committee["threshold"])
            public_shares = public_shares_from_payload(public_key, election.committee)
            published_result = ThresholdPublishedTallyResult.from_payload(public_key, payload["published_result"])
            details["published_plaintext_tally"] = published_result.plaintext_tally

            shares_by_candidate: dict[int, list] = {
                index: [] for index in range(published_encrypted_tally.candidate_count)
            }
            for share in published_result.partial_decryption_shares:
                if share.candidate_index not in shares_by_candidate or share.member_id not in public_shares:
                    details["error"] = "partial decryption references unknown candidate or committee member"
                    return details
                existing_member_ids = {known_share.member_id for known_share in shares_by_candidate[share.candidate_index]}
                if share.member_id not in existing_member_ids:
                    shares_by_candidate[share.candidate_index].append(share)

            details["enough_partial_decryptions"] = all(
                len(candidate_shares) >= threshold for candidate_shares in shares_by_candidate.values()
            )
            if not details["enough_partial_decryptions"]:
                details["error"] = "not enough partial decryptions for every candidate"
                return details

            proofs_valid = True
            plaintext_valid = True
            for candidate_index, plaintext in enumerate(published_result.plaintext_tally):
                ciphertext = published_encrypted_tally.ciphertexts[candidate_index]
                selected_shares = shares_by_candidate[candidate_index][:threshold]
                for share in selected_shares:
                    if not verify_partial_decryption_proof(
                        public_key,
                        public_shares[share.member_id],
                        ciphertext,
                        share.decryption_factor,
                        share.proof,
                    ):
                        proofs_valid = False

                if proofs_valid:
                    combined_factor = combine_partial_decryption_factors(public_key, selected_shares, threshold)
                    plaintext_point = remove_decryption_factor(ciphertext, combined_factor)
                    if plaintext_point != Bn(plaintext) * public_key.generator:
                        plaintext_valid = False

            details["partial_decryption_proofs_valid"] = proofs_valid
            details["plaintext_tally_matches_decryption"] = plaintext_valid
            details["published_result_valid"] = verify_threshold_tally_result(
                public_key,
                public_shares,
                threshold,
                published_encrypted_tally,
                published_result,
            )
            if not details["published_result_valid"] and details["error"] is None:
                details["error"] = "published tally failed final verifier"
            return details
        except Exception as exc:
            details["error"] = str(exc)
            return details

    def _existing_election(self, election_id: str, state: dict[str, ElectionState]) -> ElectionState:
        """Return an election or raise a validation-friendly error."""
        if election_id not in state:
            raise ValueError("election does not exist")
        return state[election_id]

    def _add_peer_transaction(self, transaction: dict) -> bool:
        """Import one peer mempool transaction after local validation."""
        if any(tx["tx_id"] == transaction["tx_id"] for tx in self.mempool):
            return False
        committed_ids = {
            tx["tx_id"]
            for block in self.chain
            for tx in block["transactions"]
        }
        if transaction["tx_id"] in committed_ids:
            return False
        state = self.reconstruct_state(extra_transactions=self.mempool)
        self._validate_transaction(transaction, state)
        self.mempool.append(copy.deepcopy(transaction))
        self._persist_mempool()
        return True

    def _get_json(self, url: str) -> dict:
        """Fetch JSON from a peer using only the Python standard library."""
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


def register_v2_routes(app, node: Optional[DistributedVotingBlockchain] = None):
    """
    Attach the v2 distributed-chain API to a FastAPI app.

    The old API in `blockchainV1.py` can continue to exist. This function only
    adds `/api/v2/*` routes and stores the v2 node under `app.state.v2_node`.
    """
    from fastapi import Body, Header, HTTPException, status

    v2_node = node or DistributedVotingBlockchain.from_env()
    app.state.v2_node = v2_node
    admin_api_key = os.environ.get("V2_ADMIN_KEY", os.environ.get("ADMIN_KEY", "dev_admin_key"))
    node_api_key = os.environ.get("V2_NODE_KEY", "dev_node_key")

    def api_error(exc: Exception, status_code: int = status.HTTP_400_BAD_REQUEST):
        raise HTTPException(status_code=status_code, detail=str(exc))

    def require_api_key(provided: Optional[str], expected: str, role: str) -> None:
        """Reject privileged API actions unless the caller presents the role key."""
        if not provided or not hmac.compare_digest(provided, expected):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{role} key is invalid")

    @app.get("/api/v2/node/info")
    def v2_node_info():
        return v2_node.node_info()

    @app.get("/api/v2/chain")
    def v2_chain():
        return {"length": len(v2_node.chain), "chain": v2_node.chain}

    @app.get("/api/v2/blocks/{index}")
    def v2_block(index: int):
        try:
            return v2_node.get_block(index)
        except ValueError as exc:
            api_error(exc, status.HTTP_404_NOT_FOUND)

    @app.get("/api/v2/mempool")
    def v2_mempool():
        return {"size": len(v2_node.mempool), "transactions": v2_node.mempool}

    @app.get("/api/v2/transactions/{tx_id}")
    def v2_transaction_status(tx_id: str):
        try:
            return v2_node.transaction_status(tx_id)
        except ValueError as exc:
            api_error(exc)

    @app.post("/api/v2/peers")
    def v2_add_peer(data: dict = Body(...), x_node_key: Optional[str] = Header(None)):
        require_api_key(x_node_key, node_api_key, "node")
        v2_node.add_peer(str(data.get("url", "")))
        return {"peers": v2_node.peers}

    @app.post("/api/v2/sync")
    def v2_sync(x_node_key: Optional[str] = Header(None)):
        require_api_key(x_node_key, node_api_key, "node")
        return v2_node.sync_from_peers()

    @app.post("/api/v2/transactions", status_code=status.HTTP_201_CREATED)
    def v2_submit_transaction(data: dict = Body(...), x_admin_key: Optional[str] = Header(None)):
        try:
            tx_type = str(data["type"])
            if tx_type in {"create_election", "finalize_election"}:
                require_api_key(x_admin_key, admin_api_key, "admin")
            transaction = v2_node.submit_transaction(tx_type, data.get("payload", {}))
            return {"message": "transaction accepted into mempool", "transaction": transaction}
        except (KeyError, ValueError) as exc:
            api_error(exc)

    @app.post("/api/v2/blocks/mine", status_code=status.HTTP_201_CREATED)
    def v2_mine_block(x_node_key: Optional[str] = Header(None)):
        require_api_key(x_node_key, node_api_key, "node")
        try:
            block = v2_node.mine_block()
            return {"message": "block mined", "block": block}
        except ValueError as exc:
            api_error(exc)

    @app.post("/api/v2/blocks", status_code=status.HTTP_201_CREATED)
    def v2_accept_block(block: dict):
        try:
            v2_node.accept_block(block)
            return {"message": "block accepted", "block_hash": block["block_hash"]}
        except ValueError as exc:
            api_error(exc)

    @app.get("/api/v2/elections")
    def v2_elections():
        return {"elections": v2_node.list_elections()}

    @app.get("/api/v2/elections/{election_id}")
    def v2_election(election_id: str):
        try:
            return v2_node.get_election(election_id).public_dict()
        except ValueError as exc:
            api_error(exc, status.HTTP_404_NOT_FOUND)

    @app.get("/api/v2/elections/{election_id}/encrypted-ballots")
    def v2_encrypted_ballots(election_id: str):
        try:
            return {"encrypted_ballots": v2_node.encrypted_ballots(election_id)}
        except ValueError as exc:
            api_error(exc, status.HTTP_404_NOT_FOUND)

    @app.get("/api/v2/elections/{election_id}/encrypted-tally")
    def v2_encrypted_tally(election_id: str):
        try:
            return {"encrypted_tally": v2_node.encrypted_tally(election_id)}
        except ValueError as exc:
            api_error(exc, status.HTTP_404_NOT_FOUND)

    @app.get("/api/v2/elections/{election_id}/published-result")
    def v2_published_result(election_id: str):
        try:
            return {"published_result": v2_node.published_result(election_id)}
        except ValueError as exc:
            api_error(exc, status.HTTP_404_NOT_FOUND)

    @app.get("/api/v2/elections/{election_id}/verify")
    def v2_verify(election_id: str):
        try:
            return v2_node.verify_election(election_id)
        except ValueError as exc:
            api_error(exc, status.HTTP_404_NOT_FOUND)

    return app
