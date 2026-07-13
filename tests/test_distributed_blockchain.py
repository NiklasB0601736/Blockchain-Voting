import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from voting_system.crypto_petlib_elgamal_tally import (
    EncryptedBallot,
    aggregate_encrypted_ballots,
    encrypt_candidate_vote,
    generate_committee_key_shares,
    publish_threshold_tally_result,
)
from voting_system.distributed_blockchain import (
    DistributedVotingBlockchain,
    block_hash,
    generate_validator_keypair,
    register_v2_routes,
    sign_block,
)


def digest(value: str) -> str:
    """Return the SHA-256 hex encoding used by browser demo credentials."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def election_payload(committee, election_id: str = "election-1", option_count: int = 3) -> dict:
    """Create election data whose time window stays stable during tests."""
    return {
        "election_id": election_id,
        "title": "Distributed Test Election",
        "options": [f"Candidate {index}" for index in range(option_count)],
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": "2027-01-01T00:00:00+00:00",
        "committee": committee.public_payload(),
    }


def vote_payload(committee, election_id: str, voter: str, candidate_index: int, option_count: int) -> dict:
    """Create the public payload produced by the browser-side Voter Client."""
    commitment = digest(voter)
    return {
        "election_id": election_id,
        "nullifier_hash": digest(f"{election_id}:{commitment}:nullifier"),
        "encrypted_ballot": encrypt_candidate_vote(
            committee.public_key,
            candidate_index,
            option_count,
        ).to_chain_payload(),
        "eligibility_proof_placeholder": {
            "type": "deterministic-nullifier-demo-v2",
            "accepted": True,
            "commitment_hash": commitment,
        },
        "ballot_validity_proof_placeholder": {
            "type": "local-one-hot-encryption-demo-v2",
            "accepted": True,
        },
    }


class DistributedVotingBlockchainTest(unittest.TestCase):
    """Core, API-role and encrypted voting integration tests for the V2 chain."""

    def make_node(self, data_dir: Path, node_id: str = "validator-a"):
        keys = generate_validator_keypair()
        validators = {node_id: keys["public_key"]}
        node = DistributedVotingBlockchain(
            node_id=node_id,
            data_dir=data_dir,
            validators=validators,
            private_key_hex=keys["private_key"],
        )
        return node, keys, validators

    def prepare_voters(self, node, committee, voters: list[str]) -> None:
        node.submit_transaction("create_election", election_payload(committee))
        for voter in voters:
            node.submit_transaction(
                "register_voter",
                {"election_id": "election-1", "commitment_hash": digest(voter)},
            )

    def test_block_hash_and_validator_signature_reject_tampering(self):
        with tempfile.TemporaryDirectory() as node_a_dir, tempfile.TemporaryDirectory() as node_b_dir:
            node_a, _, validators = self.make_node(Path(node_a_dir))
            committee = generate_committee_key_shares(3, 2)
            node_a.submit_transaction("create_election", election_payload(committee))
            block = node_a.mine_block()
            original_hash = block_hash(block)

            observer = DistributedVotingBlockchain("observer", Path(node_b_dir), validators=validators)
            self.assertTrue(observer.accept_block(block))
            tampered = {**block, "transactions": [{**block["transactions"][0], "payload": {
                **block["transactions"][0]["payload"], "title": "Changed",
            }}]}
            self.assertNotEqual(block_hash(tampered), original_hash)
            with self.assertRaises(ValueError):
                DistributedVotingBlockchain(
                    "observer-2", Path(tempfile.mkdtemp()), validators=validators,
                ).accept_block(tampered)

    def test_unknown_validator_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, validators = self.make_node(Path(tmp))
            attacker = generate_validator_keypair()
            block = sign_block({
                "index": 2,
                "timestamp": "2026-07-13T00:00:00+00:00",
                "previous_hash": node.chain[-1]["block_hash"],
                "validator_id": "attacker",
                "transactions": [],
            }, attacker["private_key"])
            with self.assertRaises(ValueError):
                DistributedVotingBlockchain(
                    "observer", Path(tempfile.mkdtemp()), validators=validators,
                ).accept_block(block)

    def test_mempool_and_transaction_status_move_to_committed_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(3, 2)
            transaction = node.submit_transaction("create_election", election_payload(committee))
            self.assertEqual(node.transaction_status(transaction["tx_id"])["status"], "mempool")
            node.mine_block()
            status = node.transaction_status(transaction["tx_id"])
            self.assertEqual(status["status"], "committed")
            self.assertEqual(status["block"]["index"], 2)
            self.assertEqual(node.mempool, [])

    def test_nullifier_must_be_bound_to_registered_commitment(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(3, 2)
            self.prepare_voters(node, committee, ["alice"])
            invalid = vote_payload(committee, "election-1", "alice", 0, 3)
            invalid["nullifier_hash"] = digest("arbitrary-new-nullifier")
            with self.assertRaisesRegex(ValueError, "not bound"):
                node.submit_transaction("cast_encrypted_vote", invalid)

    def test_duplicate_nullifier_is_rejected_while_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(3, 2)
            self.prepare_voters(node, committee, ["alice"])
            node.submit_transaction("cast_encrypted_vote", vote_payload(committee, "election-1", "alice", 0, 3))
            with self.assertRaisesRegex(ValueError, "nullifier already used"):
                node.submit_transaction("cast_encrypted_vote", vote_payload(committee, "election-1", "alice", 1, 3))

    def test_wrong_candidate_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(3, 2)
            self.prepare_voters(node, committee, ["alice"])
            with self.assertRaises(ValueError):
                node.submit_transaction(
                    "cast_encrypted_vote",
                    vote_payload(committee, "election-1", "alice", 0, 2),
                )

    def test_threshold_tally_verifies_from_public_chain_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(3, 2)
            self.prepare_voters(node, committee, ["alice", "bob"])
            node.submit_transaction("cast_encrypted_vote", vote_payload(committee, "election-1", "alice", 0, 3))
            node.submit_transaction("cast_encrypted_vote", vote_payload(committee, "election-1", "bob", 1, 3))
            node.mine_block()
            node.submit_transaction("finalize_election", {"election_id": "election-1"})
            node.mine_block()

            ballots = [
                EncryptedBallot.from_chain_payload(committee.public_key, payload)
                for payload in node.encrypted_ballots("election-1")
            ]
            encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)
            result = publish_threshold_tally_result(committee, encrypted_tally, [1, 3], len(ballots))
            node.submit_transaction("publish_tally_result", {
                "election_id": "election-1",
                "encrypted_tally": encrypted_tally.to_chain_payload(),
                "published_result": result.to_payload(),
            })
            node.mine_block()

            verification = node.verify_election("election-1")
            self.assertTrue(verification["valid"])
            self.assertTrue(verification["complete"])
            self.assertEqual(verification["result_status"], "verified")

    def test_verify_distinguishes_open_chain_from_completed_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(3, 2)
            node.submit_transaction("create_election", election_payload(committee))
            node.mine_block()
            verification = node.verify_election("election-1")
            self.assertTrue(verification["valid"])
            self.assertFalse(verification["complete"])
            self.assertEqual(verification["result_status"], "election_open")

    def test_longer_valid_chain_replaces_observer_chain(self):
        with tempfile.TemporaryDirectory() as node_a_dir, tempfile.TemporaryDirectory() as node_b_dir:
            node_a, _, validators = self.make_node(Path(node_a_dir))
            committee = generate_committee_key_shares(3, 2)
            node_a.submit_transaction("create_election", election_payload(committee))
            node_a.mine_block()
            observer = DistributedVotingBlockchain("observer", Path(node_b_dir), validators=validators)
            self.assertTrue(observer.replace_chain_if_valid(node_a.chain))
            self.assertEqual(observer.chain[-1]["block_hash"], node_a.chain[-1]["block_hash"])

    def test_privileged_api_actions_require_role_keys(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            "V2_ADMIN_KEY": "admin-test",
            "V2_NODE_KEY": "node-test",
        }):
            node, _, _ = self.make_node(Path(tmp))
            app = FastAPI()
            register_v2_routes(app, node=node)
            client = TestClient(app)
            committee = generate_committee_key_shares(3, 2)
            body = {"type": "create_election", "payload": election_payload(committee)}

            self.assertEqual(client.post("/api/v2/transactions", json=body).status_code, 403)
            accepted = client.post(
                "/api/v2/transactions", json=body, headers={"X-Admin-Key": "admin-test"},
            )
            self.assertEqual(accepted.status_code, 201)
            self.assertEqual(client.post("/api/v2/blocks/mine").status_code, 403)
            mined = client.post("/api/v2/blocks/mine", headers={"X-Node-Key": "node-test"})
            self.assertEqual(mined.status_code, 201)


if __name__ == "__main__":
    unittest.main()
