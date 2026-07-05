import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from crypto_petlib_elgamal_tally import (
    aggregate_encrypted_ballots,
    encrypt_candidate_vote,
    generate_committee_key_shares,
    publish_threshold_tally_result,
)
from distributed_blockchain import (
    DistributedVotingBlockchain,
    block_hash,
    generate_validator_keypair,
    register_v2_routes,
    sign_block,
)


def commitment_hash(label: str) -> str:
    """Create a deterministic demo commitment hash for tests."""
    return hashlib.sha256(label.encode()).hexdigest()


def future_election_payload(committee, election_id: str = "election-1", option_count: int = 3) -> dict:
    """
    Build a valid create_election payload.

    The timestamps are intentionally wide so tests do not depend on sleeping or
    the current wall-clock second.
    """
    return {
        "election_id": election_id,
        "title": "Distributed Test Election",
        "options": [f"Candidate {index}" for index in range(option_count)],
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": "2027-01-01T00:00:00+00:00",
        "committee": committee.public_payload(),
    }


def encrypted_vote_payload(committee, election_id: str, voter_label: str, candidate_index: int, option_count: int) -> dict:
    """
    Build a valid encrypted vote transaction payload.

    The proof fields are explicit placeholders. They make the intended
    Semaphore/ZK interface visible while keeping this prototype focused on the
    chain and Petlib tally plumbing.
    """
    ballot = encrypt_candidate_vote(committee.public_key, candidate_index, option_count)
    voter_commitment = commitment_hash(voter_label)
    return {
        "election_id": election_id,
        "nullifier_hash": commitment_hash(f"{election_id}:{voter_label}:nullifier"),
        "encrypted_ballot": ballot.to_chain_payload(),
        "eligibility_proof_placeholder": {
            "type": "semaphore-placeholder",
            "accepted": True,
            "commitment_hash": voter_commitment,
        },
        "ballot_validity_proof_placeholder": {
            "type": "one-hot-zk-placeholder",
            "accepted": True,
        },
    }


class DistributedVotingBlockchainTest(unittest.TestCase):
    """End-to-end tests for the v2 distributed voting chain core."""

    def make_node(self, data_dir: Path, node_id: str = "validator-a"):
        """
        Create a validator node with an isolated JSON data directory.

        Each test uses fresh keys and storage so block signatures, persistence
        and replay validation are exercised without cross-test state.
        """
        keys = generate_validator_keypair()
        validators = {node_id: keys["public_key"]}
        node = DistributedVotingBlockchain(
            node_id=node_id,
            data_dir=data_dir,
            validators=validators,
            private_key_hex=keys["private_key"],
        )
        return node, keys, validators

    def add_basic_election_and_registration(self, node, committee, voters):
        """Submit create_election and register_voter transactions to the mempool."""
        node.submit_transaction("create_election", future_election_payload(committee))
        for voter in voters:
            node.submit_transaction(
                "register_voter",
                {
                    "election_id": "election-1",
                    "commitment_hash": commitment_hash(voter),
                },
            )

    def test_block_hash_changes_when_transaction_changes(self):
        """
        Canonical block hashes must commit to transaction contents.

        If anyone changes a transaction after signing/mining, other nodes should
        reject the block because the block hash no longer matches.
        """
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node, committee, ["alice"])
            block = node.mine_block()

            tampered_block = dict(block)
            tampered_block["transactions"] = [dict(tx) for tx in block["transactions"]]
            tampered_block["transactions"][0] = dict(tampered_block["transactions"][0])
            tampered_block["transactions"][0]["payload"] = dict(tampered_block["transactions"][0]["payload"])
            tampered_block["transactions"][0]["payload"]["title"] = "Tampered"

            self.assertNotEqual(block_hash(block), block_hash(tampered_block))

    def test_validator_signature_accepts_valid_block_and_rejects_tampering(self):
        """
        A peer accepts a correctly signed validator block and rejects tampering.

        This is the central PoA property: validator signatures are meaningful,
        but the receiving node still validates content and hashes itself.
        """
        with tempfile.TemporaryDirectory() as node_a_dir, tempfile.TemporaryDirectory() as node_b_dir:
            node_a, _, validators = self.make_node(Path(node_a_dir))
            node_b = DistributedVotingBlockchain(
                node_id="observer-b",
                data_dir=Path(node_b_dir),
                validators=validators,
            )
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node_a, committee, ["alice"])
            block = node_a.mine_block()

            self.assertTrue(node_b.accept_block(block))
            self.assertEqual(len(node_b.chain), 2)

            tampered_block = dict(block)
            tampered_block["transactions"] = [dict(tx) for tx in block["transactions"]]
            tampered_block["transactions"][0] = dict(tampered_block["transactions"][0])
            tampered_block["transactions"][0]["payload"] = dict(tampered_block["transactions"][0]["payload"])
            tampered_block["transactions"][0]["payload"]["title"] = "Tampered"

            with self.assertRaises(ValueError):
                DistributedVotingBlockchain(
                    node_id="observer-c",
                    data_dir=Path(tempfile.mkdtemp()),
                    validators=validators,
                ).accept_block(tampered_block)

    def test_wrong_validator_signature_is_rejected(self):
        """A block signed by an unknown validator must not enter the chain."""
        with tempfile.TemporaryDirectory() as tmp:
            node, _, validators = self.make_node(Path(tmp), node_id="validator-a")
            attacker_keys = generate_validator_keypair()
            unsigned_block = {
                "index": 2,
                "timestamp": "2026-06-29T00:00:00+00:00",
                "previous_hash": node.chain[-1]["block_hash"],
                "validator_id": "attacker",
                "transactions": [],
            }
            attacker_block = sign_block(unsigned_block, attacker_keys["private_key"])
            observer = DistributedVotingBlockchain(
                node_id="observer",
                data_dir=Path(tempfile.mkdtemp()),
                validators=validators,
            )

            with self.assertRaises(ValueError):
                observer.accept_block(attacker_block)

    def test_mempool_accepts_valid_transactions_and_clears_after_mining(self):
        """
        Valid pending transactions enter the mempool and leave it after mining.

        This confirms that blocks, not direct in-memory mutation, become the
        durable source of truth.
        """
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node, committee, ["alice"])

            self.assertEqual(len(node.mempool), 2)
            node.mine_block()

            self.assertEqual(node.mempool, [])
            self.assertEqual(len(node.chain), 2)
            self.assertEqual(len(node.list_elections()), 1)

    def test_transaction_status_reports_mempool_and_committed_block(self):
        """
        Voter UI can show whether a transaction is pending or already on-chain.

        A submitted transaction starts in the mempool. After mining, the same
        tx_id resolves to the block metadata that committed it.
        """
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            node.submit_transaction("create_election", future_election_payload(committee))
            tx_id = node.mempool[0]["tx_id"]

            pending = node.transaction_status(tx_id)
            self.assertEqual(pending["status"], "mempool")
            self.assertIsNone(pending["block"])

            node.mine_block()
            committed = node.transaction_status(tx_id)

            self.assertEqual(committed["status"], "committed")
            self.assertEqual(committed["block"]["index"], 2)
            self.assertEqual(committed["block"]["validator_id"], "validator-a")

    def test_demo_create_election_generates_committee_and_candidate_indices(self):
        """
        The presentation helper creates a real create_election transaction.

        This is what the dashboard uses: the user enters candidate names, the
        helper assigns candidate indices, creates Petlib committee public data,
        stores private demo shares locally, and mines the block when requested.
        """
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))

            result = node.create_demo_election(
                title="Presentation Vote",
                candidates=["Alice", "Bob", "Charlie"],
                duration_minutes=60,
                member_count=5,
                threshold=3,
                mine=True,
            )

            self.assertEqual(
                result["candidates"],
                [
                    {"candidate_index": 0, "candidate": "Alice"},
                    {"candidate_index": 1, "candidate": "Bob"},
                    {"candidate_index": 2, "candidate": "Charlie"},
                ],
            )
            self.assertEqual(node.mempool, [])
            self.assertEqual(len(node.chain), 2)
            self.assertTrue(Path(result["private_committee_state_path"]).exists())
            election = node.get_election(result["election_id"])
            self.assertEqual(election.options, ["Alice", "Bob", "Charlie"])
            self.assertEqual(election.committee["threshold"], 3)

    def test_fastapi_v2_dashboard_helper_modules_work_together(self):
        """
        FastAPI, v2 node setup, dashboard helper and chain state work together.

        This is a small integration smoke test for the exact boundary the GUI
        uses: `/api/v2/demo/create-election` creates committee crypto material,
        submits a chain transaction, mines a block and makes the election visible
        through the public v2 endpoints.
        """
        with tempfile.TemporaryDirectory() as tmp:
            from fastapi import FastAPI

            node, _, _ = self.make_node(Path(tmp))
            app = FastAPI()
            register_v2_routes(app, node=node)
            client = TestClient(app)

            response = client.post(
                "/api/v2/demo/create-election",
                json={
                    "title": "GUI Integration Election",
                    "candidates": ["Alice", "Bob", "Charlie"],
                    "duration_minutes": 60,
                    "member_count": 5,
                    "threshold": 3,
                    "mine": True,
                },
            )

            self.assertEqual(response.status_code, 201)
            created = response.json()
            election_id = created["election_id"]
            self.assertEqual(created["candidates"][1], {"candidate_index": 1, "candidate": "Bob"})

            info = client.get("/api/v2/node/info").json()
            elections = client.get("/api/v2/elections").json()
            verify = client.get(f"/api/v2/elections/{election_id}/verify").json()

            self.assertEqual(info["chain_length"], 2)
            self.assertEqual(elections["elections"][0]["election_id"], election_id)
            self.assertTrue(verify["valid"])

    def test_fastapi_voter_client_helpers_register_and_cast_encrypted_vote(self):
        """
        The separated Voter Client API can register and cast an encrypted vote.

        This checks the boundary intended for `/voter`: a voter-facing client
        sends only election id, local demo secret and candidate index; the node
        derives commitment/nullifier, encrypts the ballot and submits the real
        chain transaction.
        """
        with tempfile.TemporaryDirectory() as tmp:
            from fastapi import FastAPI

            node, _, _ = self.make_node(Path(tmp))
            app = FastAPI()
            register_v2_routes(app, node=node)
            client = TestClient(app)
            created = client.post(
                "/api/v2/demo/create-election",
                json={
                    "title": "Voter Client Election",
                    "candidates": ["Alice", "Bob", "Charlie"],
                    "duration_minutes": 60,
                    "member_count": 5,
                    "threshold": 3,
                    "mine": True,
                },
            ).json()
            election_id = created["election_id"]

            register_response = client.post(
                "/api/v2/demo/register-voter",
                json={
                    "election_id": election_id,
                    "voter_secret": "alice-demo-secret",
                    "mine": True,
                },
            )
            vote_response = client.post(
                "/api/v2/demo/cast-vote",
                json={
                    "election_id": election_id,
                    "voter_secret": "alice-demo-secret",
                    "candidate_index": 1,
                    "mine": True,
                },
            )

            self.assertEqual(register_response.status_code, 201)
            self.assertEqual(vote_response.status_code, 201)
            vote_payload = vote_response.json()
            self.assertEqual(vote_payload["candidate"], "Bob")
            self.assertEqual(vote_payload["one_hot_preview"], [0, 1, 0])
            self.assertIn("encrypted_ballot", vote_payload)
            election = client.get(f"/api/v2/elections/{election_id}").json()
            self.assertEqual(election["encrypted_votes"], 1)

    def test_fastapi_committee_preview_reports_threshold_failure(self):
        """
        Committee preview explains when too few member shares are selected.

        This is the feedback the Committee Client should show before it tries
        to publish a tally transaction.
        """
        with tempfile.TemporaryDirectory() as tmp:
            from fastapi import FastAPI

            node, _, _ = self.make_node(Path(tmp))
            app = FastAPI()
            register_v2_routes(app, node=node)
            client = TestClient(app)
            created = client.post(
                "/api/v2/demo/create-election",
                json={
                    "title": "Committee Preview Election",
                    "candidates": ["Alice", "Bob", "Charlie"],
                    "duration_minutes": 60,
                    "member_count": 5,
                    "threshold": 3,
                    "mine": True,
                },
            ).json()

            preview = client.post(
                "/api/v2/demo/committee/preview",
                json={
                    "election_id": created["election_id"],
                    "participating_member_ids": [1, 2],
                },
            ).json()

            self.assertFalse(preview["threshold_met"])
            self.assertEqual(preview["committee_threshold"], 3)
            self.assertEqual(preview["selected_member_ids"], [1, 2])

    def test_fastapi_committee_publishes_threshold_tally_and_verify_passes(self):
        """
        Committee publish endpoint closes the visible encrypted voting cycle.

        The API creates an election, registers voters, casts encrypted votes,
        finalizes the election, publishes a 3-of-5 tally, and the public verify
        endpoint accepts the published result.
        """
        with tempfile.TemporaryDirectory() as tmp:
            from fastapi import FastAPI

            node, _, _ = self.make_node(Path(tmp))
            app = FastAPI()
            register_v2_routes(app, node=node)
            client = TestClient(app)
            created = client.post(
                "/api/v2/demo/create-election",
                json={
                    "title": "Committee Publish Election",
                    "candidates": ["Alice", "Bob", "Charlie"],
                    "duration_minutes": 60,
                    "member_count": 5,
                    "threshold": 3,
                    "mine": True,
                },
            ).json()
            election_id = created["election_id"]

            for voter, candidate_index in [("alice", 0), ("bob", 1), ("charlie", 1)]:
                client.post(
                    "/api/v2/demo/register-voter",
                    json={
                        "election_id": election_id,
                        "voter_secret": voter,
                        "mine": True,
                    },
                )
                client.post(
                    "/api/v2/demo/cast-vote",
                    json={
                        "election_id": election_id,
                        "voter_secret": voter,
                        "candidate_index": candidate_index,
                        "mine": True,
                    },
                )

            client.post(
                "/api/v2/transactions",
                json={
                    "type": "finalize_election",
                    "payload": {"election_id": election_id},
                },
            )
            client.post("/api/v2/blocks/mine")

            publish_response = client.post(
                "/api/v2/demo/committee/publish-tally",
                json={
                    "election_id": election_id,
                    "participating_member_ids": [1, 3, 5],
                    "mine": True,
                },
            )
            verify = client.get(f"/api/v2/elections/{election_id}/verify").json()

            self.assertEqual(publish_response.status_code, 201)
            published = publish_response.json()
            self.assertEqual(published["plaintext_tally"], [1, 2, 0])
            self.assertTrue(verify["valid"])
            self.assertTrue(verify["checks"]["published_result_valid"])
            self.assertTrue(verify["checks"]["published_encrypted_tally_matches_ballots"])
            self.assertTrue(verify["checks"]["partial_decryption_proofs_valid"])
            self.assertTrue(verify["checks"]["plaintext_tally_matches_decryption"])
            self.assertEqual(verify["published_details"]["published_plaintext_tally"], [1, 2, 0])

    def test_double_nullifier_is_rejected_before_block_is_mined(self):
        """
        A node rejects a second pending vote with the same nullifier.

        The check uses committed chain state plus mempool state, so double voting
        is caught even before a validator creates the next block.
        """
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node, committee, ["alice"])
            first_vote = encrypted_vote_payload(committee, "election-1", "alice", 0, 3)
            second_vote = encrypted_vote_payload(committee, "election-1", "alice", 1, 3)
            second_vote["nullifier_hash"] = first_vote["nullifier_hash"]

            node.submit_transaction("cast_encrypted_vote", first_vote)

            with self.assertRaises(ValueError):
                node.submit_transaction("cast_encrypted_vote", second_vote)

    def test_wrong_candidate_count_is_rejected(self):
        """Encrypted ballots must match the election option count."""
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node, committee, ["alice"])
            invalid_vote = encrypted_vote_payload(committee, "election-1", "alice", 0, 2)

            with self.assertRaises(ValueError):
                node.submit_transaction("cast_encrypted_vote", invalid_vote)

    def test_full_petlib_tally_publication_verifies_from_chain_data(self):
        """
        Encrypted votes can be aggregated and publicly verified after publication.

        This exercises the planned Level-1/Level-3 bridge: encrypted ballots live
        in chain transactions, while Petlib verifies the published threshold
        decryption result without private committee shares.
        """
        with tempfile.TemporaryDirectory() as tmp:
            node, _, _ = self.make_node(Path(tmp))
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node, committee, ["alice", "bob"])
            vote_payloads = [
                encrypted_vote_payload(committee, "election-1", "alice", 0, 3),
                encrypted_vote_payload(committee, "election-1", "bob", 1, 3),
            ]
            for payload in vote_payloads:
                node.submit_transaction("cast_encrypted_vote", payload)
            node.mine_block()

            node.submit_transaction("finalize_election", {"election_id": "election-1"})
            node.mine_block()

            # Use the actual chain ballot payloads for the aggregate, not fresh
            # ciphertexts. Fresh encryption would be mathematically different.
            public_ballots = [
                node.get_election("election-1").encrypted_ballots[index]
                for index in range(2)
            ]
            from crypto_petlib_elgamal_tally import EncryptedBallot

            encrypted_ballots = [
                EncryptedBallot.from_chain_payload(committee.public_key, payload)
                for payload in public_ballots
            ]
            encrypted_tally = aggregate_encrypted_ballots(committee.public_key, encrypted_ballots)
            published_result = publish_threshold_tally_result(
                committee=committee,
                encrypted_tally=encrypted_tally,
                participating_member_ids=[1, 2],
                max_plaintext=2,
            )
            node.submit_transaction(
                "publish_tally_result",
                {
                    "election_id": "election-1",
                    "encrypted_tally": encrypted_tally.to_chain_payload(),
                    "published_result": published_result.to_payload(),
                },
            )
            node.mine_block()

            verification = node.verify_election("election-1")

            self.assertTrue(verification["valid"])
            self.assertEqual(node.published_result("election-1")["published_result"]["plaintext_tally"], [1, 1, 0])
            self.assertIsNotNone(node.encrypted_tally("election-1"))

    def test_longer_valid_chain_replaces_observer_chain(self):
        """
        A node can adopt a longer valid chain from another node.

        This is the intentionally simple v1 sync/fork rule. It demonstrates
        distributed replication without pretending to be a full BFT protocol.
        """
        with tempfile.TemporaryDirectory() as node_a_dir, tempfile.TemporaryDirectory() as node_b_dir:
            node_a, _, validators = self.make_node(Path(node_a_dir))
            node_b = DistributedVotingBlockchain(
                node_id="observer-b",
                data_dir=Path(node_b_dir),
                validators=validators,
            )
            committee = generate_committee_key_shares(member_count=3, threshold=2)
            self.add_basic_election_and_registration(node_a, committee, ["alice"])
            node_a.mine_block()

            adopted = node_b.replace_chain_if_valid(node_a.chain)

            self.assertTrue(adopted)
            self.assertEqual(node_b.chain[-1]["block_hash"], node_a.chain[-1]["block_hash"])


if __name__ == "__main__":
    unittest.main()
