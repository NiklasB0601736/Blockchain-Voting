import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from voting_system.distributed_blockchain import DistributedVotingBlockchain, generate_validator_keypair


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BrowserCryptoInteropTest(unittest.TestCase):
    """Verify that Noble browser payloads are accepted and proven by Petlib."""

    def test_browser_ballots_and_threshold_proofs_verify_in_python(self):
        script = r"""
import {generateCommittee, deriveVoterCredentials, createEncryptedVotePayload, createThresholdTallyPayload} from './web/src/voting_crypto.js';
const electionId = 'interop-election';
const setup = generateCommittee(electionId, 5, 3);
const election = {election_id: electionId, title: 'Interop', options: ['Alice', 'Bob', 'Charlie'], committee: setup.public_payload};
const voters = [['alice', 0], ['bob', 1], ['charlie', 1]];
const credentials = voters.map(([secret]) => deriveVoterCredentials(electionId, secret));
const votes = voters.map(([secret, candidate]) => createEncryptedVotePayload(election, secret, candidate));
const tally = createThresholdTallyPayload(election, votes.map(vote => vote.encrypted_ballot), [setup.member_files[0], setup.member_files[2], setup.member_files[4]]);
console.log(JSON.stringify({election, credentials, votes, tally}));
"""
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)

        with tempfile.TemporaryDirectory() as tmp:
            keys = generate_validator_keypair()
            node = DistributedVotingBlockchain(
                "validator-a",
                Path(tmp),
                validators={"validator-a": keys["public_key"]},
                private_key_hex=keys["private_key"],
            )
            election = payload["election"]
            node.submit_transaction("create_election", {
                **election,
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2027-01-01T00:00:00+00:00",
            })
            for credentials in payload["credentials"]:
                node.submit_transaction("register_voter", {
                    "election_id": election["election_id"],
                    "commitment_hash": credentials["commitment_hash"],
                })
            for vote in payload["votes"]:
                node.submit_transaction("cast_encrypted_vote", vote)
            node.mine_block()
            node.submit_transaction("finalize_election", {"election_id": election["election_id"]})
            node.mine_block()
            node.submit_transaction("publish_tally_result", payload["tally"])
            node.mine_block()

            verification = node.verify_election(election["election_id"])
            self.assertTrue(verification["complete"])
            self.assertEqual(
                verification["published_details"]["published_plaintext_tally"],
                [1, 2, 0],
            )


if __name__ == "__main__":
    unittest.main()
