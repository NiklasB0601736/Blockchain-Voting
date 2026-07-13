import test from "node:test";
import assert from "node:assert/strict";

import {
    createEncryptedVotePayload,
    createThresholdTallyPayload,
    deriveVoterCredentials,
    generateCommittee,
    validateCommitteeShare,
} from "../web/src/voting_crypto.js";

function electionFixture() {
    const electionId = "browser-election";
    const committee = generateCommittee(electionId, 5, 3);
    return {
        committee,
        election: {
            election_id: electionId,
            options: ["Alice", "Bob", "Charlie"],
            committee: committee.public_payload,
        },
    };
}

test("browser encryption is probabilistic and sends no clear candidate", () => {
    const { election } = electionFixture();
    const first = createEncryptedVotePayload(election, "alice secret", 1);
    const second = createEncryptedVotePayload(election, "alice secret", 1);
    assert.notDeepEqual(first.encrypted_ballot, second.encrypted_ballot);
    assert.equal("candidate_index" in first, false);
    assert.equal(JSON.stringify(first).includes("alice secret"), false);
});

test("nullifier is deterministic and bound to the public commitment", () => {
    const first = deriveVoterCredentials("election-a", "alice secret");
    const second = deriveVoterCredentials("election-a", "alice secret");
    const otherElection = deriveVoterCredentials("election-b", "alice secret");
    assert.deepEqual(first, second);
    assert.notEqual(first.nullifier_hash, otherElection.nullifier_hash);
});

test("separate committee files need a threshold and recover the tally", () => {
    const { election, committee } = electionFixture();
    const ballots = [
        createEncryptedVotePayload(election, "alice", 0).encrypted_ballot,
        createEncryptedVotePayload(election, "bob", 1).encrypted_ballot,
        createEncryptedVotePayload(election, "charlie", 1).encrypted_ballot,
    ];
    assert.throws(
        () => createThresholdTallyPayload(election, ballots, committee.member_files.slice(0, 2)),
        /Mindestens 3/,
    );
    const published = createThresholdTallyPayload(
        election,
        ballots,
        [committee.member_files[0], committee.member_files[2], committee.member_files[4]],
    );
    assert.deepEqual(published.published_result.plaintext_tally, [1, 2, 0]);
});

test("tampered private committee files are rejected", () => {
    const { election, committee } = electionFixture();
    const changed = { ...committee.member_files[0], share: "7" };
    assert.throws(() => validateCommitteeShare(election, changed), /passen nicht/);
});
