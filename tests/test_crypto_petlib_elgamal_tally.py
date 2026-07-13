import unittest

from petlib.bn import Bn

from voting_system.crypto_petlib_elgamal_tally import (
    Ciphertext,
    PetlibPublicKey,
    aggregate_encrypted_ballots,
    compute_partial_decryption_factor,
    encrypt_candidate_vote,
    encrypt_message,
    generate_committee_key_shares,
    generate_keypair,
    publish_threshold_tally_result,
    remove_decryption_factor,
    verify_encrypted_tally,
    verify_partial_decryption_proof,
    verify_threshold_tally_result,
)


class CryptoPetlibElGamalTallyTest(unittest.TestCase):
    """Regression tests for the Petlib-backed threshold EC-ElGamal prototype."""

    def test_encryption_is_probabilistic(self):
        """
        Encrypting the same plaintext twice must not produce the same payload.

        This protects the core privacy property of ElGamal: fresh randomness r
        should hide repeated votes from observers looking at the chain.
        """
        private_key = generate_keypair()
        public_key = private_key.public_key

        first = encrypt_message(public_key, 1)
        second = encrypt_message(public_key, 1)

        self.assertNotEqual(first.to_payload(), second.to_payload())

    def test_threshold_committee_tally_accepts_three_of_five(self):
        """
        A valid 3-of-5 committee majority can decrypt the aggregate tally.

        The test mirrors the intended election flow: voters publish encrypted
        one-hot ballots, the system aggregates them homomorphically, and three
        committee members publish enough partial decryptions to reveal only the
        final candidate counts.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        ballots = [
            encrypt_candidate_vote(committee.public_key, candidate_index, candidate_count=4)
            for candidate_index in [0, 1, 1, 3, 2, 1, 0]
        ]
        encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)

        published_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=encrypted_tally,
            participating_member_ids=[1, 3, 5],
            max_plaintext=len(ballots),
        )

        self.assertTrue(verify_encrypted_tally(committee.public_key, ballots, encrypted_tally))
        self.assertEqual(published_result.plaintext_tally, [2, 3, 1, 1])
        self.assertTrue(
            verify_threshold_tally_result(
                committee.public_key,
                committee.public_shares,
                committee.threshold,
                encrypted_tally,
                published_result,
            )
        )

    def test_threshold_committee_rejects_too_few_members(self):
        """
        Fewer than threshold committee members must not decrypt the tally.

        The encrypted chain state can still exist, but the plaintext result is
        unavailable until enough valid committee shares participate.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        ballots = [
            encrypt_candidate_vote(committee.public_key, candidate_index, candidate_count=3)
            for candidate_index in [0, 1, 1, 2, 1]
        ]
        encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)

        with self.assertRaises(ValueError):
            publish_threshold_tally_result(
                committee=committee,
                encrypted_tally=encrypted_tally,
                participating_member_ids=[1, 2],
                max_plaintext=len(ballots),
            )

    def test_threshold_committee_accepts_different_valid_majorities(self):
        """
        Any valid threshold subset should recover the same plaintext tally.

        This verifies the Shamir/Lagrange reconstruction behavior: the result
        must depend on the encrypted tally and the shared secret, not on the
        particular committee majority selected.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        ballots = [
            encrypt_candidate_vote(committee.public_key, candidate_index, candidate_count=3)
            for candidate_index in [0, 1, 1, 2, 1]
        ]
        encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)

        first_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=encrypted_tally,
            participating_member_ids=[1, 2, 3],
            max_plaintext=len(ballots),
        )
        second_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=encrypted_tally,
            participating_member_ids=[2, 4, 5],
            max_plaintext=len(ballots),
        )

        self.assertEqual(first_result.plaintext_tally, [1, 3, 1])
        self.assertEqual(second_result.plaintext_tally, [1, 3, 1])
        self.assertTrue(
            verify_threshold_tally_result(
                committee.public_key,
                committee.public_shares,
                committee.threshold,
                encrypted_tally,
                second_result,
            )
        )

    def test_threshold_verification_rejects_tampered_plaintext(self):
        """
        Public verification rejects a changed plaintext result.

        An attacker cannot keep the same partial decryptions and simply publish
        a nicer-looking final tally, because verification maps the claimed count
        back to count * G and compares it with the decrypted tally point.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        ballots = [
            encrypt_candidate_vote(committee.public_key, candidate_index, candidate_count=3)
            for candidate_index in [0, 1, 1, 2, 1]
        ]
        encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)
        published_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=encrypted_tally,
            participating_member_ids=[1, 3, 5],
            max_plaintext=len(ballots),
        )
        tampered_result = type(published_result)(
            plaintext_tally=[5, 0, 0],
            partial_decryption_shares=published_result.partial_decryption_shares,
        )

        self.assertFalse(
            verify_threshold_tally_result(
                committee.public_key,
                committee.public_shares,
                committee.threshold,
                encrypted_tally,
                tampered_result,
            )
        )

    def test_partial_decryption_proof_rejects_tampering(self):
        """
        Public proof checks reject altered decryption factors and altered proofs.

        The Chaum-Pedersen proof binds one member's public share, the tally
        ciphertext and the partial decryption factor together. Changing either
        the factor or proof challenge should break verification.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        ciphertext = encrypt_message(committee.public_key, 1)
        member = committee.member_shares[0]
        factor = compute_partial_decryption_factor(member, ciphertext)

        # The proof is generated through the normal publication path so the
        # test exercises the same code used by the committee tally flow.
        published_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=type("OneCiphertextTally", (), {"candidate_count": 1, "ciphertexts": [ciphertext]})(),
            participating_member_ids=[1, 2, 3],
            max_plaintext=1,
        )
        proof = published_result.partial_decryption_shares[0].proof

        self.assertTrue(
            verify_partial_decryption_proof(
                committee.public_key,
                member.public_share,
                ciphertext,
                factor,
                proof,
            )
        )
        self.assertFalse(
            verify_partial_decryption_proof(
                committee.public_key,
                member.public_share,
                ciphertext,
                factor + committee.public_key.generator,
                proof,
            )
        )
        tampered_proof = type(proof)(
            t1=proof.t1,
            t2=proof.t2,
            challenge=(proof.challenge + Bn(1)) % committee.public_key.order,
            response=proof.response,
        )
        self.assertFalse(
            verify_partial_decryption_proof(
                committee.public_key,
                member.public_share,
                ciphertext,
                factor,
                tampered_proof,
            )
        )

    def test_payload_export_import_roundtrips_points(self):
        """
        Public keys and ciphertexts survive chain/API style serialization.

        This matters because the later blockchain integration will not store
        live Petlib objects; it will store hex payloads that must reconstruct to
        the same EC points for verification.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        public_payload = committee.public_key.to_payload()
        restored_public_key = PetlibPublicKey.from_payload(public_payload)
        ballot = encrypt_candidate_vote(committee.public_key, candidate_index=1, candidate_count=3)
        ciphertext_payload = ballot.ciphertexts[1].to_payload()
        restored_ciphertext = Ciphertext.from_payload(
            committee.public_key.group,
            ciphertext_payload,
        )

        self.assertEqual(restored_public_key.to_payload(), public_payload)
        self.assertEqual(restored_ciphertext.to_payload(), ciphertext_payload)

    def test_public_shares_match_private_shares_in_test_context(self):
        """
        Test-only sanity check for generated Shamir member shares.

        In production, observers would not know `member.share`. Here we keep it
        in memory to confirm that public_share really equals share * G.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)

        for member in committee.member_shares:
            self.assertEqual(member.share * committee.public_key.generator, member.public_share)

    def test_decryption_verification_does_not_need_private_shares(self):
        """
        Verification uses only public committee data.

        This is the property users care about after publication: anyone who can
        read the encrypted tally, public shares and proofs can check the result
        without access to private committee shares.
        """
        committee = generate_committee_key_shares(member_count=5, threshold=3)
        ballots = [
            encrypt_candidate_vote(committee.public_key, candidate_index, candidate_count=3)
            for candidate_index in [0, 1, 2]
        ]
        encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)
        published_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=encrypted_tally,
            participating_member_ids=[1, 3, 5],
            max_plaintext=len(ballots),
        )

        public_shares_only = {
            member_id: public_share
            for member_id, public_share in committee.public_shares.items()
        }

        self.assertTrue(
            verify_threshold_tally_result(
                committee.public_key,
                public_shares_only,
                committee.threshold,
                encrypted_tally,
                published_result,
            )
        )

    def test_plaintext_point_matches_tally_value_after_threshold_decryption(self):
        """
        Rebuild the threshold decryption factor manually inside the test.

        This repeats the Lagrange combination in test code to make the expected
        point explicit: after removing the combined factor, candidate 0 should
        decrypt to 2 * G because two voters selected candidate 0.
        """
        committee = generate_committee_key_shares(member_count=3, threshold=2)
        ballots = [
            encrypt_candidate_vote(committee.public_key, candidate_index, candidate_count=2)
            for candidate_index in [0, 0, 1]
        ]
        encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)
        published_result = publish_threshold_tally_result(
            committee=committee,
            encrypted_tally=encrypted_tally,
            participating_member_ids=[1, 2],
            max_plaintext=len(ballots),
        )
        first_candidate_shares = [
            share
            for share in published_result.partial_decryption_shares
            if share.candidate_index == 0
        ]
        factor = committee.public_key.group.infinite()
        member_ids = [share.member_id for share in first_candidate_shares]
        order = committee.public_key.order
        for share in first_candidate_shares:
            # Compute the same Lagrange coefficient used by Shamir recovery:
            # each partial decryption contributes lambda_i * (share_i * A).
            numerator = Bn(1)
            denominator = Bn(1)
            for other_id in member_ids:
                if other_id == share.member_id:
                    continue
                numerator = (numerator * Bn(-other_id)) % order
                denominator = (denominator * Bn(share.member_id - other_id)) % order
            coefficient = (numerator * denominator.mod_inverse(order)) % order
            factor = factor + (coefficient * share.decryption_factor)

        plaintext_point = remove_decryption_factor(encrypted_tally.ciphertexts[0], factor)

        self.assertEqual(plaintext_point, Bn(2) * committee.public_key.generator)


if __name__ == "__main__":
    unittest.main()
