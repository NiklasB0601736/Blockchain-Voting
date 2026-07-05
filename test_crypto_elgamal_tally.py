import unittest

from crypto_elgamal_tally import (
    aggregate_encrypted_ballots,
    compute_decryption_factor,
    create_decryption_proof,
    demo_candidate_tally,
    demo_threshold_candidate_tally,
    demo_threshold_success_and_failure,
    discrete_log_small,
    encrypt_candidate_vote,
    encrypt_message,
    generate_committee_key_shares,
    generate_keypair,
    publish_tally_result,
    publish_threshold_tally_result,
    remove_decryption_factor,
    verify_threshold_tally_result,
    verify_decryption_proof,
    verify_encrypted_tally,
    verify_published_tally_result,
)


class CryptoElGamalTallyTest(unittest.TestCase):
    def test_encryption_is_probabilistic(self):
        private_key = generate_keypair(bits=128)
        public_key = private_key.public_key

        first = encrypt_message(public_key, 1)
        second = encrypt_message(public_key, 1)

        self.assertNotEqual(first, second)

        first_factor = compute_decryption_factor(private_key, first)
        second_factor = compute_decryption_factor(private_key, second)
        self.assertEqual(
            discrete_log_small(public_key, remove_decryption_factor(public_key, first, first_factor), 5),
            1,
        )
        self.assertEqual(
            discrete_log_small(public_key, remove_decryption_factor(public_key, second, second_factor), 5),
            1,
        )

    def test_homomorphic_candidate_tally_with_public_decryption_verification(self):
        private_key = generate_keypair(bits=128)
        public_key = private_key.public_key
        selected_candidates = [0, 1, 1, 3, 2, 1, 0]
        ballots = [
            encrypt_candidate_vote(public_key, candidate_index, candidate_count=4)
            for candidate_index in selected_candidates
        ]

        encrypted_tally = aggregate_encrypted_ballots(public_key, ballots)
        published_result = publish_tally_result(private_key, encrypted_tally, max_plaintext=len(ballots))

        self.assertTrue(verify_encrypted_tally(public_key, ballots, encrypted_tally))
        self.assertEqual(published_result.plaintext_tally, [2, 3, 1, 1])
        self.assertTrue(verify_published_tally_result(public_key, encrypted_tally, published_result))

    def test_decryption_proof_rejects_tampering(self):
        private_key = generate_keypair(bits=128)
        public_key = private_key.public_key
        ciphertext = encrypt_message(public_key, 1)
        factor = compute_decryption_factor(private_key, ciphertext)
        proof = create_decryption_proof(private_key, ciphertext, factor)

        self.assertTrue(verify_decryption_proof(public_key, ciphertext, factor, proof))
        self.assertFalse(verify_decryption_proof(public_key, ciphertext, (factor * 2) % public_key.p, proof))

    def test_published_result_rejects_wrong_plaintext(self):
        private_key = generate_keypair(bits=128)
        public_key = private_key.public_key
        ballots = [
            encrypt_candidate_vote(public_key, candidate_index, candidate_count=3)
            for candidate_index in [0, 1, 1, 2, 1]
        ]

        encrypted_tally = aggregate_encrypted_ballots(public_key, ballots)
        published_result = publish_tally_result(private_key, encrypted_tally, max_plaintext=len(ballots))
        tampered_result = type(published_result)(
            plaintext_tally=[5, 0, 0],
            decryption_shares=published_result.decryption_shares,
        )

        self.assertTrue(verify_published_tally_result(public_key, encrypted_tally, published_result))
        self.assertFalse(verify_published_tally_result(public_key, encrypted_tally, tampered_result))

    def test_demo_returns_publicly_verifiable_result(self):
        demo = demo_candidate_tally(
            candidate_names=["Alice", "Bob", "Charlie"],
            selected_candidate_indices=[0, 1, 1, 2, 1],
        )

        self.assertTrue(demo["encrypted_tally_verified"])
        self.assertTrue(demo["decryption_verified"])
        self.assertEqual(demo["published_result"]["plaintext_tally"], [1, 3, 1])

    def test_threshold_committee_tally_accepts_three_of_five(self):
        committee = generate_committee_key_shares(member_count=5, threshold=3, bits=128)
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
        committee = generate_committee_key_shares(member_count=5, threshold=3, bits=128)
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

    def test_threshold_committee_accepts_different_valid_majority(self):
        committee = generate_committee_key_shares(member_count=5, threshold=3, bits=128)
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
        committee = generate_committee_key_shares(member_count=5, threshold=3, bits=128)
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

    def test_threshold_demo_uses_configurable_committee(self):
        demo = demo_threshold_candidate_tally(
            candidate_names=["Alice", "Bob", "Charlie"],
            selected_candidate_indices=[0, 1, 1, 2, 1],
            member_count=5,
            threshold=3,
            participating_member_ids=[1, 4, 5],
        )

        self.assertTrue(demo["encrypted_tally_verified"])
        self.assertTrue(demo["threshold_decryption_verified"])
        self.assertEqual(demo["published_result"]["plaintext_tally"], [1, 3, 1])

    def test_threshold_success_and_failure_demo_reports_both_cases(self):
        demo = demo_threshold_success_and_failure(
            candidate_names=["Alice", "Bob", "Charlie"],
            selected_candidate_indices=[0, 1, 1, 2, 1],
            member_count=5,
            threshold=3,
            successful_member_ids=[1, 3, 5],
            insufficient_member_ids=[1, 3],
        )

        self.assertTrue(demo["chain_state"]["encrypted_tally_verified"])
        self.assertTrue(demo["success_case"]["threshold_met"])
        self.assertTrue(demo["success_case"]["threshold_decryption_verified"])
        self.assertEqual(demo["success_case"]["published_result"]["plaintext_tally"], [1, 3, 1])
        self.assertFalse(demo["failure_case"]["threshold_met"])
        self.assertIsNone(demo["failure_case"]["published_result"])
        self.assertEqual(demo["failure_case"]["valid_partial_decryptions"], 2)
        self.assertEqual(demo["failure_case"]["required_partial_decryptions"], 3)


if __name__ == "__main__":
    unittest.main()
