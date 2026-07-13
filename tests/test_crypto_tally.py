import unittest

from voting_system.crypto_tally import (
    aggregate_encrypted_ballots,
    decrypt,
    decrypt_tally,
    demo_candidate_tally,
    encrypt,
    encrypt_candidate_vote,
    generate_keypair,
    one_hot_vote,
    validate_one_hot_ballot,
    verify_encrypted_tally,
)


class CryptoTallyTest(unittest.TestCase):
    def test_paillier_encryption_is_probabilistic(self):
        private_key = generate_keypair(bits=256)
        public_key = private_key.public_key

        first = encrypt(public_key, 1)
        second = encrypt(public_key, 1)

        self.assertNotEqual(first, second)
        self.assertEqual(decrypt(private_key, first), 1)
        self.assertEqual(decrypt(private_key, second), 1)

    def test_one_hot_vote_for_candidate_index(self):
        self.assertEqual(one_hot_vote(candidate_index=2, candidate_count=4), [0, 0, 1, 0])

    def test_invalid_plaintext_ballots_are_rejected_before_encryption(self):
        with self.assertRaises(ValueError):
            validate_one_hot_ballot([1, 1, 0])

        with self.assertRaises(ValueError):
            validate_one_hot_ballot([2, 0, 0])

        with self.assertRaises(ValueError):
            validate_one_hot_ballot([0, 0, 0])

    def test_encrypted_candidate_tally(self):
        private_key = generate_keypair(bits=256)
        public_key = private_key.public_key
        selected_candidates = [0, 1, 1, 3, 2, 1, 0]

        ballots = [
            encrypt_candidate_vote(public_key, candidate_index, candidate_count=4)
            for candidate_index in selected_candidates
        ]
        encrypted_tally = aggregate_encrypted_ballots(public_key, ballots)
        plaintext_tally = decrypt_tally(private_key, encrypted_tally)

        self.assertEqual(plaintext_tally, [2, 3, 1, 1])
        self.assertTrue(verify_encrypted_tally(public_key, ballots, encrypted_tally))

    def test_demo_returns_inspectable_payloads(self):
        demo = demo_candidate_tally(
            candidate_names=["Alice", "Bob", "Charlie"],
            selected_candidate_indices=[0, 1, 1, 2, 1],
        )

        self.assertTrue(demo["encrypted_tally_verified"])
        self.assertEqual(demo["plaintext_tally"], {"Alice": 1, "Bob": 3, "Charlie": 1})
        self.assertIn("ciphertexts", demo["encrypted_ballots"][0])


if __name__ == "__main__":
    unittest.main()
