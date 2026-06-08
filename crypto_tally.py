"""
Small Paillier tally prototype for encrypted candidate votes.

This module is intentionally not wired into blockchainV1.py yet. It exists so
the homomorphic tally idea can be inspected and tested in isolation.

Prototype scope:
- additively homomorphic encryption
- probabilistic encryption, so Enc(1) differs per encryption
- one-hot candidate ballots, e.g. [0, 1, 0]
- public aggregation check by recomputing encrypted totals
- private decryption of aggregate totals for manual verification

Not implemented here:
- threshold decryption
- zero-knowledge proof that a ballot is valid
- proof that a published plaintext tally matches an encrypted tally
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Sequence


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int
    g: int

    @property
    def n_squared(self) -> int:
        return self.n * self.n


@dataclass(frozen=True)
class PaillierPrivateKey:
    public_key: PaillierPublicKey
    lambda_value: int
    mu: int


@dataclass(frozen=True)
class EncryptedBallot:
    """One encrypted one-hot vote vector."""

    candidate_count: int
    ciphertexts: List[int]

    def to_chain_payload(self) -> dict:
        return {
            "candidate_count": self.candidate_count,
            "ciphertexts": [str(ciphertext) for ciphertext in self.ciphertexts],
        }

    @classmethod
    def from_chain_payload(cls, payload: dict) -> "EncryptedBallot":
        return cls(
            candidate_count=int(payload["candidate_count"]),
            ciphertexts=[int(ciphertext) for ciphertext in payload["ciphertexts"]],
        )


@dataclass(frozen=True)
class EncryptedTally:
    """Encrypted per-candidate vote totals."""

    candidate_count: int
    ciphertexts: List[int]

    def to_chain_payload(self) -> dict:
        return {
            "candidate_count": self.candidate_count,
            "ciphertexts": [str(ciphertext) for ciphertext in self.ciphertexts],
        }


def generate_keypair(bits: int = 512) -> PaillierPrivateKey:
    """Generate a Paillier keypair.

    Use larger keys for anything beyond this prototype. 512 bits keeps local
    experiments fast; real systems should use established audited libraries and
    modern security parameters.
    """

    if bits < 128:
        raise ValueError("bits must be at least 128 for this prototype")

    prime_bits = bits // 2
    while True:
        p = _generate_prime(prime_bits)
        q = _generate_prime(prime_bits)
        if p == q:
            continue

        n = p * q
        lambda_value = _lcm(p - 1, q - 1)
        public_key = PaillierPublicKey(n=n, g=n + 1)
        n_squared = public_key.n_squared
        x = pow(public_key.g, lambda_value, n_squared)
        l_value = _l_function(x, n)

        try:
            mu = pow(l_value, -1, n)
        except ValueError:
            continue

        return PaillierPrivateKey(
            public_key=public_key,
            lambda_value=lambda_value,
            mu=mu,
        )


def encrypt(public_key: PaillierPublicKey, plaintext: int) -> int:
    """Encrypt a non-negative integer with fresh randomness."""

    if plaintext < 0:
        raise ValueError("plaintext must be non-negative")
    if plaintext >= public_key.n:
        raise ValueError("plaintext must be smaller than n")

    r = _random_coprime(public_key.n)
    n_squared = public_key.n_squared
    return (pow(public_key.g, plaintext, n_squared) * pow(r, public_key.n, n_squared)) % n_squared


def decrypt(private_key: PaillierPrivateKey, ciphertext: int) -> int:
    """Decrypt a Paillier ciphertext."""

    public_key = private_key.public_key
    x = pow(ciphertext, private_key.lambda_value, public_key.n_squared)
    l_value = _l_function(x, public_key.n)
    return (l_value * private_key.mu) % public_key.n


def add_ciphertexts(public_key: PaillierPublicKey, ciphertexts: Iterable[int]) -> int:
    """Homomorphically add plaintexts by multiplying ciphertexts."""

    result = 1
    for ciphertext in ciphertexts:
        result = (result * ciphertext) % public_key.n_squared
    return result


def encrypt_candidate_vote(
    public_key: PaillierPublicKey,
    candidate_index: int,
    candidate_count: int,
) -> EncryptedBallot:
    """Encrypt one candidate vote as a one-hot vector."""

    plaintext_ballot = one_hot_vote(candidate_index, candidate_count)
    return encrypt_plaintext_ballot(public_key, plaintext_ballot)


def encrypt_plaintext_ballot(public_key: PaillierPublicKey, ballot: Sequence[int]) -> EncryptedBallot:
    """Encrypt a plaintext one-hot ballot.

    This validation is local prototype validation. In the target architecture,
    the chain cannot see plaintext and must verify a zero-knowledge validity
    proof instead.
    """

    validate_one_hot_ballot(ballot)
    return EncryptedBallot(
        candidate_count=len(ballot),
        ciphertexts=[encrypt(public_key, value) for value in ballot],
    )


def one_hot_vote(candidate_index: int, candidate_count: int) -> List[int]:
    if candidate_count < 2:
        raise ValueError("candidate_count must be at least 2")
    if candidate_index < 0 or candidate_index >= candidate_count:
        raise ValueError("candidate_index out of range")

    return [1 if index == candidate_index else 0 for index in range(candidate_count)]


def validate_one_hot_ballot(ballot: Sequence[int]) -> None:
    if len(ballot) < 2:
        raise ValueError("ballot must contain at least 2 candidates")
    if any(value not in (0, 1) for value in ballot):
        raise ValueError("ballot values must be 0 or 1")
    if sum(ballot) != 1:
        raise ValueError("ballot must select exactly one candidate")


def aggregate_encrypted_ballots(
    public_key: PaillierPublicKey,
    ballots: Sequence[EncryptedBallot],
) -> EncryptedTally:
    if not ballots:
        raise ValueError("cannot aggregate empty ballot list")

    candidate_count = ballots[0].candidate_count
    for ballot in ballots:
        if ballot.candidate_count != candidate_count:
            raise ValueError("all ballots must have the same candidate_count")

    totals = []
    for candidate_index in range(candidate_count):
        column = [ballot.ciphertexts[candidate_index] for ballot in ballots]
        totals.append(add_ciphertexts(public_key, column))

    return EncryptedTally(candidate_count=candidate_count, ciphertexts=totals)


def decrypt_tally(private_key: PaillierPrivateKey, encrypted_tally: EncryptedTally) -> List[int]:
    return [decrypt(private_key, ciphertext) for ciphertext in encrypted_tally.ciphertexts]


def verify_encrypted_tally(
    public_key: PaillierPublicKey,
    ballots: Sequence[EncryptedBallot],
    published_tally: EncryptedTally,
) -> bool:
    """Publicly verify that the encrypted tally matches the public ballots."""

    recomputed_tally = aggregate_encrypted_ballots(public_key, ballots)
    return recomputed_tally == published_tally


def demo_candidate_tally(candidate_names: Sequence[str], selected_candidate_indices: Sequence[int]) -> dict:
    """Run a small end-to-end encrypted tally demo and return inspectable data."""

    if len(candidate_names) < 2:
        raise ValueError("at least 2 candidates required")

    private_key = generate_keypair(bits=512)
    public_key = private_key.public_key
    ballots = [
        encrypt_candidate_vote(public_key, candidate_index, len(candidate_names))
        for candidate_index in selected_candidate_indices
    ]
    encrypted_tally = aggregate_encrypted_ballots(public_key, ballots)
    plaintext_tally = decrypt_tally(private_key, encrypted_tally)

    return {
        "candidate_names": list(candidate_names),
        "public_key_n": str(public_key.n),
        "encrypted_ballots": [ballot.to_chain_payload() for ballot in ballots],
        "encrypted_tally": encrypted_tally.to_chain_payload(),
        "plaintext_tally": dict(zip(candidate_names, plaintext_tally)),
        "encrypted_tally_verified": verify_encrypted_tally(public_key, ballots, encrypted_tally),
    }


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _is_probable_prime(value: int, rounds: int = 32) -> bool:
    if value < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False

    d = value - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(value - 3) + 2
        x = pow(a, d, value)
        if x in (1, value - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False

    return True


def _random_coprime(n: int) -> int:
    while True:
        candidate = secrets.randbelow(n - 1) + 1
        if math.gcd(candidate, n) == 1:
            return candidate


def _l_function(x: int, n: int) -> int:
    return (x - 1) // n


def _lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b)


if __name__ == "__main__":
    demo = demo_candidate_tally(
        candidate_names=["Alice", "Bob", "Charlie", "Diana"],
        selected_candidate_indices=[0, 1, 1, 3, 2, 1, 0],
    )
    print("Encrypted tally verified:", demo["encrypted_tally_verified"])
    print("Plaintext tally:", demo["plaintext_tally"])
    print("First encrypted ballot payload:")
    print(demo["encrypted_ballots"][0])
