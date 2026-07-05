"""
Exponential ElGamal tally prototype for verifiable encrypted voting.

This is the Level 3 crypto layer prototype. It is intentionally isolated from
blockchainV1.py and the frontend.

Prototype scope:
- encrypted one-hot candidate ballots
- homomorphic tally aggregation
- plaintext tally recovery from encrypted totals
- Chaum-Pedersen proof that a published decryption factor is correct
- public verification that the decrypted result matches the encrypted tally

Not implemented here:
- threshold key generation/decryption
- ZK proof that an encrypted ballot is one-hot without seeing plaintext
- Semaphore/nullifier voter eligibility
- production-grade parameters or audited cryptography
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Sequence


@dataclass(frozen=True)
class ElGamalPublicKey:
    p: int
    q: int
    g: int
    h: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
    public_key: ElGamalPublicKey
    secret: int


@dataclass(frozen=True)
class CommitteeMemberShare:
    member_id: int
    share: int
    public_share: int

    def public_payload(self) -> dict:
        return {"member_id": self.member_id, "public_share": str(self.public_share)}


@dataclass(frozen=True)
class CommitteeKeyShares:
    public_key: ElGamalPublicKey
    threshold: int
    member_count: int
    member_shares: List[CommitteeMemberShare]

    @property
    def public_shares(self) -> dict[int, int]:
        return {member.member_id: member.public_share for member in self.member_shares}

    def public_payload(self) -> dict:
        return {
            "threshold": self.threshold,
            "member_count": self.member_count,
            "public_key": {
                "p": str(self.public_key.p),
                "q": str(self.public_key.q),
                "g": str(self.public_key.g),
                "h": str(self.public_key.h),
            },
            "public_shares": [member.public_payload() for member in self.member_shares],
        }


@dataclass(frozen=True)
class Ciphertext:
    a: int
    b: int

    def to_payload(self) -> dict:
        return {"a": str(self.a), "b": str(self.b)}

    @classmethod
    def from_payload(cls, payload: dict) -> "Ciphertext":
        return cls(a=int(payload["a"]), b=int(payload["b"]))


@dataclass(frozen=True)
class EncryptedBallot:
    candidate_count: int
    ciphertexts: List[Ciphertext]

    def to_chain_payload(self) -> dict:
        return {
            "candidate_count": self.candidate_count,
            "ciphertexts": [ciphertext.to_payload() for ciphertext in self.ciphertexts],
        }


@dataclass(frozen=True)
class EncryptedTally:
    candidate_count: int
    ciphertexts: List[Ciphertext]

    def to_chain_payload(self) -> dict:
        return {
            "candidate_count": self.candidate_count,
            "ciphertexts": [ciphertext.to_payload() for ciphertext in self.ciphertexts],
        }


@dataclass(frozen=True)
class ChaumPedersenProof:
    """Proof that log_g(h) == log_a(decryption_factor)."""

    t1: int
    t2: int
    challenge: int
    response: int

    def to_payload(self) -> dict:
        return {
            "t1": str(self.t1),
            "t2": str(self.t2),
            "challenge": str(self.challenge),
            "response": str(self.response),
        }


@dataclass(frozen=True)
class DecryptionShare:
    candidate_index: int
    decryption_factor: int
    proof: ChaumPedersenProof

    def to_payload(self) -> dict:
        return {
            "candidate_index": self.candidate_index,
            "decryption_factor": str(self.decryption_factor),
            "proof": self.proof.to_payload(),
        }


@dataclass(frozen=True)
class PartialDecryptionShare:
    candidate_index: int
    member_id: int
    decryption_factor: int
    proof: ChaumPedersenProof

    def to_payload(self) -> dict:
        return {
            "candidate_index": self.candidate_index,
            "member_id": self.member_id,
            "decryption_factor": str(self.decryption_factor),
            "proof": self.proof.to_payload(),
        }


@dataclass(frozen=True)
class PublishedTallyResult:
    plaintext_tally: List[int]
    decryption_shares: List[DecryptionShare]

    def to_payload(self) -> dict:
        return {
            "plaintext_tally": self.plaintext_tally,
            "decryption_shares": [share.to_payload() for share in self.decryption_shares],
        }


@dataclass(frozen=True)
class ThresholdPublishedTallyResult:
    plaintext_tally: List[int]
    partial_decryption_shares: List[PartialDecryptionShare]

    def to_payload(self) -> dict:
        return {
            "plaintext_tally": self.plaintext_tally,
            "partial_decryption_shares": [
                share.to_payload() for share in self.partial_decryption_shares
            ],
        }


def generate_keypair(bits: int = 256) -> ElGamalPrivateKey:
    """Generate a safe-prime subgroup keypair for the prototype."""

    if bits < 128:
        raise ValueError("bits must be at least 128 for this prototype")

    p, q = _generate_safe_prime(bits)
    g = _subgroup_generator(p, q)
    secret = secrets.randbelow(q - 1) + 1
    h = pow(g, secret, p)
    return ElGamalPrivateKey(public_key=ElGamalPublicKey(p=p, q=q, g=g, h=h), secret=secret)


def majority_threshold(member_count: int) -> int:
    if member_count < 1:
        raise ValueError("member_count must be at least 1")
    return member_count // 2 + 1


def generate_committee_key_shares(
    member_count: int,
    threshold: int | None = None,
    bits: int = 256,
) -> CommitteeKeyShares:
    """Generate Shamir shares for a threshold ElGamal committee.

    Any `threshold` members can combine their partial decryptions. Fewer than
    `threshold` members are not enough.
    """

    if threshold is None:
        threshold = majority_threshold(member_count)
    if member_count < 1:
        raise ValueError("member_count must be at least 1")
    if threshold < 1 or threshold > member_count:
        raise ValueError("threshold must be between 1 and member_count")

    p, q = _generate_safe_prime(bits)
    g = _subgroup_generator(p, q)
    secret = secrets.randbelow(q - 1) + 1
    coefficients = [secret] + [secrets.randbelow(q) for _ in range(threshold - 1)]
    h = pow(g, secret, p)
    public_key = ElGamalPublicKey(p=p, q=q, g=g, h=h)

    member_shares = []
    for member_id in range(1, member_count + 1):
        share = _evaluate_polynomial(coefficients, member_id, q)
        public_share = pow(g, share, p)
        member_shares.append(
            CommitteeMemberShare(
                member_id=member_id,
                share=share,
                public_share=public_share,
            )
        )

    return CommitteeKeyShares(
        public_key=public_key,
        threshold=threshold,
        member_count=member_count,
        member_shares=member_shares,
    )


def encrypt_message(public_key: ElGamalPublicKey, message: int) -> Ciphertext:
    """Encrypt a small non-negative integer as g^message."""

    if message < 0 or message >= public_key.q:
        raise ValueError("message out of range")

    r = secrets.randbelow(public_key.q - 1) + 1
    a = pow(public_key.g, r, public_key.p)
    encoded_message = pow(public_key.g, message, public_key.p)
    b = (pow(public_key.h, r, public_key.p) * encoded_message) % public_key.p
    return Ciphertext(a=a, b=b)


def multiply_ciphertexts(public_key: ElGamalPublicKey, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
    if not ciphertexts:
        return Ciphertext(a=1, b=1)

    a_product = 1
    b_product = 1
    for ciphertext in ciphertexts:
        a_product = (a_product * ciphertext.a) % public_key.p
        b_product = (b_product * ciphertext.b) % public_key.p
    return Ciphertext(a=a_product, b=b_product)


def encrypt_candidate_vote(
    public_key: ElGamalPublicKey,
    candidate_index: int,
    candidate_count: int,
) -> EncryptedBallot:
    plaintext_ballot = one_hot_vote(candidate_index, candidate_count)
    return encrypt_plaintext_ballot(public_key, plaintext_ballot)


def encrypt_plaintext_ballot(public_key: ElGamalPublicKey, ballot: Sequence[int]) -> EncryptedBallot:
    validate_one_hot_ballot(ballot)
    return EncryptedBallot(
        candidate_count=len(ballot),
        ciphertexts=[encrypt_message(public_key, value) for value in ballot],
    )


def aggregate_encrypted_ballots(
    public_key: ElGamalPublicKey,
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
        totals.append(multiply_ciphertexts(public_key, column))

    return EncryptedTally(candidate_count=candidate_count, ciphertexts=totals)


def publish_tally_result(
    private_key: ElGamalPrivateKey,
    encrypted_tally: EncryptedTally,
    max_plaintext: int,
) -> PublishedTallyResult:
    plaintext_tally = []
    decryption_shares = []

    for candidate_index, ciphertext in enumerate(encrypted_tally.ciphertexts):
        decryption_factor = compute_decryption_factor(private_key, ciphertext)
        decrypted_point = remove_decryption_factor(private_key.public_key, ciphertext, decryption_factor)
        plaintext = discrete_log_small(private_key.public_key, decrypted_point, max_plaintext)
        proof = create_decryption_proof(private_key, ciphertext, decryption_factor)

        plaintext_tally.append(plaintext)
        decryption_shares.append(
            DecryptionShare(
                candidate_index=candidate_index,
                decryption_factor=decryption_factor,
                proof=proof,
            )
        )

    return PublishedTallyResult(plaintext_tally=plaintext_tally, decryption_shares=decryption_shares)


def verify_published_tally_result(
    public_key: ElGamalPublicKey,
    encrypted_tally: EncryptedTally,
    published_result: PublishedTallyResult,
) -> bool:
    if len(published_result.plaintext_tally) != encrypted_tally.candidate_count:
        return False
    if len(published_result.decryption_shares) != encrypted_tally.candidate_count:
        return False

    shares_by_index = {share.candidate_index: share for share in published_result.decryption_shares}
    for candidate_index, plaintext in enumerate(published_result.plaintext_tally):
        share = shares_by_index.get(candidate_index)
        if share is None:
            return False

        ciphertext = encrypted_tally.ciphertexts[candidate_index]
        if not verify_decryption_proof(public_key, ciphertext, share.decryption_factor, share.proof):
            return False

        decrypted_point = remove_decryption_factor(public_key, ciphertext, share.decryption_factor)
        expected_point = pow(public_key.g, plaintext, public_key.p)
        if decrypted_point != expected_point:
            return False

    return True


def publish_threshold_tally_result(
    committee: CommitteeKeyShares,
    encrypted_tally: EncryptedTally,
    participating_member_ids: Sequence[int],
    max_plaintext: int,
) -> ThresholdPublishedTallyResult:
    """Publish a tally using only a threshold subset of committee members."""

    unique_member_ids = list(dict.fromkeys(participating_member_ids))
    if len(unique_member_ids) < committee.threshold:
        raise ValueError("not enough committee members for threshold decryption")

    members_by_id = {member.member_id: member for member in committee.member_shares}
    participants = []
    for member_id in unique_member_ids:
        if member_id not in members_by_id:
            raise ValueError(f"unknown committee member: {member_id}")
        participants.append(members_by_id[member_id])

    plaintext_tally = []
    partial_decryption_shares = []

    for candidate_index, ciphertext in enumerate(encrypted_tally.ciphertexts):
        candidate_shares = []
        for member in participants:
            factor = compute_partial_decryption_factor(committee.public_key, member, ciphertext)
            proof = create_partial_decryption_proof(committee.public_key, member, ciphertext, factor)
            share = PartialDecryptionShare(
                candidate_index=candidate_index,
                member_id=member.member_id,
                decryption_factor=factor,
                proof=proof,
            )
            candidate_shares.append(share)
            partial_decryption_shares.append(share)

        combined_factor = combine_partial_decryption_factors(
            committee.public_key,
            candidate_shares,
            committee.threshold,
        )
        decrypted_point = remove_decryption_factor(committee.public_key, ciphertext, combined_factor)
        plaintext_tally.append(discrete_log_small(committee.public_key, decrypted_point, max_plaintext))

    return ThresholdPublishedTallyResult(
        plaintext_tally=plaintext_tally,
        partial_decryption_shares=partial_decryption_shares,
    )


def verify_threshold_tally_result(
    public_key: ElGamalPublicKey,
    public_shares: dict[int, int],
    threshold: int,
    encrypted_tally: EncryptedTally,
    published_result: ThresholdPublishedTallyResult,
) -> bool:
    if threshold < 1:
        return False
    if len(published_result.plaintext_tally) != encrypted_tally.candidate_count:
        return False

    shares_by_candidate: dict[int, list[PartialDecryptionShare]] = {
        index: [] for index in range(encrypted_tally.candidate_count)
    }
    for share in published_result.partial_decryption_shares:
        if share.candidate_index not in shares_by_candidate:
            return False
        if share.member_id not in public_shares:
            return False
        shares_by_candidate[share.candidate_index].append(share)

    for candidate_index, plaintext in enumerate(published_result.plaintext_tally):
        candidate_shares = _unique_member_shares(shares_by_candidate[candidate_index])
        if len(candidate_shares) < threshold:
            return False

        ciphertext = encrypted_tally.ciphertexts[candidate_index]
        selected_shares = candidate_shares[:threshold]
        for share in selected_shares:
            if not verify_partial_decryption_proof(
                public_key,
                public_shares[share.member_id],
                ciphertext,
                share.decryption_factor,
                share.proof,
            ):
                return False

        combined_factor = combine_partial_decryption_factors(public_key, selected_shares, threshold)
        decrypted_point = remove_decryption_factor(public_key, ciphertext, combined_factor)
        expected_point = pow(public_key.g, plaintext, public_key.p)
        if decrypted_point != expected_point:
            return False

    return True


def verify_encrypted_tally(
    public_key: ElGamalPublicKey,
    ballots: Sequence[EncryptedBallot],
    published_tally: EncryptedTally,
) -> bool:
    return aggregate_encrypted_ballots(public_key, ballots) == published_tally


def compute_decryption_factor(private_key: ElGamalPrivateKey, ciphertext: Ciphertext) -> int:
    return pow(ciphertext.a, private_key.secret, private_key.public_key.p)


def compute_partial_decryption_factor(
    public_key: ElGamalPublicKey,
    member: CommitteeMemberShare,
    ciphertext: Ciphertext,
) -> int:
    return pow(ciphertext.a, member.share, public_key.p)


def combine_partial_decryption_factors(
    public_key: ElGamalPublicKey,
    shares: Sequence[PartialDecryptionShare],
    threshold: int,
) -> int:
    unique_shares = _unique_member_shares(shares)
    if len(unique_shares) < threshold:
        raise ValueError("not enough partial decryption shares")

    selected_shares = unique_shares[:threshold]
    member_ids = [share.member_id for share in selected_shares]
    combined_factor = 1
    for share in selected_shares:
        coefficient = _lagrange_coefficient_at_zero(share.member_id, member_ids, public_key.q)
        combined_factor = (
            combined_factor * pow(share.decryption_factor, coefficient, public_key.p)
        ) % public_key.p
    return combined_factor


def remove_decryption_factor(
    public_key: ElGamalPublicKey,
    ciphertext: Ciphertext,
    decryption_factor: int,
) -> int:
    return (ciphertext.b * pow(decryption_factor, -1, public_key.p)) % public_key.p


def create_decryption_proof(
    private_key: ElGamalPrivateKey,
    ciphertext: Ciphertext,
    decryption_factor: int,
) -> ChaumPedersenProof:
    public_key = private_key.public_key
    return _create_discrete_log_equality_proof(
        public_key=public_key,
        witness=private_key.secret,
        public_element=public_key.h,
        ciphertext= ciphertext,
        decryption_factor=decryption_factor,
    )


def create_partial_decryption_proof(
    public_key: ElGamalPublicKey,
    member: CommitteeMemberShare,
    ciphertext: Ciphertext,
    decryption_factor: int,
) -> ChaumPedersenProof:
    return _create_discrete_log_equality_proof(
        public_key=public_key,
        witness=member.share,
        public_element=member.public_share,
        ciphertext=ciphertext,
        decryption_factor=decryption_factor,
    )


def _create_discrete_log_equality_proof(
    public_key: ElGamalPublicKey,
    witness: int,
    public_element: int,
    ciphertext: Ciphertext,
    decryption_factor: int,
) -> ChaumPedersenProof:
    w = secrets.randbelow(public_key.q - 1) + 1
    t1 = pow(public_key.g, w, public_key.p)
    t2 = pow(ciphertext.a, w, public_key.p)
    challenge = _challenge(public_key, public_element, ciphertext, decryption_factor, t1, t2)
    response = (w + challenge * witness) % public_key.q
    return ChaumPedersenProof(t1=t1, t2=t2, challenge=challenge, response=response)


def verify_decryption_proof(
    public_key: ElGamalPublicKey,
    ciphertext: Ciphertext,
    decryption_factor: int,
    proof: ChaumPedersenProof,
) -> bool:
    return verify_partial_decryption_proof(
        public_key,
        public_key.h,
        ciphertext,
        decryption_factor,
        proof,
    )


def verify_partial_decryption_proof(
    public_key: ElGamalPublicKey,
    public_share: int,
    ciphertext: Ciphertext,
    decryption_factor: int,
    proof: ChaumPedersenProof,
) -> bool:
    expected_challenge = _challenge(
        public_key,
        public_share,
        ciphertext,
        decryption_factor,
        proof.t1,
        proof.t2,
    )
    if proof.challenge != expected_challenge:
        return False

    left_1 = pow(public_key.g, proof.response, public_key.p)
    right_1 = (proof.t1 * pow(public_share, proof.challenge, public_key.p)) % public_key.p
    left_2 = pow(ciphertext.a, proof.response, public_key.p)
    right_2 = (proof.t2 * pow(decryption_factor, proof.challenge, public_key.p)) % public_key.p
    return left_1 == right_1 and left_2 == right_2


def discrete_log_small(public_key: ElGamalPublicKey, point: int, max_plaintext: int) -> int:
    current = 1
    for value in range(max_plaintext + 1):
        if current == point:
            return value
        current = (current * public_key.g) % public_key.p
    raise ValueError("plaintext is outside the configured tally range")


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


def demo_candidate_tally(candidate_names: Sequence[str], selected_candidate_indices: Sequence[int]) -> dict:
    if len(candidate_names) < 2:
        raise ValueError("at least 2 candidates required")

    private_key = generate_keypair(bits=256)
    public_key = private_key.public_key
    ballots = [
        encrypt_candidate_vote(public_key, candidate_index, len(candidate_names))
        for candidate_index in selected_candidate_indices
    ]
    encrypted_tally = aggregate_encrypted_ballots(public_key, ballots)
    published_result = publish_tally_result(
        private_key=private_key,
        encrypted_tally=encrypted_tally,
        max_plaintext=len(ballots),
    )

    return {
        "candidate_names": list(candidate_names),
        "public_key": {
            "p": str(public_key.p),
            "q": str(public_key.q),
            "g": str(public_key.g),
            "h": str(public_key.h),
        },
        "encrypted_ballots": [ballot.to_chain_payload() for ballot in ballots],
        "encrypted_tally": encrypted_tally.to_chain_payload(),
        "published_result": published_result.to_payload(),
        "encrypted_tally_verified": verify_encrypted_tally(public_key, ballots, encrypted_tally),
        "decryption_verified": verify_published_tally_result(public_key, encrypted_tally, published_result),
    }


def demo_threshold_candidate_tally(
    candidate_names: Sequence[str],
    selected_candidate_indices: Sequence[int],
    member_count: int,
    threshold: int | None = None,
    participating_member_ids: Sequence[int] | None = None,
) -> dict:
    if len(candidate_names) < 2:
        raise ValueError("at least 2 candidates required")

    committee = generate_committee_key_shares(
        member_count=member_count,
        threshold=threshold,
        bits=256,
    )
    if participating_member_ids is None:
        participating_member_ids = [member.member_id for member in committee.member_shares[: committee.threshold]]

    ballots = [
        encrypt_candidate_vote(committee.public_key, candidate_index, len(candidate_names))
        for candidate_index in selected_candidate_indices
    ]
    encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)
    published_result = publish_threshold_tally_result(
        committee=committee,
        encrypted_tally=encrypted_tally,
        participating_member_ids=participating_member_ids,
        max_plaintext=len(ballots),
    )

    return {
        "candidate_names": list(candidate_names),
        "committee": committee.public_payload(),
        "participating_member_ids": list(participating_member_ids),
        "encrypted_ballots": [ballot.to_chain_payload() for ballot in ballots],
        "encrypted_tally": encrypted_tally.to_chain_payload(),
        "published_result": published_result.to_payload(),
        "encrypted_tally_verified": verify_encrypted_tally(committee.public_key, ballots, encrypted_tally),
        "threshold_decryption_verified": verify_threshold_tally_result(
            committee.public_key,
            committee.public_shares,
            committee.threshold,
            encrypted_tally,
            published_result,
        ),
    }


def demo_threshold_success_and_failure(
    candidate_names: Sequence[str],
    selected_candidate_indices: Sequence[int],
    member_count: int,
    threshold: int | None = None,
    successful_member_ids: Sequence[int] | None = None,
    insufficient_member_ids: Sequence[int] | None = None,
) -> dict:
    if len(candidate_names) < 2:
        raise ValueError("at least 2 candidates required")

    committee = generate_committee_key_shares(
        member_count=member_count,
        threshold=threshold,
        bits=256,
    )
    if successful_member_ids is None:
        successful_member_ids = [
            member.member_id for member in committee.member_shares[: committee.threshold]
        ]
    if insufficient_member_ids is None:
        insufficient_member_ids = successful_member_ids[: committee.threshold - 1]

    ballots = [
        encrypt_candidate_vote(committee.public_key, candidate_index, len(candidate_names))
        for candidate_index in selected_candidate_indices
    ]
    encrypted_tally = aggregate_encrypted_ballots(committee.public_key, ballots)
    chain_state = {
        "candidate_names": list(candidate_names),
        "committee": committee.public_payload(),
        "encrypted_ballots": [ballot.to_chain_payload() for ballot in ballots],
        "encrypted_tally": encrypted_tally.to_chain_payload(),
        "encrypted_tally_verified": verify_encrypted_tally(committee.public_key, ballots, encrypted_tally),
    }

    success_result = publish_threshold_tally_result(
        committee=committee,
        encrypted_tally=encrypted_tally,
        participating_member_ids=successful_member_ids,
        max_plaintext=len(ballots),
    )
    success = {
        "participating_member_ids": list(successful_member_ids),
        "threshold_met": True,
        "threshold_decryption_verified": verify_threshold_tally_result(
            committee.public_key,
            committee.public_shares,
            committee.threshold,
            encrypted_tally,
            success_result,
        ),
        "published_result": success_result.to_payload(),
    }

    failure = {
        "participating_member_ids": list(insufficient_member_ids),
        "threshold_met": False,
        "message": "Kann nicht entschluesselt werden: Threshold wurde nicht erreicht.",
        "valid_partial_decryptions": len(set(insufficient_member_ids)),
        "required_partial_decryptions": committee.threshold,
        "published_result": None,
    }

    return {
        "chain_state": chain_state,
        "success_case": success,
        "failure_case": failure,
    }


def print_threshold_demo_report(demo: dict) -> None:
    chain_state = demo["chain_state"]
    print("CHAIN / PUBLIC STATE")
    print("--------------------")
    print("Candidates:", chain_state["candidate_names"])
    print("Committee threshold:", chain_state["committee"]["threshold"])
    print("Committee members:", chain_state["committee"]["member_count"])
    print("Encrypted tally verified:", chain_state["encrypted_tally_verified"])
    print("Encrypted tally payload:")
    print(chain_state["encrypted_tally"])
    print("First encrypted ballot payload:")
    print(chain_state["encrypted_ballots"][0])

    print("\nCASE A - THRESHOLD REACHED")
    print("--------------------------")
    success = demo["success_case"]
    print("Participating committee members:", success["participating_member_ids"])
    print("Threshold met:", success["threshold_met"])
    print("Threshold decryption verified:", success["threshold_decryption_verified"])
    print("Published plaintext tally:", success["published_result"]["plaintext_tally"])

    print("\nCASE B - THRESHOLD NOT REACHED")
    print("------------------------------")
    failure = demo["failure_case"]
    print("Participating committee members:", failure["participating_member_ids"])
    print("Threshold met:", failure["threshold_met"])
    print("Valid partial decryptions:", failure["valid_partial_decryptions"])
    print("Required partial decryptions:", failure["required_partial_decryptions"])
    print(failure["message"])


def _challenge(
    public_key: ElGamalPublicKey,
    public_element: int,
    ciphertext: Ciphertext,
    decryption_factor: int,
    t1: int,
    t2: int,
) -> int:
    values = [
        public_key.p,
        public_key.q,
        public_key.g,
        public_key.h,
        public_element,
        ciphertext.a,
        ciphertext.b,
        decryption_factor,
        t1,
        t2,
    ]
    digest = hashlib.sha256("|".join(str(value) for value in values).encode()).digest()
    return int.from_bytes(digest, "big") % public_key.q


def _evaluate_polynomial(coefficients: Sequence[int], x: int, modulus: int) -> int:
    result = 0
    power = 1
    for coefficient in coefficients:
        result = (result + coefficient * power) % modulus
        power = (power * x) % modulus
    return result


def _lagrange_coefficient_at_zero(member_id: int, member_ids: Sequence[int], modulus: int) -> int:
    numerator = 1
    denominator = 1
    for other_id in member_ids:
        if other_id == member_id:
            continue
        numerator = (numerator * (-other_id)) % modulus
        denominator = (denominator * (member_id - other_id)) % modulus
    return (numerator * pow(denominator, -1, modulus)) % modulus


def _unique_member_shares(shares: Sequence[PartialDecryptionShare]) -> List[PartialDecryptionShare]:
    unique = {}
    for share in shares:
        unique.setdefault(share.member_id, share)
    return list(unique.values())


def _generate_safe_prime(bits: int) -> tuple[int, int]:
    q_bits = bits - 1
    while True:
        q = _generate_prime(q_bits)
        p = 2 * q + 1
        if _is_probable_prime(p):
            return p, q


def _subgroup_generator(p: int, q: int) -> int:
    while True:
        candidate = secrets.randbelow(p - 3) + 2
        generator = pow(candidate, 2, p)
        if generator != 1 and pow(generator, q, p) == 1:
            return generator


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


if __name__ == "__main__":
    demo = demo_threshold_success_and_failure(
        candidate_names=["Alice", "Bob", "Charlie", "Diana"],
        selected_candidate_indices=[0, 1, 1, 3, 2, 1, 0],
        member_count=5,
        threshold=3,
        successful_member_ids=[1, 3, 5],
        insufficient_member_ids=[1, 3],
    )
    print_threshold_demo_report(demo)
