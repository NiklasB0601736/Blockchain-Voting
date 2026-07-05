"""
Petlib-backed EC-ElGamal tally prototype for verifiable encrypted voting.

This module keeps the same voting flow as crypto_elgamal_tally.py, but replaces
the hand-rolled prime group arithmetic with Petlib/OpenSSL elliptic-curve
operations. It is still a prototype and is not wired into blockchainV1.py.

High-level model:
- A candidate vote is represented as a one-hot vector, e.g. Bob in a
  three-candidate election becomes [0, 1, 0].
- Each vector entry is encrypted separately with EC-ElGamal.
- Ciphertexts can be added point-wise, so all encrypted ballots can be summed
  without decrypting individual votes.
- The committee receives Shamir key shares. A threshold of members can publish
  partial decryptions plus proofs, and everyone else can verify that the final
  plaintext tally matches the encrypted tally.

Important prototype limitation:
This demonstrates the cryptographic shape of the protocol, but it is not yet a
production voting system. Missing pieces include ballot validity ZK proofs,
anonymous eligibility/nullifier logic, hardened serialization, and independent
security review.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Sequence

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt


# Petlib/OpenSSL curve NID. 415 is prime256v1 / secp256r1 in this environment.
# Keeping this as a constant makes all generated keys and serialized payloads
# use the same group unless a test deliberately overrides it.
CURVE_ID = 415

# Domain separation prevents this Fiat-Shamir challenge hash from accidentally
# being reusable as a proof in another protocol with similar point inputs.
CHALLENGE_DOMAIN = b"voting-elgamal-chaum-pedersen-v1"


@dataclass(frozen=True)
class PetlibPublicKey:
    """
    Public EC-ElGamal key material.

    group:
        The elliptic-curve group used for all point operations.
    generator:
        Base point G. Plaintexts are encoded as small multiples m * G.
    public_point:
        Public key H = x * G, where x is the private decryption key.

    This object is safe to publish. It contains no private scalar.
    """

    group: EcGroup
    generator: EcPt
    public_point: EcPt

    @property
    def order(self) -> Bn:
        """Return the group order q, used as modulus for all scalar math."""
        return self.group.order()

    @property
    def curve_id(self) -> int:
        """Return the OpenSSL/Petlib curve identifier for payload metadata."""
        return self.group.nid()

    def to_payload(self) -> dict:
        """
        Serialize public key material for chain/API payloads.

        EC points are exported through Petlib's canonical binary point export
        and then hex-encoded so they can live in JSON-like structures.
        """
        return {
            "curve_id": self.curve_id,
            "generator": _point_to_hex(self.generator),
            "public_key": _point_to_hex(self.public_point),
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "PetlibPublicKey":
        """Reconstruct a public key from the JSON-compatible payload format."""
        group = EcGroup(int(payload["curve_id"]))
        return cls(
            group=group,
            generator=_point_from_hex(group, payload["generator"]),
            public_point=_point_from_hex(group, payload["public_key"]),
        )


@dataclass(frozen=True)
class PetlibPrivateKey:
    """
    Single-holder private key for EC-ElGamal.

    The threshold flow below normally avoids giving one party this secret.
    This type is still useful for basic demos and tests.
    """

    public_key: PetlibPublicKey
    secret: Bn


@dataclass(frozen=True)
class CommitteeMemberShare:
    """
    Private Shamir share for one committee member.

    share:
        The private scalar f(member_id). This must stay with the committee
        member and must never be written to a public chain payload.
    public_share:
        Public commitment share * G. This lets verifiers check partial
        decryptions without learning the private share.
    """

    member_id: int
    share: Bn
    public_share: EcPt

    def public_payload(self) -> dict:
        """Serialize only the public part of a committee member share."""
        return {"member_id": self.member_id, "public_share": _point_to_hex(self.public_share)}


@dataclass(frozen=True)
class CommitteeKeyShares:
    """
    Complete committee setup object.

    For the prototype this object stores all private member shares in memory,
    because the demo needs to simulate multiple committee members locally. In a
    real deployment each member would receive only their own `share`; observers
    would receive only `public_payload()`.
    """

    public_key: PetlibPublicKey
    threshold: int
    member_count: int
    member_shares: List[CommitteeMemberShare]

    @property
    def public_shares(self) -> dict[int, EcPt]:
        """Return member_id -> public_share for public proof verification."""
        return {member.member_id: member.public_share for member in self.member_shares}

    def public_payload(self) -> dict:
        """
        Serialize public committee data.

        Notice that private Shamir shares are intentionally not included. The
        payload is sufficient to verify published partial decryptions.
        """
        return {
            "threshold": self.threshold,
            "member_count": self.member_count,
            **self.public_key.to_payload(),
            "public_shares": [member.public_payload() for member in self.member_shares],
        }


@dataclass(frozen=True)
class Ciphertext:
    """
    One EC-ElGamal ciphertext.

    Encryption of message m:
        A = r * G
        B = r * H + m * G

    Here r is fresh randomness per ciphertext. The plaintext is encoded as the
    point m * G because elliptic-curve ElGamal encrypts group elements, not raw
    integers. Since vote counts are small, we can recover m later with a small
    lookup/discrete-log table.
    """

    a: EcPt
    b: EcPt

    def to_payload(self) -> dict:
        """Serialize the two EC points as hex strings."""
        return {"a": _point_to_hex(self.a), "b": _point_to_hex(self.b)}

    @classmethod
    def from_payload(cls, group: EcGroup, payload: dict) -> "Ciphertext":
        """Deserialize a ciphertext from its chain/API representation."""
        return cls(a=_point_from_hex(group, payload["a"]), b=_point_from_hex(group, payload["b"]))


@dataclass(frozen=True)
class EncryptedBallot:
    """
    Encrypted one-hot ballot.

    `ciphertexts[i]` encrypts either 0 or 1 for candidate i. The current module
    validates this before encryption, but it does not yet produce a ZK proof
    that the encrypted ballot is really one-hot. That proof is a later step.
    """

    candidate_count: int
    ciphertexts: List[Ciphertext]

    def to_chain_payload(self) -> dict:
        """Export the ballot in the format that could be stored on-chain."""
        return {
            "candidate_count": self.candidate_count,
            "ciphertexts": [ciphertext.to_payload() for ciphertext in self.ciphertexts],
        }

    @classmethod
    def from_chain_payload(cls, public_key: PetlibPublicKey, payload: dict) -> "EncryptedBallot":
        """
        Reconstruct an encrypted ballot from chain data.

        The chain/API only stores hex-encoded point payloads. Verifiers need to
        turn those payloads back into Petlib points before they can aggregate or
        check the encrypted vote. Passing the public key gives us the correct
        curve/group for point import.
        """
        return cls(
            candidate_count=int(payload["candidate_count"]),
            ciphertexts=[
                Ciphertext.from_payload(public_key.group, ciphertext_payload)
                for ciphertext_payload in payload["ciphertexts"]
            ],
        )


@dataclass(frozen=True)
class EncryptedTally:
    """
    Homomorphically aggregated encrypted ballot sum.

    For each candidate this stores the point-wise sum of all ballot ciphertexts.
    Decrypting each entry yields the final count for that candidate, not any
    individual person's vote.
    """

    candidate_count: int
    ciphertexts: List[Ciphertext]

    def to_chain_payload(self) -> dict:
        """Export the encrypted tally as JSON-compatible public data."""
        return {
            "candidate_count": self.candidate_count,
            "ciphertexts": [ciphertext.to_payload() for ciphertext in self.ciphertexts],
        }

    @classmethod
    def from_chain_payload(cls, public_key: PetlibPublicKey, payload: dict) -> "EncryptedTally":
        """
        Reconstruct an encrypted tally from chain data.

        This mirrors EncryptedBallot.from_chain_payload and is used when a
        published tally result is verified from public JSON payloads.
        """
        return cls(
            candidate_count=int(payload["candidate_count"]),
            ciphertexts=[
                Ciphertext.from_payload(public_key.group, ciphertext_payload)
                for ciphertext_payload in payload["ciphertexts"]
            ],
        )


@dataclass(frozen=True)
class ChaumPedersenProof:
    """
    Non-interactive Chaum-Pedersen proof for equal discrete logs.

    It proves that the same private scalar s links:
        public_share = s * G
        decryption_factor = s * A

    In words: the committee member used their real key share to compute the
    partial decryption for this ciphertext. The verifier learns that statement,
    but not the private share s.
    """

    t1: EcPt
    t2: EcPt
    challenge: Bn
    response: Bn

    def to_payload(self) -> dict:
        """Serialize proof points and scalars for public verification."""
        return {
            "t1": _point_to_hex(self.t1),
            "t2": _point_to_hex(self.t2),
            "challenge": str(int(self.challenge)),
            "response": str(int(self.response)),
        }

    @classmethod
    def from_payload(cls, public_key: PetlibPublicKey, payload: dict) -> "ChaumPedersenProof":
        """
        Reconstruct a Chaum-Pedersen proof from public chain data.

        The scalar values are encoded as decimal strings in the public payload
        so JSON clients do not lose precision when handling large integers.
        """
        return cls(
            t1=_point_from_hex(public_key.group, payload["t1"]),
            t2=_point_from_hex(public_key.group, payload["t2"]),
            challenge=Bn.from_decimal(str(payload["challenge"])),
            response=Bn.from_decimal(str(payload["response"])),
        )


@dataclass(frozen=True)
class PartialDecryptionShare:
    """
    One committee member's partial decryption for one tally ciphertext.

    The factor is not a plaintext vote. It is share_i * A. Several such factors
    are combined with Lagrange coefficients to reconstruct x * A, which can then
    be subtracted from B.
    """

    candidate_index: int
    member_id: int
    decryption_factor: EcPt
    proof: ChaumPedersenProof

    def to_payload(self) -> dict:
        """Serialize the public partial decryption and its proof."""
        return {
            "candidate_index": self.candidate_index,
            "member_id": self.member_id,
            "decryption_factor": _point_to_hex(self.decryption_factor),
            "proof": self.proof.to_payload(),
        }

    @classmethod
    def from_payload(cls, public_key: PetlibPublicKey, payload: dict) -> "PartialDecryptionShare":
        """
        Reconstruct a committee member's public partial decryption payload.

        This does not include or require the private committee share. It is
        exactly the public material needed for verification.
        """
        return cls(
            candidate_index=int(payload["candidate_index"]),
            member_id=int(payload["member_id"]),
            decryption_factor=_point_from_hex(public_key.group, payload["decryption_factor"]),
            proof=ChaumPedersenProof.from_payload(public_key, payload["proof"]),
        )


@dataclass(frozen=True)
class ThresholdPublishedTallyResult:
    """
    Public decryption result.

    This is what the committee publishes after threshold decryption: the claimed
    plaintext tally and enough partial decryptions/proofs for everyone else to
    recompute and verify that claim against the encrypted tally.
    """

    plaintext_tally: List[int]
    partial_decryption_shares: List[PartialDecryptionShare]

    def to_payload(self) -> dict:
        """Export the published result in JSON-compatible form."""
        return {
            "plaintext_tally": self.plaintext_tally,
            "partial_decryption_shares": [
                share.to_payload() for share in self.partial_decryption_shares
            ],
        }

    @classmethod
    def from_payload(cls, public_key: PetlibPublicKey, payload: dict) -> "ThresholdPublishedTallyResult":
        """
        Reconstruct a published threshold tally from public chain data.

        The resulting object can be passed directly into
        verify_threshold_tally_result together with the public key, public
        committee shares, and encrypted tally.
        """
        return cls(
            plaintext_tally=[int(value) for value in payload["plaintext_tally"]],
            partial_decryption_shares=[
                PartialDecryptionShare.from_payload(public_key, share_payload)
                for share_payload in payload["partial_decryption_shares"]
            ],
        )


def generate_keypair(curve_id: int = CURVE_ID) -> PetlibPrivateKey:
    """
    Generate a normal, non-threshold EC-ElGamal keypair.

    This is mostly useful for small experiments. The threshold committee setup
    below is the more relevant path for the voting design because it avoids one
    single decryption authority.
    """
    group = EcGroup(curve_id)
    generator = group.generator()
    order = group.order()

    # Secret scalar x is chosen uniformly from 1..q-1. Public key is H = x * G.
    secret = _random_nonzero(order)
    public_point = secret * generator
    return PetlibPrivateKey(
        public_key=PetlibPublicKey(group=group, generator=generator, public_point=public_point),
        secret=secret,
    )


def majority_threshold(member_count: int) -> int:
    """Return the smallest strict majority for a committee of this size."""
    if member_count < 1:
        raise ValueError("member_count must be at least 1")
    return member_count // 2 + 1


def generate_committee_key_shares(
    member_count: int,
    threshold: int | None = None,
    curve_id: int = CURVE_ID,
) -> CommitteeKeyShares:
    """
    Create a threshold ElGamal committee using Shamir Secret Sharing.

    A random secret x is chosen as the committee decryption key. Instead of
    storing x directly, we build a random polynomial f where f(0) = x. Each
    committee member receives f(member_id). Any `threshold` points can
    reconstruct f(0), but fewer points reveal no usable key in the Shamir model.

    The public key is still H = x * G, so voters only need the public key and do
    not care how the private key is split internally.
    """
    if threshold is None:
        threshold = majority_threshold(member_count)
    if member_count < 1:
        raise ValueError("member_count must be at least 1")
    if threshold < 1 or threshold > member_count:
        raise ValueError("threshold must be between 1 and member_count")

    group = EcGroup(curve_id)
    generator = group.generator()
    order = group.order()

    # f(0) is the shared private key. The remaining coefficients randomize the
    # Shamir polynomial and determine the individual member shares.
    secret = _random_nonzero(order)
    coefficients = [secret] + [order.random() for _ in range(threshold - 1)]
    public_key = PetlibPublicKey(
        group=group,
        generator=generator,
        public_point=secret * generator,
    )

    member_shares = []
    for member_id in range(1, member_count + 1):
        # The private share is f(member_id). The public share is f(member_id)*G
        # and can later be used to verify Chaum-Pedersen proofs.
        share = _evaluate_polynomial(coefficients, member_id, order)
        member_shares.append(
            CommitteeMemberShare(
                member_id=member_id,
                share=share,
                public_share=share * generator,
            )
        )

    return CommitteeKeyShares(
        public_key=public_key,
        threshold=threshold,
        member_count=member_count,
        member_shares=member_shares,
    )


def encrypt_message(public_key: PetlibPublicKey, message: int) -> Ciphertext:
    """
    Encrypt a small integer as an EC-ElGamal ciphertext.

    Petlib encrypts points, not integers. We therefore encode `message` as
    `message * G`. This is practical for vote counts because the final plaintext
    range is tiny compared with the group order.

    Fresh randomness r is essential: encrypting the same vote twice should
    produce different ciphertexts.
    """
    if message < 0 or message >= int(public_key.order):
        raise ValueError("message out of range")

    r = _random_nonzero(public_key.order)
    encoded_message = Bn(message) * public_key.generator
    return Ciphertext(
        a=r * public_key.generator,
        b=(r * public_key.public_point) + encoded_message,
    )


def add_ciphertexts(public_key: PetlibPublicKey, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
    """
    Homomorphically add EC-ElGamal ciphertexts.

    If C1 encrypts m1 and C2 encrypts m2, then C1 + C2 encrypts m1 + m2.
    This is why the election can publish encrypted ballots first and only later
    decrypt the aggregated candidate counts.
    """
    a_sum = public_key.group.infinite()
    b_sum = public_key.group.infinite()
    for ciphertext in ciphertexts:
        a_sum = a_sum + ciphertext.a
        b_sum = b_sum + ciphertext.b
    return Ciphertext(a=a_sum, b=b_sum)


def encrypt_candidate_vote(
    public_key: PetlibPublicKey,
    candidate_index: int,
    candidate_count: int,
) -> EncryptedBallot:
    """Convert a selected candidate index into a one-hot ballot and encrypt it."""
    return encrypt_plaintext_ballot(public_key, one_hot_vote(candidate_index, candidate_count))


def encrypt_plaintext_ballot(public_key: PetlibPublicKey, ballot: Sequence[int]) -> EncryptedBallot:
    """
    Encrypt an already prepared one-hot ballot vector.

    This function is deliberately strict: only exactly-one-selection ballots are
    accepted. Later, a ZK proof should make this property publicly verifiable
    without revealing which entry contains the 1.
    """
    validate_one_hot_ballot(ballot)
    return EncryptedBallot(
        candidate_count=len(ballot),
        ciphertexts=[encrypt_message(public_key, value) for value in ballot],
    )


def aggregate_encrypted_ballots(
    public_key: PetlibPublicKey,
    ballots: Sequence[EncryptedBallot],
) -> EncryptedTally:
    """
    Aggregate all encrypted ballots candidate by candidate.

    No decryption happens here. The function only adds EC points. The result is
    one encrypted counter per candidate.
    """
    if not ballots:
        raise ValueError("cannot aggregate empty ballot list")

    candidate_count = ballots[0].candidate_count
    for ballot in ballots:
        if ballot.candidate_count != candidate_count:
            raise ValueError("all ballots must have the same candidate_count")

    totals = []
    for candidate_index in range(candidate_count):
        # Add the same candidate position across all ballots, e.g. all encrypted
        # "Alice" entries together, then all encrypted "Bob" entries, etc.
        totals.append(
            add_ciphertexts(
                public_key,
                [ballot.ciphertexts[candidate_index] for ballot in ballots],
            )
        )
    return EncryptedTally(candidate_count=candidate_count, ciphertexts=totals)


def publish_threshold_tally_result(
    committee: CommitteeKeyShares,
    encrypted_tally: EncryptedTally,
    participating_member_ids: Sequence[int],
    max_plaintext: int,
) -> ThresholdPublishedTallyResult:
    """
    Simulate committee publication of a threshold-decrypted tally.

    For every candidate counter, each participating member publishes:
    - their partial decryption factor share_i * A
    - a Chaum-Pedersen proof that this factor was computed from their public
      share, without revealing share_i

    Once enough valid partial decryptions exist, they are combined to obtain
    x * A. Subtracting x * A from B leaves only m * G, from which the small vote
    count m is recovered.
    """
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
    all_shares = []
    for candidate_index, ciphertext in enumerate(encrypted_tally.ciphertexts):
        candidate_shares = []
        for member in participants:
            # A partial factor is not useful by itself for plaintext recovery
            # unless enough other threshold factors are also available.
            factor = compute_partial_decryption_factor(member, ciphertext)
            proof = create_partial_decryption_proof(committee.public_key, member, ciphertext, factor)
            share = PartialDecryptionShare(
                candidate_index=candidate_index,
                member_id=member.member_id,
                decryption_factor=factor,
                proof=proof,
            )
            candidate_shares.append(share)
            all_shares.append(share)

        combined_factor = combine_partial_decryption_factors(
            committee.public_key,
            candidate_shares,
            committee.threshold,
        )
        plaintext_point = remove_decryption_factor(ciphertext, combined_factor)

        # The final plaintext point should be count * G. Because count is small
        # in a tally, a bounded lookup is acceptable for the prototype.
        plaintext_tally.append(discrete_log_small(committee.public_key, plaintext_point, max_plaintext))

    return ThresholdPublishedTallyResult(
        plaintext_tally=plaintext_tally,
        partial_decryption_shares=all_shares,
    )


def verify_threshold_tally_result(
    public_key: PetlibPublicKey,
    public_shares: dict[int, EcPt],
    threshold: int,
    encrypted_tally: EncryptedTally,
    published_result: ThresholdPublishedTallyResult,
) -> bool:
    """
    Publicly verify a threshold-decrypted tally.

    The verifier needs only public data:
    - committee public key
    - public member shares
    - encrypted tally
    - published plaintext tally
    - partial decryptions and proofs

    The verifier does not need private committee shares. It checks that enough
    valid partial decryptions exist for each candidate and that recomputing the
    plaintext point produces the published count.
    """
    if threshold < 1:
        return False
    if len(published_result.plaintext_tally) != encrypted_tally.candidate_count:
        return False

    shares_by_candidate: dict[int, list[PartialDecryptionShare]] = {
        index: [] for index in range(encrypted_tally.candidate_count)
    }
    for share in published_result.partial_decryption_shares:
        # Reject shares for unknown candidates or unknown committee members
        # before doing any group arithmetic with them.
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
            # Each member must prove that decryption_factor = share_i * A and
            # public_share = share_i * G use the same hidden share_i.
            if not verify_partial_decryption_proof(
                public_key,
                public_shares[share.member_id],
                ciphertext,
                share.decryption_factor,
                share.proof,
            ):
                return False

        combined_factor = combine_partial_decryption_factors(public_key, selected_shares, threshold)
        plaintext_point = remove_decryption_factor(ciphertext, combined_factor)

        # The published integer is accepted only if it maps back to the exact
        # point recovered from the encrypted tally and committee factors.
        if plaintext_point != Bn(plaintext) * public_key.generator:
            return False

    return True


def public_shares_from_payload(public_key: PetlibPublicKey, payload: dict) -> dict[int, EcPt]:
    """
    Reconstruct public committee shares from a public committee payload.

    The distributed chain stores only public committee material. This helper
    turns the JSON/chain representation back into Petlib points so validators
    can verify published threshold tally results without private shares.
    """
    return {
        int(share_payload["member_id"]): _point_from_hex(public_key.group, share_payload["public_share"])
        for share_payload in payload["public_shares"]
    }


def verify_encrypted_tally(
    public_key: PetlibPublicKey,
    ballots: Sequence[EncryptedBallot],
    published_tally: EncryptedTally,
) -> bool:
    """
    Check that a published encrypted tally equals the sum of all ballots.

    This does not prove that each ballot is valid; it only verifies the
    arithmetic consistency between the visible encrypted ballots and the visible
    encrypted tally.
    """
    return aggregate_encrypted_ballots(public_key, ballots) == published_tally


def compute_partial_decryption_factor(member: CommitteeMemberShare, ciphertext: Ciphertext) -> EcPt:
    """
    Compute one member's threshold decryption factor.

    For ciphertext A = r * G, member i computes share_i * A. Later these
    factors are Lagrange-combined to reconstruct x * A without reconstructing
    the private key x directly in one place.
    """
    return member.share * ciphertext.a


def combine_partial_decryption_factors(
    public_key: PetlibPublicKey,
    shares: Sequence[PartialDecryptionShare],
    threshold: int,
) -> EcPt:
    """
    Combine enough partial decryption factors into the full factor x * A.

    Shamir reconstruction is linear, so instead of reconstructing x and then
    multiplying by A, we can multiply each partial point by its Lagrange
    coefficient and add the points:

        sum(lambda_i * (share_i * A)) = (sum(lambda_i * share_i)) * A = x * A
    """
    unique_shares = _unique_member_shares(shares)
    if len(unique_shares) < threshold:
        raise ValueError("not enough partial decryption shares")

    selected_shares = unique_shares[:threshold]
    member_ids = [share.member_id for share in selected_shares]
    combined = public_key.group.infinite()
    for share in selected_shares:
        coefficient = _lagrange_coefficient_at_zero(share.member_id, member_ids, public_key.order)
        combined = combined + (coefficient * share.decryption_factor)
    return combined


def remove_decryption_factor(ciphertext: Ciphertext, decryption_factor: EcPt) -> EcPt:
    """
    Remove the ElGamal masking term from B.

    Since B = r * H + m * G and H = x * G, the combined decryption factor is
    x * A = x * (r * G) = r * H. Subtracting it leaves m * G.
    """
    return ciphertext.b - decryption_factor


def create_partial_decryption_proof(
    public_key: PetlibPublicKey,
    member: CommitteeMemberShare,
    ciphertext: Ciphertext,
    decryption_factor: EcPt,
) -> ChaumPedersenProof:
    """
    Create a proof that a partial decryption was computed with the real share.

    The witness is member.share. The public statement links two equations:
    member.public_share = member.share * G and
    decryption_factor = member.share * ciphertext.a.
    """
    return _create_discrete_log_equality_proof(
        public_key=public_key,
        witness=member.share,
        public_element=member.public_share,
        ciphertext=ciphertext,
        decryption_factor=decryption_factor,
    )


def verify_partial_decryption_proof(
    public_key: PetlibPublicKey,
    public_share: EcPt,
    ciphertext: Ciphertext,
    decryption_factor: EcPt,
    proof: ChaumPedersenProof,
) -> bool:
    """
    Verify one Chaum-Pedersen partial decryption proof.

    The verifier recomputes the Fiat-Shamir challenge from the public transcript
    and checks both response equations. If either equation fails, the member
    either used the wrong share, the factor was tampered with, or the proof does
    not belong to this ciphertext.
    """
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

    return (
        proof.response * public_key.generator == proof.t1 + (proof.challenge * public_share)
        and proof.response * ciphertext.a == proof.t2 + (proof.challenge * decryption_factor)
    )


def discrete_log_small(public_key: PetlibPublicKey, point: EcPt, max_plaintext: int) -> int:
    """
    Recover a small integer m from the point m * G.

    General elliptic-curve discrete log is intentionally infeasible. Here we
    only search 0..max_plaintext, which is safe for a tally counter because the
    maximum count is the number of ballots.
    """
    current = public_key.group.infinite()
    for value in range(max_plaintext + 1):
        if current == point:
            return value
        current = current + public_key.generator
    raise ValueError("plaintext is outside the configured tally range")


def one_hot_vote(candidate_index: int, candidate_count: int) -> List[int]:
    """
    Build a one-hot vote vector from a candidate index.

    Example: candidate_index=2 and candidate_count=4 becomes [0, 0, 1, 0].
    """
    if candidate_count < 2:
        raise ValueError("candidate_count must be at least 2")
    if candidate_index < 0 or candidate_index >= candidate_count:
        raise ValueError("candidate_index out of range")
    return [1 if index == candidate_index else 0 for index in range(candidate_count)]


def validate_one_hot_ballot(ballot: Sequence[int]) -> None:
    """
    Validate the plaintext ballot shape before encryption.

    This protects the local prototype from encrypting malformed ballots such as
    [1, 1, 0]. A real public voting protocol additionally needs a zero-knowledge
    proof so observers can verify this after encryption.
    """
    if len(ballot) < 2:
        raise ValueError("ballot must contain at least 2 candidates")
    if any(value not in (0, 1) for value in ballot):
        raise ValueError("ballot values must be 0 or 1")
    if sum(ballot) != 1:
        raise ValueError("ballot must select exactly one candidate")


def demo_threshold_candidate_tally(
    candidate_names: Sequence[str],
    selected_candidate_indices: Sequence[int],
    member_count: int,
    threshold: int | None = None,
    participating_member_ids: Sequence[int] | None = None,
) -> dict:
    """
    Run an end-to-end threshold tally demo and return public-facing payloads.

    This is useful for manual verification from the terminal. It intentionally
    returns chain-like data structures so the output resembles what a later
    blockchain/API integration would publish.
    """
    committee = generate_committee_key_shares(member_count=member_count, threshold=threshold)
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


def _create_discrete_log_equality_proof(
    public_key: PetlibPublicKey,
    witness: Bn,
    public_element: EcPt,
    ciphertext: Ciphertext,
    decryption_factor: EcPt,
) -> ChaumPedersenProof:
    """
    Create a non-interactive proof of equal discrete logs.

    Schnorr/Chaum-Pedersen shape:
    - choose random nonce w
    - commit with t1 = w * G and t2 = w * A
    - derive challenge c = H(public transcript)
    - respond with z = w + c * witness mod q

    Verification checks z * G == t1 + c * public_element and
    z * A == t2 + c * decryption_factor.
    """
    w = _random_nonzero(public_key.order)
    t1 = w * public_key.generator
    t2 = w * ciphertext.a
    challenge = _challenge(public_key, public_element, ciphertext, decryption_factor, t1, t2)
    response = (w + (challenge * witness)) % public_key.order
    return ChaumPedersenProof(t1=t1, t2=t2, challenge=challenge, response=response)


def _challenge(
    public_key: PetlibPublicKey,
    public_element: EcPt,
    ciphertext: Ciphertext,
    decryption_factor: EcPt,
    t1: EcPt,
    t2: EcPt,
) -> Bn:
    """
    Hash the public proof transcript into a scalar challenge.

    The transcript uses exported EC points rather than `str(point)` so that the
    challenge is stable and canonical. Domain separation is included as the
    first field.
    """
    transcript = b"|".join(
        [
            CHALLENGE_DOMAIN,
            str(public_key.curve_id).encode(),
            public_key.generator.export(),
            public_key.public_point.export(),
            public_element.export(),
            ciphertext.a.export(),
            ciphertext.b.export(),
            decryption_factor.export(),
            t1.export(),
            t2.export(),
        ]
    )
    return Bn.from_binary(hashlib.sha256(transcript).digest()) % public_key.order


def _evaluate_polynomial(coefficients: Sequence[Bn], x: int, modulus: Bn) -> Bn:
    """
    Evaluate a Shamir polynomial at x modulo the group order.

    Coefficients are stored lowest degree first:
    coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 + ...
    """
    result = Bn(0)
    power = Bn(1)
    x_value = Bn(x)
    for coefficient in coefficients:
        result = (result + (coefficient * power)) % modulus
        power = (power * x_value) % modulus
    return result


def _lagrange_coefficient_at_zero(member_id: int, member_ids: Sequence[int], modulus: Bn) -> Bn:
    """
    Compute the Lagrange coefficient for reconstructing f(0).

    Given the participating member ids, this coefficient says how much the
    selected member's share contributes to the secret at x=0.
    """
    numerator = Bn(1)
    denominator = Bn(1)
    for other_id in member_ids:
        if other_id == member_id:
            continue
        numerator = (numerator * Bn(-other_id)) % modulus
        denominator = (denominator * Bn(member_id - other_id)) % modulus
    return (numerator * denominator.mod_inverse(modulus)) % modulus


def _unique_member_shares(shares: Sequence[PartialDecryptionShare]) -> List[PartialDecryptionShare]:
    """
    Deduplicate partial decryptions by member id.

    A member should not be counted twice toward the threshold. If duplicates are
    present, the first occurrence wins.
    """
    unique = {}
    for share in shares:
        unique.setdefault(share.member_id, share)
    return list(unique.values())


def _random_nonzero(modulus: Bn) -> Bn:
    """Sample a random scalar from 1..modulus-1."""
    while True:
        value = modulus.random()
        if value != 0:
            return value


def _point_to_hex(point: EcPt) -> str:
    """Serialize an EC point to a compact hex string."""
    return point.export().hex()


def _point_from_hex(group: EcGroup, value: str) -> EcPt:
    """Deserialize an EC point from the compact hex string representation."""
    return EcPt.from_binary(bytes.fromhex(value), group)


if __name__ == "__main__":
    demo = demo_threshold_candidate_tally(
        candidate_names=["Alice", "Bob", "Charlie", "Diana"],
        selected_candidate_indices=[0, 1, 1, 3, 2, 1, 0],
        member_count=5,
        threshold=3,
        participating_member_ids=[1, 3, 5],
    )
    print("Encrypted tally verified:", demo["encrypted_tally_verified"])
    print("Threshold decryption verified:", demo["threshold_decryption_verified"])
    print("Participating committee members:", demo["participating_member_ids"])
    print("Published plaintext tally:", demo["published_result"]["plaintext_tally"])
    print("First encrypted ballot payload:")
    print(demo["encrypted_ballots"][0])
