import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

const CURVE_ID = 415;
const CHALLENGE_DOMAIN = "voting-elgamal-chaum-pedersen-v1";
const Point = p256.Point;
const GENERATOR = Point.BASE;
const ORDER = Point.Fn.ORDER;
const encoder = new TextEncoder();

function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBigInt(bytes) {
    const hex = bytesToHex(bytes);
    return hex ? BigInt(`0x${hex}`) : 0n;
}

function concatBytes(parts) {
    const length = parts.reduce((total, part) => total + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

function hashText(value) {
    return bytesToHex(sha256(encoder.encode(String(value))));
}

function randomScalar() {
    while (true) {
        const bytes = new Uint8Array(32);
        globalThis.crypto.getRandomValues(bytes);
        const value = bytesToBigInt(bytes);
        if (value > 0n && value < ORDER) return value;
    }
}

function mod(value) {
    const reduced = value % ORDER;
    return reduced >= 0n ? reduced : reduced + ORDER;
}

function inverse(value) {
    let oldR = mod(value);
    let r = ORDER;
    let oldS = 1n;
    let s = 0n;
    while (r !== 0n) {
        const quotient = oldR / r;
        [oldR, r] = [r, oldR - quotient * r];
        [oldS, s] = [s, oldS - quotient * s];
    }
    if (oldR !== 1n) throw new Error("scalar has no modular inverse");
    return mod(oldS);
}

function pointFromHex(value) {
    return Point.fromHex(String(value));
}

function pointToHex(point) {
    return point.toHex(true);
}

function committeeFingerprint(publicPayload) {
    return hashText([
        publicPayload.curve_id,
        publicPayload.generator,
        publicPayload.public_key,
        publicPayload.threshold,
        publicPayload.member_count,
    ].join(":"));
}

function deriveVoterCredentials(electionId, voterSecret) {
    const secret = String(voterSecret).trim();
    if (!secret) throw new Error("Voter Secret fehlt");
    const commitmentHash = hashText(secret);
    return {
        commitment_hash: commitmentHash,
        // This deterministic link closes the demo's arbitrary-nullifier hole.
        // A production system replaces the public link with a ZK nullifier proof.
        nullifier_hash: hashText(`${electionId}:${commitmentHash}:nullifier`),
    };
}

function encryptCandidateVote(committeePayload, candidateIndex, candidateCount) {
    if (Number(committeePayload.curve_id) !== CURVE_ID) throw new Error("Nicht unterstuetzte Kurve");
    if (candidateCount < 2 || candidateIndex < 0 || candidateIndex >= candidateCount) {
        throw new Error("Kandidat ausserhalb des gueltigen Bereichs");
    }
    const publicPoint = pointFromHex(committeePayload.public_key);
    const ciphertexts = [];
    for (let index = 0; index < candidateCount; index += 1) {
        const randomness = randomScalar();
        const a = GENERATOR.multiply(randomness);
        const mask = publicPoint.multiply(randomness);
        const b = index === candidateIndex ? mask.add(GENERATOR) : mask;
        ciphertexts.push({ a: pointToHex(a), b: pointToHex(b) });
    }
    return { candidate_count: candidateCount, ciphertexts };
}

function createEncryptedVotePayload(election, voterSecret, candidateIndex) {
    const credentials = deriveVoterCredentials(election.election_id, voterSecret);
    return {
        election_id: election.election_id,
        nullifier_hash: credentials.nullifier_hash,
        encrypted_ballot: encryptCandidateVote(
            election.committee,
            candidateIndex,
            election.options.length,
        ),
        eligibility_proof_placeholder: {
            type: "deterministic-nullifier-demo-v2",
            accepted: true,
            commitment_hash: credentials.commitment_hash,
        },
        ballot_validity_proof_placeholder: {
            type: "local-one-hot-encryption-demo-v2",
            accepted: true,
        },
    };
}

function evaluatePolynomial(coefficients, memberId) {
    let result = 0n;
    let power = 1n;
    const x = BigInt(memberId);
    for (const coefficient of coefficients) {
        result = mod(result + coefficient * power);
        power = mod(power * x);
    }
    return result;
}

function generateCommittee(electionId, memberCount, threshold) {
    if (memberCount < 1 || threshold < 1 || threshold > memberCount) {
        throw new Error("Committee- oder Threshold-Wert ungueltig");
    }
    const coefficients = Array.from({ length: threshold }, () => randomScalar());
    const shares = [];
    const publicShares = [];
    for (let memberId = 1; memberId <= memberCount; memberId += 1) {
        const share = evaluatePolynomial(coefficients, memberId);
        const publicShare = pointToHex(GENERATOR.multiply(share));
        shares.push({ member_id: memberId, share: share.toString(), public_share: publicShare });
        publicShares.push({ member_id: memberId, public_share: publicShare });
    }
    const publicPayload = {
        threshold,
        member_count: memberCount,
        curve_id: CURVE_ID,
        generator: pointToHex(GENERATOR),
        public_key: pointToHex(GENERATOR.multiply(coefficients[0])),
        public_shares: publicShares,
    };
    const fingerprint = committeeFingerprint(publicPayload);
    return {
        public_payload: publicPayload,
        member_files: shares.map(share => ({
            version: "voting-committee-share-v1",
            election_id: electionId,
            committee_fingerprint: fingerprint,
            ...share,
        })),
    };
}

function validateCommitteeShare(election, memberFile) {
    if (memberFile.version !== "voting-committee-share-v1") throw new Error("Unbekanntes Share-Format");
    if (memberFile.election_id !== election.election_id) throw new Error("Share gehoert zu einer anderen Wahl");
    if (memberFile.committee_fingerprint !== committeeFingerprint(election.committee)) {
        throw new Error("Share passt nicht zum Committee");
    }
    const expected = GENERATOR.multiply(mod(BigInt(memberFile.share)));
    if (pointToHex(expected) !== memberFile.public_share) throw new Error("Privater und oeffentlicher Share passen nicht");
    const publicEntry = election.committee.public_shares.find(
        item => Number(item.member_id) === Number(memberFile.member_id),
    );
    if (!publicEntry || publicEntry.public_share !== memberFile.public_share) {
        throw new Error("Share ist nicht im oeffentlichen Committee registriert");
    }
    return true;
}

function aggregateEncryptedBallots(ballots, candidateCount) {
    if (!ballots.length) throw new Error("Keine verschluesselten Stimmen vorhanden");
    const totals = Array.from({ length: candidateCount }, () => ({ a: Point.ZERO, b: Point.ZERO }));
    for (const ballot of ballots) {
        if (Number(ballot.candidate_count) !== candidateCount || ballot.ciphertexts.length !== candidateCount) {
            throw new Error("Ballot passt nicht zur Wahl");
        }
        ballot.ciphertexts.forEach((ciphertext, index) => {
            totals[index].a = totals[index].a.add(pointFromHex(ciphertext.a));
            totals[index].b = totals[index].b.add(pointFromHex(ciphertext.b));
        });
    }
    return {
        candidate_count: candidateCount,
        ciphertexts: totals.map(ciphertext => ({
            a: pointToHex(ciphertext.a),
            b: pointToHex(ciphertext.b),
        })),
    };
}

function challengeScalar(committee, publicShare, ciphertext, factor, t1, t2) {
    const separator = encoder.encode("|");
    const fields = [
        encoder.encode(CHALLENGE_DOMAIN),
        encoder.encode(String(committee.curve_id)),
        Point.fromHex(committee.generator).toBytes(true),
        Point.fromHex(committee.public_key).toBytes(true),
        publicShare.toBytes(true),
        ciphertext.a.toBytes(true),
        ciphertext.b.toBytes(true),
        factor.toBytes(true),
        t1.toBytes(true),
        t2.toBytes(true),
    ];
    const transcript = [];
    fields.forEach((field, index) => {
        if (index) transcript.push(separator);
        transcript.push(field);
    });
    return bytesToBigInt(sha256(concatBytes(transcript))) % ORDER;
}

function partialDecryption(committee, memberFile, ciphertextPayload, candidateIndex) {
    const share = mod(BigInt(memberFile.share));
    const ciphertext = {
        a: pointFromHex(ciphertextPayload.a),
        b: pointFromHex(ciphertextPayload.b),
    };
    const publicShare = pointFromHex(memberFile.public_share);
    const factor = ciphertext.a.multiply(share);
    const nonce = randomScalar();
    const t1 = GENERATOR.multiply(nonce);
    const t2 = ciphertext.a.multiply(nonce);
    const challenge = challengeScalar(committee, publicShare, ciphertext, factor, t1, t2);
    const response = mod(nonce + challenge * share);
    return {
        candidate_index: candidateIndex,
        member_id: Number(memberFile.member_id),
        decryption_factor: pointToHex(factor),
        proof: {
            t1: pointToHex(t1),
            t2: pointToHex(t2),
            challenge: challenge.toString(),
            response: response.toString(),
        },
    };
}

function lagrangeCoefficient(memberId, memberIds) {
    let numerator = 1n;
    let denominator = 1n;
    for (const otherId of memberIds) {
        if (otherId === memberId) continue;
        numerator = mod(numerator * -BigInt(otherId));
        denominator = mod(denominator * BigInt(memberId - otherId));
    }
    return mod(numerator * inverse(denominator));
}

function recoverSmallPlaintext(point, maximum) {
    let current = Point.ZERO;
    for (let value = 0; value <= maximum; value += 1) {
        if (current.equals(point)) return value;
        current = current.add(GENERATOR);
    }
    throw new Error("Tally liegt ausserhalb des erwarteten Bereichs");
}

function createThresholdTallyPayload(election, ballotPayloads, memberFiles) {
    const uniqueMembers = new Map();
    for (const file of memberFiles) {
        validateCommitteeShare(election, file);
        uniqueMembers.set(Number(file.member_id), file);
    }
    const selected = Array.from(uniqueMembers.values()).sort(
        (left, right) => Number(left.member_id) - Number(right.member_id),
    );
    const threshold = Number(election.committee.threshold);
    if (selected.length < threshold) throw new Error(`Mindestens ${threshold} unterschiedliche Shares erforderlich`);

    const encryptedTally = aggregateEncryptedBallots(ballotPayloads, election.options.length);
    const allPartialShares = [];
    const plaintextTally = [];
    for (let candidateIndex = 0; candidateIndex < encryptedTally.candidate_count; candidateIndex += 1) {
        const ciphertextPayload = encryptedTally.ciphertexts[candidateIndex];
        const candidateShares = selected.map(file =>
            partialDecryption(election.committee, file, ciphertextPayload, candidateIndex),
        );
        allPartialShares.push(...candidateShares);

        const thresholdShares = candidateShares.slice(0, threshold);
        const memberIds = thresholdShares.map(item => item.member_id);
        let combinedFactor = Point.ZERO;
        for (const share of thresholdShares) {
            const coefficient = lagrangeCoefficient(share.member_id, memberIds);
            combinedFactor = combinedFactor.add(pointFromHex(share.decryption_factor).multiply(coefficient));
        }
        const plaintextPoint = pointFromHex(ciphertextPayload.b).subtract(combinedFactor);
        plaintextTally.push(recoverSmallPlaintext(plaintextPoint, ballotPayloads.length));
    }
    return {
        election_id: election.election_id,
        encrypted_tally: encryptedTally,
        published_result: {
            plaintext_tally: plaintextTally,
            partial_decryption_shares: allPartialShares,
        },
    };
}

export {
    aggregateEncryptedBallots,
    committeeFingerprint,
    createEncryptedVotePayload,
    createThresholdTallyPayload,
    deriveVoterCredentials,
    encryptCandidateVote,
    generateCommittee,
    hashText,
    validateCommitteeShare,
};
