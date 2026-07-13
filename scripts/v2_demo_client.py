#!/usr/bin/env python3
"""
Small demo client for the distributed v2 voting chain.

The node (`voting_system.node_server` + `/api/v2`) is deliberately separate from this
client. That mirrors the real architecture:

- the node stores and validates chain data,
- the voter client encrypts a ballot and submits a vote transaction,
- the committee client keeps private shares and later publishes the tally.

This script is not a production wallet or committee tool. It is a presentation
helper that makes the current code path visible without forcing you to handcraft
large JSON payloads in curl.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import sys
from petlib.bn import Bn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from voting_system.crypto_petlib_elgamal_tally import (
    CommitteeKeyShares,
    CommitteeMemberShare,
    EncryptedBallot,
    PetlibPublicKey,
    aggregate_encrypted_ballots,
    encrypt_candidate_vote,
    generate_committee_key_shares,
    public_shares_from_payload,
    publish_threshold_tally_result,
)


DEFAULT_STATE_FILE = str(PROJECT_ROOT / ".node-data" / "v2-demo-client-state.json")


def sha256_hex(value: str) -> str:
    """Create deterministic demo commitments and nullifiers."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def request_json(
    api_url: str,
    path: str,
    method: str = "GET",
    payload: Any | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """
    Send JSON to the v2 API using only the Python standard library.

    Keeping this dependency-free makes the client easy to run in the same venv
    as the project. API errors are surfaced as Python exceptions with the server
    response body attached where possible.
    """
    url = f"{api_url.rstrip('/')}{path}"
    data = None
    request_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {body}") from exc


def submit_transaction(api_url: str, tx_type: str, payload: dict, admin_key: str = "") -> dict:
    """Submit one v2 transaction to a node mempool."""
    return request_json(
        api_url,
        "/api/v2/transactions",
        method="POST",
        payload={"type": tx_type, "payload": payload},
        headers={"X-Admin-Key": admin_key} if tx_type in {"create_election", "finalize_election"} else None,
    )


def mine_block(api_url: str, node_key: str) -> dict:
    """Ask a validator node to mine/sign the current mempool."""
    return request_json(api_url, "/api/v2/blocks/mine", method="POST", headers={"X-Node-Key": node_key})


def save_committee(state_file: Path, committee: CommitteeKeyShares, election_id: str, options: list[str]) -> None:
    """
    Persist private committee shares for the demo committee client.

    The manifest contains only public committee data. Every private member
    share is written to a separate file beside it so the files can be handed to
    different committee clients.
    """
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "election_id": election_id,
        "options": options,
        "committee_public_payload": committee.public_payload(),
    }
    state_file.write_text(json.dumps(state, indent=2, sort_keys=True))
    share_dir = state_file.with_name(f"{state_file.stem}-committee-shares")
    share_dir.mkdir(parents=True, exist_ok=True)
    for member in committee.member_shares:
        share_path = share_dir / f"member-{member.member_id}.json"
        share_path.write_text(json.dumps({
            "election_id": election_id,
            "member_id": member.member_id,
            "share": str(int(member.share)),
        }, indent=2, sort_keys=True))


def load_committee(state_file: Path) -> tuple[CommitteeKeyShares, dict]:
    """
    Load the demo committee state and reconstruct Petlib objects.

    The public shares are reconstructed from the public payload. Private share
    scalars are reconstructed from decimal strings that are stored only in the
    local demo state file.
    """
    state = json.loads(state_file.read_text())
    public_payload = state["committee_public_payload"]
    public_key = PetlibPublicKey.from_payload(public_payload)
    public_shares = public_shares_from_payload(public_key, public_payload)
    share_dir = state_file.with_name(f"{state_file.stem}-committee-shares")
    private_payloads = [json.loads(path.read_text()) for path in sorted(share_dir.glob("member-*.json"))]
    member_shares = [
        CommitteeMemberShare(
            member_id=int(member["member_id"]),
            share=Bn.from_decimal(member["share"]),
            public_share=public_shares[int(member["member_id"])],
        )
        for member in private_payloads
    ]
    committee = CommitteeKeyShares(
        public_key=public_key,
        threshold=int(public_payload["threshold"]),
        member_count=int(public_payload["member_count"]),
        member_shares=member_shares,
    )
    return committee, state


def create_election(args) -> None:
    """Generate a committee and submit a create_election transaction."""
    options = [option.strip() for option in args.options.split(",") if option.strip()]
    if len(options) < 2:
        raise SystemExit("At least two comma-separated options are required.")

    committee = generate_committee_key_shares(args.member_count, args.threshold)
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "election_id": args.election_id,
        "title": args.title,
        "options": options,
        "start_time": now.isoformat(),
        "end_time": (now + dt.timedelta(minutes=args.duration_minutes)).isoformat(),
        "committee": committee.public_payload(),
    }
    save_committee(Path(args.state_file), committee, args.election_id, options)
    response = submit_transaction(args.api_url, "create_election", payload, args.admin_key)
    print_json("create_election accepted", response)
    if args.mine:
        print_json("block mined", mine_block(args.api_url, args.node_key))


def register_voter(args) -> None:
    """Submit a demo eligibility registration transaction."""
    _, state = load_committee(Path(args.state_file))
    payload = {
        "election_id": state["election_id"],
        "commitment_hash": sha256_hex(args.voter),
    }
    response = submit_transaction(args.api_url, "register_voter", payload)
    print_json("register_voter accepted", response)
    if args.mine:
        print_json("block mined", mine_block(args.api_url, args.node_key))


def cast_vote(args) -> None:
    """Encrypt one candidate selection and submit it as a v2 vote transaction."""
    committee, state = load_committee(Path(args.state_file))
    option_count = len(state["options"])
    if args.candidate_index < 0 or args.candidate_index >= option_count:
        raise SystemExit(f"candidate_index must be between 0 and {option_count - 1}.")

    ballot = encrypt_candidate_vote(committee.public_key, args.candidate_index, option_count)
    commitment = sha256_hex(args.voter)
    payload = {
        "election_id": state["election_id"],
        "nullifier_hash": sha256_hex(f"{state['election_id']}:{commitment}:nullifier"),
        "encrypted_ballot": ballot.to_chain_payload(),
        "eligibility_proof_placeholder": {
            "type": "deterministic-nullifier-demo-v2",
            "accepted": True,
            "commitment_hash": sha256_hex(args.voter),
        },
        "ballot_validity_proof_placeholder": {
            "type": "local-one-hot-encryption-demo-v2",
            "accepted": True,
        },
    }
    response = submit_transaction(args.api_url, "cast_encrypted_vote", payload)
    print_json("cast_encrypted_vote accepted", response)
    if args.mine:
        print_json("block mined", mine_block(args.api_url, args.node_key))


def finalize_election(args) -> None:
    """Submit a transaction that marks the election ready for tally publication."""
    _, state = load_committee(Path(args.state_file))
    response = submit_transaction(
        args.api_url,
        "finalize_election",
        {"election_id": state["election_id"]},
        args.admin_key,
    )
    print_json("finalize_election accepted", response)
    if args.mine:
        print_json("block mined", mine_block(args.api_url, args.node_key))


def publish_tally(args) -> None:
    """
    Load encrypted ballots from the node, decrypt the aggregate with threshold
    shares, and submit the public tally result transaction.
    """
    committee, state = load_committee(Path(args.state_file))
    election_id = state["election_id"]
    ballots_response = request_json(args.api_url, f"/api/v2/elections/{election_id}/encrypted-ballots")
    ballot_payloads = ballots_response["encrypted_ballots"]
    if not ballot_payloads:
        raise SystemExit("No encrypted ballots are committed on-chain yet.")

    encrypted_ballots = [
        EncryptedBallot.from_chain_payload(committee.public_key, ballot_payload)
        for ballot_payload in ballot_payloads
    ]
    encrypted_tally = aggregate_encrypted_ballots(committee.public_key, encrypted_ballots)
    member_ids = [int(value.strip()) for value in args.members.split(",") if value.strip()]
    published_result = publish_threshold_tally_result(
        committee=committee,
        encrypted_tally=encrypted_tally,
        participating_member_ids=member_ids,
        max_plaintext=len(encrypted_ballots),
    )
    payload = {
        "election_id": election_id,
        "encrypted_tally": encrypted_tally.to_chain_payload(),
        "published_result": published_result.to_payload(),
    }
    response = submit_transaction(args.api_url, "publish_tally_result", payload)
    print_json("publish_tally_result accepted", response)
    if args.mine:
        print_json("block mined", mine_block(args.api_url, args.node_key))


def run_full_demo(args) -> None:
    """
    Run the current complete happy-path demo against one validator node.

    This is useful during presentations: start the node, open the dashboard,
    then run this command and watch mempool/chain/election/verify panels change.
    """
    create_election(args)
    for voter in args.voters.split(","):
        args.voter = voter.strip()
        register_voter(args)
    for vote_spec in args.votes.split(","):
        voter, candidate_index = vote_spec.split(":")
        args.voter = voter.strip()
        args.candidate_index = int(candidate_index)
        cast_vote(args)
    finalize_election(args)
    publish_tally(args)
    verification = request_json(args.api_url, f"/api/v2/elections/{args.election_id}/verify")
    print_json("public verification", verification)


def print_json(title: str, value: Any) -> None:
    """Print a labeled JSON block for terminal demos."""
    print(f"\n=== {title} ===")
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    """Define the demo client's subcommands."""
    parser = argparse.ArgumentParser(description="Demo client for the v2 distributed voting chain.")
    parser.add_argument("--api-url", default="http://127.0.0.1:5001")
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--admin-key", default="dev_admin_key")
    parser.add_argument("--node-key", default="dev_node_key")

    subcommands = parser.add_subparsers(dest="command", required=True)

    create = subcommands.add_parser("create-election")
    create.add_argument("--election-id", default="demo-election")
    create.add_argument("--title", default="Demo Election")
    create.add_argument("--options", default="Alice,Bob,Charlie")
    create.add_argument("--duration-minutes", type=int, default=60)
    create.add_argument("--member-count", type=int, default=5)
    create.add_argument("--threshold", type=int, default=3)
    create.add_argument("--mine", action="store_true")
    create.set_defaults(func=create_election)

    register = subcommands.add_parser("register")
    register.add_argument("--voter", required=True)
    register.add_argument("--mine", action="store_true")
    register.set_defaults(func=register_voter)

    vote = subcommands.add_parser("vote")
    vote.add_argument("--voter", required=True)
    vote.add_argument("--candidate-index", type=int, required=True)
    vote.add_argument("--mine", action="store_true")
    vote.set_defaults(func=cast_vote)

    finalize = subcommands.add_parser("finalize")
    finalize.add_argument("--mine", action="store_true")
    finalize.set_defaults(func=finalize_election)

    publish = subcommands.add_parser("publish-tally")
    publish.add_argument("--members", default="1,2,3")
    publish.add_argument("--mine", action="store_true")
    publish.set_defaults(func=publish_tally)

    full = subcommands.add_parser("full-demo")
    full.add_argument("--election-id", default="demo-election")
    full.add_argument("--title", default="Demo Election")
    full.add_argument("--options", default="Alice,Bob,Charlie")
    full.add_argument("--duration-minutes", type=int, default=60)
    full.add_argument("--member-count", type=int, default=5)
    full.add_argument("--threshold", type=int, default=3)
    full.add_argument("--members", default="1,2,3")
    full.add_argument("--voters", default="alice,bob,charlie")
    full.add_argument("--votes", default="alice:0,bob:1,charlie:1")
    full.add_argument("--mine", action="store_true", default=True)
    full.set_defaults(func=run_full_demo)

    return parser


def main() -> None:
    """Parse CLI arguments and run the selected demo action."""
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
