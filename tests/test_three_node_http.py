import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from voting_system.crypto_petlib_elgamal_tally import generate_committee_key_shares
from voting_system.distributed_blockchain import generate_validator_keypair


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    """Ask the OS for an unused local TCP port."""
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def request_json(base_url: str, path: str, method: str = "GET", payload=None, headers=None):
    """Small standard-library HTTP client used by the process integration test."""
    data = json.dumps(payload).encode() if payload is not None else None
    request_headers = dict(headers or {})
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{base_url}{path}", data=data, method=method, headers=request_headers,
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


class ThreeNodeHttpIntegrationTest(unittest.TestCase):
    """Run three real FastAPI processes and synchronize a signed block over HTTP."""

    def test_validator_block_reaches_two_observer_processes(self):
        ports = [free_port() for _ in range(3)]
        urls = [f"http://127.0.0.1:{port}" for port in ports]
        keys = generate_validator_keypair()
        validators = {"node1": keys["public_key"]}
        processes = []

        with tempfile.TemporaryDirectory() as root:
            try:
                for index, (port, url) in enumerate(zip(ports, urls), start=1):
                    env = os.environ.copy()
                    env.update({
                        "NODE_ID": f"node{index}",
                        "PORT": str(port),
                        "DATA_DIR": str(Path(root) / f"node{index}"),
                        "VALIDATORS_JSON": json.dumps(validators),
                        "PEERS": ",".join(peer for peer in urls if peer != url),
                        "V2_ADMIN_KEY": "admin-test",
                        "V2_NODE_KEY": "node-test",
                        "PYTHONPATH": str(PROJECT_ROOT),
                    })
                    if index == 1:
                        env["NODE_PRIVATE_KEY"] = keys["private_key"]
                    else:
                        env.pop("NODE_PRIVATE_KEY", None)
                    processes.append(subprocess.Popen(
                        [str(PROJECT_ROOT / ".venv/bin/python"), "-m", "voting_system.node_server"],
                        cwd=PROJECT_ROOT,
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    ))

                deadline = time.monotonic() + 12
                for url in urls:
                    while True:
                        try:
                            request_json(url, "/api/v2/node/info")
                            break
                        except (urllib.error.URLError, ConnectionError):
                            if time.monotonic() >= deadline:
                                self.fail(f"Node did not start: {url}")
                            time.sleep(0.05)

                committee = generate_committee_key_shares(3, 2)
                election = {
                    "election_id": "http-election",
                    "title": "HTTP Process Test",
                    "options": ["Alice", "Bob"],
                    "start_time": "2026-01-01T00:00:00+00:00",
                    "end_time": "2027-01-01T00:00:00+00:00",
                    "committee": committee.public_payload(),
                }
                request_json(
                    urls[0], "/api/v2/transactions", "POST",
                    {"type": "create_election", "payload": election},
                    {"X-Admin-Key": "admin-test"},
                )
                request_json(
                    urls[0], "/api/v2/blocks/mine", "POST", headers={"X-Node-Key": "node-test"},
                )
                for observer_url in urls[1:]:
                    result = request_json(
                        observer_url, "/api/v2/sync", "POST", headers={"X-Node-Key": "node-test"},
                    )
                    self.assertTrue(result["adopted_chain"])

                infos = [request_json(url, "/api/v2/node/info") for url in urls]
                self.assertEqual({info["chain_length"] for info in infos}, {2})
                self.assertEqual(len({info["latest_block_hash"] for info in infos}), 1)
            finally:
                for process in processes:
                    process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()


if __name__ == "__main__":
    unittest.main()
