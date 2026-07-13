"""
Start a small local v2 demo network with three separate nodes.

This script is intentionally presentation-oriented. It hides the long manual
environment-variable command lines, but it still prints every relevant setting
so the demo remains transparent:

- node1 runs on port 5001 and owns the PoA validator private key.
- node2 runs on port 5002 as an observer node.
- node3 runs on port 5003 as another observer node.
- every node gets its own JSON data directory.
- every node knows the other two nodes as peers.

Use `--reset` before a presentation to remove only the generated demo-network
state under `.node-data/v2-demo-network`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from voting_system.distributed_blockchain import generate_validator_keypair


DEFAULT_DATA_ROOT = PROJECT_ROOT / ".node-data" / "v2-demo-network"
CONFIG_FILE = "network-config.json"


def safe_reset_path(path: Path) -> bool:
    """
    Return whether a reset target is inside this project's `.node-data` folder.

    The script has a reset flag because old validator keys and old chains can
    break a presentation. This guard prevents an accidental custom path from
    deleting unrelated project files.
    """
    allowed_root = (PROJECT_ROOT / ".node-data").resolve()
    try:
        path.resolve().relative_to(allowed_root)
        return True
    except ValueError:
        return False


def load_or_create_config(data_root: Path, base_port: int) -> dict:
    """
    Load the stable demo-network key config, or create it on first run.

    Validator signatures must keep using the same public/private key pair while
    an existing chain is present. Regenerating keys without resetting data would
    make old blocks fail signature validation.
    """
    data_root.mkdir(parents=True, exist_ok=True)
    config_path = data_root / CONFIG_FILE
    if config_path.exists():
        return json.loads(config_path.read_text())

    validator_keys = generate_validator_keypair()
    nodes = [
        {"node_id": "node1", "port": base_port, "validator": True},
        {"node_id": "node2", "port": base_port + 1, "validator": False},
        {"node_id": "node3", "port": base_port + 2, "validator": False},
    ]
    config = {
        "validators": {"node1": validator_keys["public_key"]},
        "validator_private_key": validator_keys["private_key"],
        "nodes": nodes,
    }
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=True))
    return config


def build_node_env(config: dict, node_config: dict, data_root: Path) -> dict:
    """
    Build the environment consumed by `DistributedVotingBlockchain.from_env`.

    Only node1 receives `NODE_PRIVATE_KEY`, so only node1 is allowed to mine
    PoA blocks. Observer nodes still validate the signatures and transaction
    rules when they sync or receive blocks.
    """
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    node_id = node_config["node_id"]
    node_url_by_id = {
        item["node_id"]: f"http://127.0.0.1:{item['port']}"
        for item in config["nodes"]
    }
    peer_urls = [
        url
        for peer_id, url in node_url_by_id.items()
        if peer_id != node_id
    ]
    env.update(
        {
            "NODE_ID": node_id,
            "PORT": str(node_config["port"]),
            "DATA_DIR": str(data_root / node_id),
            "VALIDATORS_JSON": json.dumps(config["validators"]),
            "PEERS": ",".join(peer_urls),
            "V2_ADMIN_KEY": "dev_admin_key",
            "V2_NODE_KEY": "dev_node_key",
            "PYTHONUNBUFFERED": "1",
            "PYTHONPATH": str(PROJECT_ROOT) if not existing_pythonpath else f"{PROJECT_ROOT}{os.pathsep}{existing_pythonpath}",
        }
    )
    if node_config["validator"]:
        env["NODE_PRIVATE_KEY"] = config["validator_private_key"]
    else:
        env.pop("NODE_PRIVATE_KEY", None)
    return env


def start_node(config: dict, node_config: dict, data_root: Path) -> subprocess.Popen:
    """
    Start one FastAPI process for one node and return the subprocess handle.

    The command uses the current Python interpreter so it works both inside the
    project's virtual environment and from a normal shell.
    """
    env = build_node_env(config, node_config, data_root)
    node_id = node_config["node_id"]
    port = node_config["port"]
    print(f"\nStarting {node_id} on http://127.0.0.1:{port}")
    print(f"  DATA_DIR={env['DATA_DIR']}")
    print(f"  PEERS={env['PEERS']}")
    print(f"  VALIDATOR={'yes' if node_config['validator'] else 'no'}")
    return subprocess.Popen([sys.executable, "-m", "voting_system.blockchain_v1"], cwd=PROJECT_ROOT, env=env)


def terminate_processes(processes: list[subprocess.Popen]) -> None:
    """Stop all child node processes as cleanly as possible."""
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    """Parse CLI flags, prepare config, start all nodes, and keep them alive."""
    parser = argparse.ArgumentParser(description="Start three local v2 demo blockchain nodes.")
    parser.add_argument("--base-port", type=int, default=5001, help="Port for node1; node2/3 use the next ports.")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT, help="Directory for generated node state.")
    parser.add_argument("--reset", action="store_true", help="Delete the generated demo-network state before starting.")
    args = parser.parse_args()

    data_root = args.data_root
    if args.reset:
        if not safe_reset_path(data_root):
            print(f"Refusing to reset outside .node-data: {data_root}", file=sys.stderr)
            return 2
        if data_root.exists():
            print(f"Resetting demo network state: {data_root}")
            shutil.rmtree(data_root)

    config = load_or_create_config(data_root, args.base_port)
    for index, node in enumerate(config["nodes"]):
        node["port"] = args.base_port + index

    urls = {
        node["node_id"]: f"http://127.0.0.1:{node['port']}"
        for node in config["nodes"]
    }

    print("\nV2 demo network")
    print("=" * 60)
    print(f"Dashboard node1: {urls['node1']}/dashboard")
    print(f"Voter client:     {urls['node1']}/voter")
    print(f"Committee client: {urls['node1']}/committee")
    print(f"Observer node2:   {urls['node2']}/dashboard")
    print(f"Observer node3:   {urls['node3']}/dashboard")
    print("=" * 60)

    processes: list[subprocess.Popen] = []

    def handle_shutdown(_signum, _frame):
        print("\nStopping demo network...")
        terminate_processes(processes)
        raise SystemExit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    try:
        for node in config["nodes"]:
            processes.append(start_node(config, node, data_root))
            time.sleep(0.5)

        print("\nAll nodes started. Press Ctrl+C to stop the demo network.")
        while True:
            stopped = [process for process in processes if process.poll() is not None]
            if stopped:
                print("One node exited unexpectedly. Stopping the remaining nodes.", file=sys.stderr)
                terminate_processes(processes)
                return 1
            time.sleep(1)
    finally:
        terminate_processes(processes)


if __name__ == "__main__":
    raise SystemExit(main())
