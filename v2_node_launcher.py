#!/usr/bin/env python3
"""
Small GUI launcher for v2 distributed voting nodes.

The v2 node still needs explicit configuration: node id, port, data directory,
validator private key, validator registry and peers. Typing that as a long shell
command is useful once for understanding the architecture, but it is clumsy for
presentations. This launcher keeps the configuration visible while turning it
into form fields and buttons.

The launcher does not hide what happens:
- the environment variables used by the node are shown in the form,
- generated keys are visible,
- the exact node process output is streamed into the log,
- the dashboard is still a separate browser page that talks to the node API.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from distributed_blockchain import DistributedVotingBlockchain, generate_validator_keypair


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_ADMIN_KEY = "dev_admin_key"


class V2NodeLauncher(tk.Tk):
    """
    Tkinter launcher for one local v2 node process.

    The class owns the subprocess handle so the GUI can start and stop the node.
    It deliberately starts only one process at a time; for multiple nodes you can
    open the launcher twice or change the fields and start another terminal.
    """

    def __init__(self) -> None:
        super().__init__()
        self.title("V2 Distributed Voting Node Launcher")
        self.geometry("1040x820")
        self.minsize(900, 680)
        self.process: subprocess.Popen | None = None

        self.node_id = tk.StringVar(value="node1")
        self.port = tk.StringVar(value="5001")
        self.data_dir = tk.StringVar(value=".node-data/node1")
        self.private_key = tk.StringVar(value="")
        self.public_key = tk.StringVar(value="")
        self.validators_json = tk.StringVar(value="")
        self.peers = tk.StringVar(value="")
        self.admin_key = tk.StringVar(value=DEFAULT_ADMIN_KEY)

        self._build_ui()
        self._generate_key_if_empty()

    def _build_ui(self) -> None:
        """Create all form fields, action buttons and the process log."""
        root = ttk.Frame(self, padding=18)
        root.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(
            root,
            text="V2 Node starten, ohne Env-Variablen per Hand zu tippen",
            font=("TkDefaultFont", 18, "bold"),
        )
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            root,
            text=(
                "Die Konfiguration bleibt sichtbar: Node-ID, Port, Keys, Validatoren, "
                "Data-Dir und Peers werden als Felder gesetzt und dann als Env an blockchainV1.py uebergeben."
            ),
            wraplength=940,
        )
        subtitle.pack(anchor=tk.W, pady=(4, 16))

        form = ttk.Frame(root)
        form.pack(fill=tk.X)

        self._entry(form, "Node ID", self.node_id, 0, 0)
        self._entry(form, "Port", self.port, 0, 1)
        self._entry(form, "Data dir", self.data_dir, 1, 0)
        self._entry(form, "Admin key", self.admin_key, 1, 1)
        self._entry(form, "Peers, comma separated", self.peers, 2, 0, columnspan=2)

        key_box = ttk.LabelFrame(root, text="Validator Key")
        key_box.pack(fill=tk.X, pady=(16, 0))
        self._entry(key_box, "Private key hex", self.private_key, 0, 0, columnspan=2)
        self._entry(key_box, "Public key hex", self.public_key, 1, 0, columnspan=2)

        key_buttons = ttk.Frame(key_box)
        key_buttons.grid(row=2, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=(4, 10))
        ttk.Button(key_buttons, text="Neuen Validator-Key erzeugen", command=self.generate_key).pack(side=tk.LEFT)
        ttk.Button(key_buttons, text="Single-Validator JSON setzen", command=self.set_single_validator_json).pack(side=tk.LEFT, padx=8)

        validators_box = ttk.LabelFrame(root, text="VALIDATORS_JSON")
        validators_box.pack(fill=tk.BOTH, expand=False, pady=(16, 0))
        validators_help = ttk.Label(
            validators_box,
            text=(
                "Diese Liste sagt allen Nodes, welche Validatoren Bloeke signieren duerfen. "
                "Fuer eine lokale Demo reicht ein Eintrag fuer diese Node."
            ),
            wraplength=940,
        )
        validators_help.pack(anchor=tk.W, padx=10, pady=(8, 4))
        self.validators_text = scrolledtext.ScrolledText(validators_box, height=6, wrap=tk.WORD)
        self.validators_text.pack(fill=tk.X, padx=10, pady=(0, 10))

        actions = ttk.Frame(root)
        actions.pack(fill=tk.X, pady=16)
        ttk.Button(actions, text="Node starten", command=self.start_node).pack(side=tk.LEFT)
        ttk.Button(actions, text="Node stoppen", command=self.stop_node).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Lokalen Node-State resetten", command=self.reset_data_dir).pack(side=tk.LEFT)
        ttk.Button(actions, text="Dashboard oeffnen", command=self.open_dashboard).pack(side=tk.LEFT)
        ttk.Button(actions, text="API Docs oeffnen", command=self.open_docs).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Demo-Client Befehl anzeigen", command=self.show_demo_command).pack(side=tk.LEFT)

        env_box = ttk.LabelFrame(root, text="Node Log")
        env_box.pack(fill=tk.BOTH, expand=True)
        self.log = scrolledtext.ScrolledText(env_box, height=14, wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for column in range(2):
            form.columnconfigure(column, weight=1)
            key_box.columnconfigure(column, weight=1)

    def _entry(
        self,
        parent: ttk.Frame,
        label: str,
        variable: tk.StringVar,
        row: int,
        column: int,
        columnspan: int = 1,
    ) -> None:
        """Add a labeled entry to a grid-based form."""
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=column, columnspan=columnspan, sticky=tk.EW, padx=10, pady=6)
        ttk.Label(frame, text=label).pack(anchor=tk.W)
        ttk.Entry(frame, textvariable=variable).pack(fill=tk.X)

    def _generate_key_if_empty(self) -> None:
        """Create an initial demo key so the launcher works immediately."""
        if not self.private_key.get() or not self.public_key.get():
            self.generate_key()

    def generate_key(self) -> None:
        """Generate a fresh Ed25519 validator keypair and fill the form."""
        keys = generate_validator_keypair()
        self.private_key.set(keys["private_key"])
        self.public_key.set(keys["public_key"])
        self.set_single_validator_json()

    def set_single_validator_json(self) -> None:
        """Fill VALIDATORS_JSON with the current node as the only validator."""
        validators = {self.node_id.get().strip() or "node1": self.public_key.get().strip()}
        pretty = json.dumps(validators, indent=2, sort_keys=True)
        self.validators_text.delete("1.0", tk.END)
        self.validators_text.insert(tk.END, pretty)
        self.validators_json.set(pretty)

    def start_node(self) -> None:
        """
        Start blockchainV1.py with the visible form values as environment.

        The node is launched as a subprocess using the same Python interpreter
        that runs the launcher, so it uses the same venv/dependencies.
        """
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Node laeuft bereits", "Die Node ist schon gestartet.")
            return

        try:
            validators_json = self.validators_text.get("1.0", tk.END).strip()
            validators = json.loads(validators_json)
        except json.JSONDecodeError as exc:
            messagebox.showerror("VALIDATORS_JSON ungueltig", str(exc))
            return

        if not self._preflight_node_state(validators):
            return

        env = os.environ.copy()
        env.update(
            {
                "NODE_ID": self.node_id.get().strip(),
                "NODE_PRIVATE_KEY": self.private_key.get().strip(),
                "VALIDATORS_JSON": validators_json,
                "DATA_DIR": self.data_dir.get().strip(),
                "PORT": self.port.get().strip(),
                "ADMIN_KEY": self.admin_key.get().strip(),
                "PEERS": self.peers.get().strip(),
            }
        )

        self._log_line("Starting node with visible configuration:")
        for key in ["NODE_ID", "PORT", "DATA_DIR", "PEERS", "VALIDATORS_JSON"]:
            self._log_line(f"  {key}={env[key]}")

        self.process = subprocess.Popen(
            [sys.executable, "blockchainV1.py"],
            cwd=PROJECT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self._stream_process_output, daemon=True).start()

    def _preflight_node_state(self, validators: dict) -> bool:
        """
        Check whether the existing DATA_DIR can be opened with the current keys.

        If a user generates a fresh validator key but reuses `.node-data/node1`,
        the old blocks are still signed by the previous key. The node is correct
        to reject that chain. For demos, this method catches the mismatch before
        spawning the process and offers to reset the local node state.
        """
        data_dir = self._data_dir_path()
        if not (data_dir / "chain.json").exists():
            return True

        try:
            DistributedVotingBlockchain(
                node_id=self.node_id.get().strip(),
                data_dir=data_dir,
                validators={str(key): str(value) for key, value in validators.items()},
                private_key_hex=self.private_key.get().strip(),
                peers=[peer.strip() for peer in self.peers.get().split(",") if peer.strip()],
            )
            return True
        except ValueError as exc:
            reset = messagebox.askyesno(
                "Lokaler Chain-State passt nicht",
                (
                    f"Das Data-Dir {data_dir} enthaelt bereits eine Chain, "
                    "die nicht zur aktuellen Validator-Konfiguration passt.\n\n"
                    f"Grund: {exc}\n\n"
                    "Das passiert meistens, wenn du einen neuen Validator-Key "
                    "erzeugt hast, aber das alte DATA_DIR weiterverwendest.\n\n"
                    "Lokalen Demo-State jetzt loeschen und frisch starten?"
                ),
            )
            if reset:
                self._reset_data_dir_path(data_dir)
                self._log_line(f"Reset local node state: {data_dir}")
                return True
            self._log_line("Start cancelled: existing DATA_DIR does not validate with current keys.")
            return False

    def reset_data_dir(self) -> None:
        """
        Delete the selected local node state directory after confirmation.

        This removes chain.json, mempool.json, peers.json and demo committee
        files for this node. It does not touch source code. It is the right
        action when you want to start a fresh demo with a new validator key.
        """
        if self.process and self.process.poll() is None:
            messagebox.showerror("Node laeuft", "Stoppe die Node zuerst, bevor du den State resettest.")
            return

        data_dir = self._data_dir_path()
        if not data_dir.exists():
            self._log_line(f"No local state to reset: {data_dir}")
            return

        if not messagebox.askyesno("Lokalen State loeschen?", f"{data_dir} wirklich loeschen?"):
            return
        self._reset_data_dir_path(data_dir)
        self._log_line(f"Reset local node state: {data_dir}")

    def _data_dir_path(self) -> Path:
        """Resolve the DATA_DIR field relative to the project directory."""
        path = Path(self.data_dir.get().strip())
        if not path.is_absolute():
            path = PROJECT_DIR / path
        return path

    def _reset_data_dir_path(self, data_dir: Path) -> None:
        """
        Remove one local DATA_DIR, guarded so the launcher cannot erase the repo.

        The launcher only deletes directories inside `.node-data` by design.
        This keeps the reset action scoped to demo runtime data.
        """
        resolved = data_dir.resolve()
        allowed_root = (PROJECT_DIR / ".node-data").resolve()
        if allowed_root not in [resolved, *resolved.parents]:
            raise ValueError("Refusing to delete a DATA_DIR outside .node-data")
        shutil.rmtree(resolved, ignore_errors=True)

    def stop_node(self) -> None:
        """Terminate the running node process, if any."""
        if not self.process or self.process.poll() is not None:
            self._log_line("No running node process.")
            return
        self._log_line("Stopping node...")
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._log_line("Node did not stop in time; killing process.")
            self.process.kill()
        self._log_line("Node stopped.")

    def open_dashboard(self) -> None:
        """Open the browser dashboard and point it at this node's port."""
        dashboard = PROJECT_DIR / "frontend_v2.html"
        webbrowser.open(dashboard.resolve().as_uri())
        self._log_line(f"Dashboard opened. Set API URL to http://127.0.0.1:{self.port.get().strip()}")

    def open_docs(self) -> None:
        """Open FastAPI docs for the running node."""
        webbrowser.open(f"http://127.0.0.1:{self.port.get().strip()}/docs")

    def show_demo_command(self) -> None:
        """Show the simplified demo-client command for the current node."""
        command = f"{sys.executable} v2_demo_client.py --api-url http://127.0.0.1:{self.port.get().strip()} full-demo"
        self._log_line("Run this in a second terminal for a full visible demo:")
        self._log_line(command)

    def _stream_process_output(self) -> None:
        """Forward the node subprocess output into the GUI log."""
        assert self.process is not None
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self._log_line(line.rstrip())
        self._log_line(f"Node process exited with code {self.process.poll()}.")

    def _log_line(self, line: str) -> None:
        """Append one line to the GUI log from any thread."""
        self.log.after(0, self._append_log_line, line)

    def _append_log_line(self, line: str) -> None:
        """Append one line to the Tk text widget on the UI thread."""
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)

    def destroy(self) -> None:
        """Stop the node process when the launcher window closes."""
        self.stop_node()
        super().destroy()


def main() -> None:
    """Run the launcher GUI."""
    app = V2NodeLauncher()
    app.mainloop()


if __name__ == "__main__":
    main()
