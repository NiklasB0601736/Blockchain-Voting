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

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from voting_system.distributed_blockchain import DistributedVotingBlockchain, generate_validator_keypair
from voting_system.tls import ensure_development_tls_material

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
        self.voter_client_process: subprocess.Popen | None = None
        self.demo_network_process: subprocess.Popen | None = None
        self.tls_paths = ensure_development_tls_material()

        self.node_id = tk.StringVar(value="node1")
        self.port = tk.StringVar(value="5001")
        self.data_dir = tk.StringVar(value=".node-data/node1")
        self.demo_network_base_port = tk.StringVar(value="5001")
        self.voter_client_port = tk.StringVar(value="7000")
        self.demo_network_reset = tk.BooleanVar(value=True)
        self.private_key = tk.StringVar(value="")
        self.public_key = tk.StringVar(value="")
        self.validators_json = tk.StringVar(value="")
        self.peers = tk.StringVar(value="")
        self.admin_key = tk.StringVar(value=DEFAULT_ADMIN_KEY)
        self.node_api_key = tk.StringVar(value="dev_node_key")

        self._build_ui()
        self._generate_key_if_empty()

    def _build_ui(self) -> None:
        """
        Create the scrollable form, action buttons and process log.

        Tkinter frames do not scroll by themselves. A Canvas therefore acts as
        the viewport and contains one normal ttk.Frame with all existing
        controls. The vertical scrollbar moves the Canvas viewport, while the
        inner frame can continue using the familiar pack/grid layout.
        """
        scroll_container = ttk.Frame(self)
        scroll_container.pack(fill=tk.BOTH, expand=True)

        self.scroll_canvas = tk.Canvas(scroll_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(
            scroll_container,
            orient=tk.VERTICAL,
            command=self.scroll_canvas.yview,
        )
        self.scroll_canvas.configure(yscrollcommand=scrollbar.set)
        self.scroll_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        root = ttk.Frame(self.scroll_canvas, padding=18)
        self.scroll_content_window = self.scroll_canvas.create_window(
            (0, 0),
            window=root,
            anchor=tk.NW,
        )

        # Whenever controls change the required content height, update the
        # Canvas scroll region. When the window width changes, stretch the inner
        # form to the full visible width so fields do not become unnecessarily
        # narrow or leave an empty strip beside the scrollbar.
        root.bind("<Configure>", self._update_scroll_region)
        self.scroll_canvas.bind("<Configure>", self._resize_scroll_content)

        # Mouse-wheel events originate on the child control under the pointer,
        # not necessarily on the Canvas. Binding at application level keeps
        # scrolling available over labels, entries and buttons. Text widgets
        # are excluded in `_on_mousewheel` so both log areas retain their own
        # independent scrolling behavior.
        self.bind_all("<MouseWheel>", self._on_mousewheel, add="+")
        self.bind_all("<Button-4>", self._on_mousewheel, add="+")
        self.bind_all("<Button-5>", self._on_mousewheel, add="+")

        title = ttk.Label(
            root,
            text="V2 Node Controller",
            font=("TkDefaultFont", 18, "bold"),
        )
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            root,
            text=(
                "Single Node konfigurieren oder lokales Demo-Netzwerk starten."
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
        self._entry(form, "Node API key", self.node_api_key, 2, 0)
        self._entry(form, "Peers, comma separated", self.peers, 2, 1)

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
                "Validatoren, die Bloeke signieren duerfen."
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

        voter_box = ttk.LabelFrame(root, text="Separater Voting Client")
        voter_box.pack(fill=tk.X, pady=(0, 16))
        voter_controls = ttk.Frame(voter_box)
        voter_controls.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(voter_controls, text="Client Port").pack(side=tk.LEFT)
        ttk.Entry(voter_controls, textvariable=self.voter_client_port, width=8).pack(side=tk.LEFT, padx=(6, 14))
        ttk.Button(voter_controls, text="Voting Client starten", command=self.start_voter_client).pack(side=tk.LEFT)
        ttk.Button(voter_controls, text="Voting Client stoppen", command=self.stop_voter_client).pack(side=tk.LEFT, padx=8)
        ttk.Button(voter_controls, text="Voting Client oeffnen", command=self.open_voter_client).pack(side=tk.LEFT)

        demo_network_box = ttk.LabelFrame(root, text="Demo Network")
        demo_network_box.pack(fill=tk.X, pady=(0, 16))
        demo_network_help = ttk.Label(
            demo_network_box,
            text=(
                "Startet node1 als Validator und node2/node3 als Observer."
            ),
            wraplength=940,
        )
        demo_network_help.pack(anchor=tk.W, padx=10, pady=(8, 4))

        demo_network_controls = ttk.Frame(demo_network_box)
        demo_network_controls.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Label(demo_network_controls, text="Base Port").pack(side=tk.LEFT)
        ttk.Entry(demo_network_controls, textvariable=self.demo_network_base_port, width=8).pack(side=tk.LEFT, padx=(6, 14))
        ttk.Checkbutton(
            demo_network_controls,
            text="Demo-State vorher resetten",
            variable=self.demo_network_reset,
        ).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Button(
            demo_network_controls,
            text="3-Node-Demo starten",
            command=self.start_demo_network,
        ).pack(side=tk.LEFT)
        ttk.Button(
            demo_network_controls,
            text="3-Node-Demo stoppen",
            command=self.stop_demo_network,
        ).pack(side=tk.LEFT, padx=8)
        ttk.Button(
            demo_network_controls,
            text="Demo Links oeffnen",
            command=self.open_demo_network_links,
        ).pack(side=tk.LEFT)

        env_box = ttk.LabelFrame(root, text="Node Log")
        env_box.pack(fill=tk.BOTH, expand=True)
        self.log = scrolledtext.ScrolledText(env_box, height=14, wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for column in range(2):
            form.columnconfigure(column, weight=1)
            key_box.columnconfigure(column, weight=1)

    def _update_scroll_region(self, _event: tk.Event) -> None:
        """Make the complete inner form reachable through the scrollbar."""
        bounds = self.scroll_canvas.bbox("all")
        if bounds is not None:
            self.scroll_canvas.configure(scrollregion=bounds)

    def _resize_scroll_content(self, event: tk.Event) -> None:
        """Keep the embedded form as wide as the visible Canvas viewport."""
        self.scroll_canvas.itemconfigure(self.scroll_content_window, width=event.width)

    def _on_mousewheel(self, event: tk.Event) -> str | None:
        """
        Scroll the launcher on macOS, Windows and Linux wheel events.

        `ScrolledText` controls already implement their own wheel handling. If
        the pointer is over one of them, this method deliberately does nothing;
        otherwise it normalizes the platform-specific event into Canvas units.
        """
        if isinstance(event.widget, tk.Text):
            return None

        if getattr(event, "num", None) == 4:
            units = -3
        elif getattr(event, "num", None) == 5:
            units = 3
        elif event.delta:
            units = -1 if event.delta > 0 else 1
        else:
            return None

        self.scroll_canvas.yview_scroll(units, "units")
        return "break"

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
        Start the packaged FastAPI node with the visible form values as environment.

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
        existing_pythonpath = env.get("PYTHONPATH", "")
        env.update(
            {
                "NODE_ID": self.node_id.get().strip(),
                "NODE_PRIVATE_KEY": self.private_key.get().strip(),
                "VALIDATORS_JSON": validators_json,
                "DATA_DIR": self.data_dir.get().strip(),
                "PORT": self.port.get().strip(),
                "ADMIN_KEY": self.admin_key.get().strip(),
                "V2_ADMIN_KEY": self.admin_key.get().strip(),
                "V2_NODE_KEY": self.node_api_key.get().strip(),
                "PEERS": self.peers.get().strip(),
                "PYTHONPATH": str(PROJECT_DIR) if not existing_pythonpath else f"{PROJECT_DIR}{os.pathsep}{existing_pythonpath}",
            }
        )
        self.tls_paths.apply_to_environment(env)

        self._log_line("Start single node:")
        for key in ["NODE_ID", "PORT", "DATA_DIR", "PEERS", "VALIDATORS_JSON"]:
            self._log_line(f"  {key}={env[key]}")
        self._log_line(f"  TLS_CA_CERT={env['TLS_CA_CERT']}")

        self.process = subprocess.Popen(
            [sys.executable, "-m", "voting_system.node_server"],
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

    def start_demo_network(self) -> None:
        """
        Start the three-node presentation network from inside the launcher.

        This runs `scripts/run_v2_demo_network.py` as a subprocess. Keeping the
        network script as the single source of truth prevents the GUI and CLI
        paths from drifting apart.
        """
        if self.demo_network_process and self.demo_network_process.poll() is None:
            messagebox.showinfo("Demo Network laeuft bereits", "Die 3-Node-Demo ist schon gestartet.")
            return
        if self.voter_client_process and self.voter_client_process.poll() is None:
            messagebox.showinfo(
                "Voting Client separat gestartet",
                "Stoppe zuerst den einzelnen Voting Client. Das Demo-Netzwerk startet einen eigenen Client-Prozess.",
            )
            return

        try:
            base_port = int(self.demo_network_base_port.get().strip())
            voter_port = int(self.voter_client_port.get().strip())
        except ValueError:
            messagebox.showerror("Port ungueltig", "Bitte Zahlen fuer Node- und Voting-Client-Port eintragen.")
            return

        command = [
            sys.executable,
            str(PROJECT_DIR / "scripts" / "run_v2_demo_network.py"),
            "--base-port",
            str(base_port),
            "--voter-port",
            str(voter_port),
        ]
        if self.demo_network_reset.get():
            command.append("--reset")

        self._log_line("Start demo network:")
        self._log_line("  " + " ".join(command))
        self._log_line(f"  node1 dashboard: https://127.0.0.1:{base_port}/dashboard")
        self._log_line(
            f"  voter client:     https://127.0.0.1:{self.voter_client_port.get().strip()}"
            f"/?node=https://127.0.0.1:{base_port}"
        )
        self._log_line(f"  committee client: https://127.0.0.1:{base_port}/committee")
        self._log_line(f"  node2 dashboard: https://127.0.0.1:{base_port + 1}/dashboard")
        self._log_line(f"  node3 dashboard: https://127.0.0.1:{base_port + 2}/dashboard")

        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(PROJECT_DIR) if not existing_pythonpath else f"{PROJECT_DIR}{os.pathsep}{existing_pythonpath}"
        self.demo_network_process = subprocess.Popen(
            command,
            cwd=PROJECT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self._stream_demo_network_output, daemon=True).start()

    def stop_demo_network(self) -> None:
        """Terminate the three-node demo network subprocess, if it is running."""
        if not self.demo_network_process or self.demo_network_process.poll() is not None:
            self._log_line("No running demo network process.")
            return

        self._log_line("Stopping 3-node demo network...")
        self.demo_network_process.terminate()
        try:
            self.demo_network_process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self._log_line("Demo network did not stop in time; killing process.")
            self.demo_network_process.kill()
        self._log_line("Demo network stopped.")

    def open_demo_network_links(self) -> None:
        """Open the main presentation pages for the configured demo network."""
        try:
            base_port = int(self.demo_network_base_port.get().strip())
        except ValueError:
            messagebox.showerror("Base Port ungueltig", "Bitte eine Zahl fuer den Base Port eintragen.")
            return

        webbrowser.open(f"https://127.0.0.1:{base_port}/dashboard")
        webbrowser.open(f"https://127.0.0.1:{base_port}/committee")
        webbrowser.open(
            f"https://127.0.0.1:{self.voter_client_port.get().strip()}"
            f"/?node=https://127.0.0.1:{base_port}"
        )
        self._log_line(f"Opened node1 pages and the separate voter client.")

    def start_voter_client(self) -> None:
        """Start the standalone voter server without starting a blockchain node."""
        if self.demo_network_process and self.demo_network_process.poll() is None:
            messagebox.showinfo(
                "Demo Network laeuft",
                "Das Demo-Netzwerk hat den separaten Voting Client bereits gestartet.",
            )
            return
        if self.voter_client_process and self.voter_client_process.poll() is None:
            messagebox.showinfo("Voting Client laeuft bereits", "Der separate Client ist schon gestartet.")
            return

        try:
            port = int(self.voter_client_port.get().strip())
        except ValueError:
            messagebox.showerror("Client Port ungueltig", "Bitte eine Zahl fuer den Client Port eintragen.")
            return

        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["VOTER_CLIENT_PORT"] = str(port)
        env["PYTHONPATH"] = str(PROJECT_DIR) if not existing_pythonpath else f"{PROJECT_DIR}{os.pathsep}{existing_pythonpath}"
        self.tls_paths.apply_to_environment(env)
        self.voter_client_process = subprocess.Popen(
            [sys.executable, "-m", "voting_system.voter_client_server"],
            cwd=PROJECT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._log_line(f"Started separate voter client on port {port}.")
        threading.Thread(target=self._stream_voter_client_output, daemon=True).start()

    def stop_voter_client(self) -> None:
        """Stop the standalone voter server, leaving every node untouched."""
        if not self.voter_client_process or self.voter_client_process.poll() is not None:
            self._log_line("No running voter client process.")
            return
        self._log_line("Stopping separate voter client...")
        self.voter_client_process.terminate()
        try:
            self.voter_client_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.voter_client_process.kill()
        self._log_line("Voter client stopped.")

    def open_voter_client(self) -> None:
        """Open the independent client and preselect the configured Node API."""
        url = (
            f"https://127.0.0.1:{self.voter_client_port.get().strip()}"
            f"/?node=https://127.0.0.1:{self.port.get().strip()}"
        )
        webbrowser.open(url)
        self._log_line(f"Opened voter client: {url}")

    def open_dashboard(self) -> None:
        """Open the browser dashboard and point it at this node's port."""
        url = f"https://127.0.0.1:{self.port.get().strip()}/dashboard"
        webbrowser.open(url)
        self._log_line(f"Opened dashboard: {url}")

    def open_docs(self) -> None:
        """Open FastAPI docs for the running node."""
        webbrowser.open(f"https://127.0.0.1:{self.port.get().strip()}/docs")

    def show_demo_command(self) -> None:
        """Show the simplified demo-client command for the current node."""
        command = f"{sys.executable} scripts/v2_demo_client.py --api-url https://127.0.0.1:{self.port.get().strip()} full-demo"
        self._log_line("Demo client command:")
        self._log_line(command)

    def _stream_process_output(self) -> None:
        """Forward the node subprocess output into the GUI log."""
        assert self.process is not None
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self._log_line(line.rstrip())
        self._log_line(f"Node process exited with code {self.process.poll()}.")

    def _stream_demo_network_output(self) -> None:
        """Forward the demo-network subprocess output into the GUI log."""
        assert self.demo_network_process is not None
        assert self.demo_network_process.stdout is not None
        for line in self.demo_network_process.stdout:
            self._log_line("[network] " + line.rstrip())
        self._log_line(f"Demo network process exited with code {self.demo_network_process.poll()}.")

    def _stream_voter_client_output(self) -> None:
        """Forward standalone voter server output into the shared launcher log."""
        assert self.voter_client_process is not None
        assert self.voter_client_process.stdout is not None
        for line in self.voter_client_process.stdout:
            self._log_line("[voter] " + line.rstrip())
        self._log_line(f"Voter client process exited with code {self.voter_client_process.poll()}.")

    def _log_line(self, line: str) -> None:
        """Append one line to the GUI log from any thread."""
        self.log.after(0, self._append_log_line, line)

    def _append_log_line(self, line: str) -> None:
        """Append one line to the Tk text widget on the UI thread."""
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)

    def destroy(self) -> None:
        """Stop child processes when the launcher window closes."""
        self.stop_demo_network()
        self.stop_voter_client()
        self.stop_node()
        super().destroy()


def main() -> None:
    """Run the launcher GUI."""
    app = V2NodeLauncher()
    app.mainloop()


if __name__ == "__main__":
    main()
