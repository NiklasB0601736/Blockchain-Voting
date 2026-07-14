#!/usr/bin/env python3
"""Generate or replace the local HTTPS certificate used by the demo."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from voting_system.tls import DEFAULT_TLS_DIR, ensure_development_tls_material


def main() -> int:
    """Create TLS material and print the files relevant to users and servers."""
    parser = argparse.ArgumentParser(description="Generate local HTTPS certificates.")
    parser.add_argument("--tls-dir", type=Path, default=DEFAULT_TLS_DIR)
    parser.add_argument("--host", action="append", default=[], help="Additional LAN IP or DNS name; repeatable.")
    parser.add_argument("--force", action="store_true", help="Replace the existing local CA and server certificate.")
    args = parser.parse_args()

    paths = ensure_development_tls_material(args.tls_dir, force=args.force, extra_hosts=args.host)
    print(f"CA certificate: {paths.ca_cert}")
    print(f"Server certificate: {paths.server_cert}")
    print(f"Server private key: {paths.server_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
