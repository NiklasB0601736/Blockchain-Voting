"""
FastAPI entry point for the active distributed voting node.

This module deliberately contains only the current V2 application surface:

- the distributed Proof-of-Authority chain and its `/api/v2` routes,
- the node dashboard,
- the committee client,
- the shared browser cryptography bundle.

The earlier local V1 blockchain and its plaintext voting API are kept in the
archive. Separating both generations prevents obsolete endpoints from looking
like part of the current architecture and gives scripts one unambiguous node
entry point.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from voting_system.distributed_blockchain import DistributedVotingBlockchain, register_v2_routes


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = PROJECT_ROOT / "web"


def create_app(node: DistributedVotingBlockchain | None = None) -> FastAPI:
    """
    Construct one active V2 blockchain-node application.

    Passing a node instance keeps unit tests deterministic. Normal launches omit
    it, causing `register_v2_routes` to load node identity, validator keys,
    peers and persistence paths from the documented environment variables.
    """
    app = FastAPI(
        title="Distributed Blockchain Voting Node",
        description="V2 API fuer PoA-Chain, verschluesselte Ballots und Threshold-Tally.",
        version="2.0.0",
    )

    # The independently hosted voter client talks to this API from another
    # origin (port 7000 in the demo). Wildcard CORS is acceptable for the local
    # prototype because voter transactions are public submissions and the two
    # privileged operations still require their explicit role headers.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Admin-Key", "X-Node-Key"],
    )
    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="node-assets")

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_request, exc: HTTPException):
        """Keep GUI-facing API errors compact and consistent."""
        detail = exc.detail if isinstance(exc.detail, str) else "Request fehlgeschlagen"
        return JSONResponse(status_code=exc.status_code, content={"error": detail})

    @app.get("/")
    def root() -> dict:
        """List only the interfaces that belong to an active blockchain node."""
        return {
            "message": "Distributed Blockchain Voting Node laeuft",
            "api_docs": "/docs",
            "dashboard": "/dashboard",
            "committee_client": "/committee",
            "node_info": "/api/v2/node/info",
            "chain": "/api/v2/chain",
        }

    @app.get("/dashboard")
    def dashboard() -> FileResponse:
        """Serve the node/operator dashboard from the node process."""
        dashboard_path = WEB_DIR / "frontend_v2.html"
        if not dashboard_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="frontend_v2.html nicht gefunden",
            )
        return FileResponse(dashboard_path)

    @app.get("/committee")
    def committee_client() -> FileResponse:
        """Serve the committee tally interface, which reads public chain data."""
        committee_path = WEB_DIR / "committee_client.html"
        if not committee_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="committee_client.html nicht gefunden",
            )
        return FileResponse(committee_path)

    register_v2_routes(app, node=node)
    return app


app = create_app()


def main() -> None:
    """Run one configured blockchain node for development or presentations."""
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5001"))
    reload_enabled = os.environ.get("API_RELOAD", "0") == "1"
    target = "voting_system.node_server:app" if reload_enabled else app

    print("\n" + "=" * 70)
    print("DISTRIBUTED BLOCKCHAIN VOTING NODE".center(70))
    print("=" * 70)
    print(f"API:       http://{host}:{port}")
    print(f"Dashboard: http://{host}:{port}/dashboard")
    print(f"Committee: http://{host}:{port}/committee")
    print("=" * 70 + "\n")

    uvicorn.run(target, host=host, port=port, reload=reload_enabled)


if __name__ == "__main__":
    main()
