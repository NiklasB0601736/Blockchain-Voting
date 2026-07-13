"""
Serve the browser voting client independently from every blockchain node.

The voting client performs commitment derivation and EC-ElGamal encryption in
the browser. Hosting it in a separate process makes the architectural boundary
visible: this server only delivers trusted static client code, while all chain
reads and transaction submissions go to the Node API selected in the GUI.

This separation is useful for the prototype, but it is not by itself a complete
software-supply-chain solution. A production client would additionally need
signed releases, reproducible builds and a trusted update mechanism.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = PROJECT_ROOT / "web"


def create_voter_client_app() -> FastAPI:
    """
    Build the standalone HTTP application for the browser voting client.

    Only the voter page, its browser cryptography bundle and a health endpoint
    are exposed. In particular, this app has no blockchain state, validator
    key, admin endpoint, dashboard or committee page.
    """
    app = FastAPI(
        title="Voting Client",
        description="Separater Browser-Client fuer lokale Stimmenverschluesselung.",
        version="2.0.0",
    )
    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="voter-assets")

    def voter_page() -> FileResponse:
        """Return the voter HTML or a clear error when the web build is missing."""
        voter_path = WEB_DIR / "voter_client.html"
        if not voter_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="voter_client.html nicht gefunden",
            )
        return FileResponse(voter_path)

    @app.get("/")
    def root() -> FileResponse:
        """Open the voting interface directly at the client server root."""
        return voter_page()

    @app.get("/voter")
    def voter() -> FileResponse:
        """Keep an explicit voter URL for readable links and bookmarks."""
        return voter_page()

    @app.get("/health")
    def health() -> dict:
        """Expose a minimal readiness check without contacting a blockchain node."""
        return {"status": "ok", "service": "standalone-voter-client"}

    return app


app = create_voter_client_app()


def main() -> None:
    """Run the standalone client server on the configured local port."""
    import uvicorn

    host = os.environ.get("VOTER_CLIENT_HOST", "127.0.0.1")
    port = int(os.environ.get("VOTER_CLIENT_PORT", "7000"))
    uvicorn.run(app, host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
