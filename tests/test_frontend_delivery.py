import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from voting_system.node_server import create_app
from voting_system.voter_client_server import create_voter_client_app


class FrontendDeliveryTest(unittest.TestCase):
    """Smoke-test the exact HTML and crypto assets served during the demo."""

    def test_node_serves_dashboard_and_committee_but_not_voter(self):
        with tempfile.TemporaryDirectory() as data_dir, patch.dict(os.environ, {
            "NODE_ID": "frontend-test",
            "DATA_DIR": data_dir,
            "VALIDATORS_JSON": "{}",
        }):
            client = TestClient(create_app())
            for path in ["/dashboard", "/committee"]:
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("text/html", response.headers["content-type"])
                self.assertIn("/assets/voting_crypto.bundle.js", response.text)
                self.assertNotIn("/api/v2/demo/", response.text)

            self.assertEqual(client.get("/voter").status_code, 404)

            cors_response = client.get(
                "/api/v2/elections",
                headers={"Origin": "http://127.0.0.1:7000"},
            )
            self.assertEqual(cors_response.status_code, 200)
            self.assertEqual(cors_response.headers["access-control-allow-origin"], "*")

            bundle = client.get("/assets/voting_crypto.bundle.js")
            self.assertEqual(bundle.status_code, 200)
            self.assertIn("VotingCrypto", bundle.text)

    def test_voter_is_served_by_standalone_client_without_node_pages(self):
        """The voter process exposes its own page and no operator interfaces."""
        client = TestClient(create_voter_client_app())

        for path in ["/", "/voter"]:
            response = client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn("text/html", response.headers["content-type"])
            self.assertIn("/assets/voting_crypto.bundle.js", response.text)
            self.assertIn("new URLSearchParams", response.text)

        self.assertEqual(client.get("/dashboard").status_code, 404)
        self.assertEqual(client.get("/committee").status_code, 404)
        self.assertEqual(client.get("/health").json()["service"], "standalone-voter-client")

        bundle = client.get("/assets/voting_crypto.bundle.js")
        self.assertEqual(bundle.status_code, 200)
        self.assertIn("VotingCrypto", bundle.text)


if __name__ == "__main__":
    unittest.main()
