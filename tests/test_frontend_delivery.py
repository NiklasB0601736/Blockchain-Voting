import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from voting_system.blockchain_v1 import create_app


class FrontendDeliveryTest(unittest.TestCase):
    """Smoke-test the exact HTML and crypto assets served during the demo."""

    def test_dashboard_voter_committee_and_crypto_bundle_are_served(self):
        with tempfile.TemporaryDirectory() as data_dir, patch.dict(os.environ, {
            "NODE_ID": "frontend-test",
            "DATA_DIR": data_dir,
            "VALIDATORS_JSON": "{}",
        }):
            client = TestClient(create_app())
            for path in ["/dashboard", "/voter", "/committee"]:
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("text/html", response.headers["content-type"])
                self.assertIn("/assets/voting_crypto.bundle.js", response.text)
                self.assertNotIn("/api/v2/demo/", response.text)

            bundle = client.get("/assets/voting_crypto.bundle.js")
            self.assertEqual(bundle.status_code, 200)
            self.assertIn("VotingCrypto", bundle.text)


if __name__ == "__main__":
    unittest.main()
