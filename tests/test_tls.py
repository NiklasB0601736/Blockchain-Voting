import ipaddress
import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from voting_system.distributed_blockchain import normalize_peer_url
from voting_system.tls import create_client_ssl_context, ensure_development_tls_material


class TLSConfigurationTest(unittest.TestCase):
    """Verify the local CA, server identity and HTTPS-only peer policy."""

    def test_generated_certificate_is_signed_for_local_https_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = ensure_development_tls_material(Path(tmp), extra_hosts=["demo.local", "192.0.2.10"])
            ca = x509.load_pem_x509_certificate(paths.ca_cert.read_bytes())
            server = x509.load_pem_x509_certificate(paths.server_cert.read_bytes())
            san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

            self.assertEqual(server.issuer, ca.subject)
            self.assertIn("localhost", san.get_values_for_type(x509.DNSName))
            self.assertIn("demo.local", san.get_values_for_type(x509.DNSName))
            self.assertIn(ipaddress.ip_address("127.0.0.1"), san.get_values_for_type(x509.IPAddress))
            self.assertIn(ipaddress.ip_address("192.0.2.10"), san.get_values_for_type(x509.IPAddress))
            self.assertEqual(paths.server_key.stat().st_mode & 0o777, 0o600)
            self.assertIsNotNone(create_client_ssl_context(paths.ca_cert))

    def test_legacy_http_peer_is_migrated_but_invalid_scheme_is_rejected(self):
        self.assertEqual(
            normalize_peer_url("http://127.0.0.1:5002/"),
            "https://127.0.0.1:5002",
        )
        self.assertEqual(
            normalize_peer_url("https://127.0.0.1:5003/"),
            "https://127.0.0.1:5003",
        )
        with self.assertRaises(ValueError):
            normalize_peer_url("127.0.0.1:5002")


if __name__ == "__main__":
    unittest.main()
