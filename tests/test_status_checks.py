import unittest
from unittest.mock import patch, mock_open, MagicMock
import sys
import os

# Mock external modules that are not required or might fail to import
sys.modules['postfix_mta_sts_resolver'] = MagicMock()
sys.modules['postfix_mta_sts_resolver.resolver'] = MagicMock()
sys.modules['exclusiveprocess'] = MagicMock()

# Add management directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

# Mock utils.load_environment before importing status_checks
import utils
utils.load_environment = MagicMock(return_value={
    "PRIMARY_HOSTNAME": "box.example.com",
    "STORAGE_ROOT": "/tmp/storage",
    "PUBLIC_IP": "12.34.56.78",
    "PUBLIC_IPV6": "2001:db8::1"
})

import status_checks

class TestStatusChecks(unittest.TestCase):
    def setUp(self):
        self.env = {
            "PRIMARY_HOSTNAME": "box.example.com",
            "STORAGE_ROOT": "/tmp/storage",
            "PUBLIC_IP": "12.34.56.78",
            "PUBLIC_IPV6": "2001:db8::1"
        }
        self.output = status_checks.BufferedOutput()

    @patch('os.path.exists', return_value=False)
    def test_tls_hardening_no_files(self, mock_exists):
        status_checks.check_tls_hardening(self.env, self.output)
        
        # We expect two warnings because neither protocols nor ciphers could be determined
        warnings = [args[0] for name, args, kwargs in self.output.buf if name == 'print_warning']
        self.assertIn("Could not determine Nginx ssl_protocols configuration.", warnings)
        self.assertIn("Could not determine Nginx ssl_ciphers configuration.", warnings)

    @patch('os.path.exists', return_value=True)
    def test_tls_hardening_secure(self, mock_exists):
        nginx_conf_content = """
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        """
        with patch('builtins.open', mock_open(read_data=nginx_conf_content)):
            status_checks.check_tls_hardening(self.env, self.output)
            
            oks = [args[0] for name, args, kwargs in self.output.buf if name == 'print_ok']
            warnings = [args[0] for name, args, kwargs in self.output.buf if name == 'print_warning']
            
            self.assertEqual(len(warnings), 0)
            self.assertIn("Nginx TLS protocols are configured securely (only modern TLS allowed).", oks)
            self.assertIn("Nginx TLS cipher suites are configured securely.", oks)

    @patch('os.path.exists', return_value=True)
    def test_tls_hardening_weak_protocols(self, mock_exists):
        nginx_conf_content = """
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;
        """
        with patch('builtins.open', mock_open(read_data=nginx_conf_content)):
            status_checks.check_tls_hardening(self.env, self.output)
            
            oks = [args[0] for name, args, kwargs in self.output.buf if name == 'print_ok']
            warnings = [args[0] for name, args, kwargs in self.output.buf if name == 'print_warning']
            
            self.assertIn("Nginx TLS cipher suites are configured securely.", oks)
            self.assertEqual(len(warnings), 1)
            self.assertTrue(any("permits insecure protocols" in w for w in warnings))
            self.assertTrue(any("tlsv1" in w and "tlsv1.1" in w for w in warnings))

    @patch('os.path.exists', return_value=True)
    def test_tls_hardening_weak_ciphers(self, mock_exists):
        nginx_conf_content = """
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:RC4-SHA:3DES-EDH;
        """
        with patch('builtins.open', mock_open(read_data=nginx_conf_content)):
            status_checks.check_tls_hardening(self.env, self.output)
            
            oks = [args[0] for name, args, kwargs in self.output.buf if name == 'print_ok']
            warnings = [args[0] for name, args, kwargs in self.output.buf if name == 'print_warning']
            
            self.assertIn("Nginx TLS protocols are configured securely (only modern TLS allowed).", oks)
            self.assertEqual(len(warnings), 1)
            self.assertTrue(any("permits weak/vulnerable ciphers" in w for w in warnings))
            self.assertTrue(any("RC4-SHA" in w or "3DES-EDH" in w for w in warnings))

    @patch('os.path.exists', return_value=True)
    def test_tls_hardening_commented_out_directives(self, mock_exists):
        nginx_conf_content = """
        # Let's check commented out directives
        # ssl_protocols TLSv1 TLSv1.1;
        ssl_protocols TLSv1.2 TLSv1.3; # We only want modern ones, not TLSv1
        
        # ssl_ciphers RC4-SHA:3DES-EDH;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;
        """
        with patch('builtins.open', mock_open(read_data=nginx_conf_content)):
            status_checks.check_tls_hardening(self.env, self.output)
            
            oks = [args[0] for name, args, kwargs in self.output.buf if name == 'print_ok']
            warnings = [args[0] for name, args, kwargs in self.output.buf if name == 'print_warning']
            
            self.assertEqual(len(warnings), 0)
            self.assertIn("Nginx TLS protocols are configured securely (only modern TLS allowed).", oks)
            self.assertIn("Nginx TLS cipher suites are configured securely.", oks)

if __name__ == '__main__':
    unittest.main()
