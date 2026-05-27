import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import sqlite3
import json
import pyotp

# Mock external modules that are not required or might fail to import
sys.modules['exclusiveprocess'] = MagicMock()

# Add management directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

# Mock utils.load_environment before importing mfa/mailconfig
import utils
utils.load_environment = MagicMock(return_value={
    "PRIMARY_HOSTNAME": "box.example.com",
    "STORAGE_ROOT": "/tmp/storage"
})

import mfa

class TestMFA(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite database
        self.db_conn = sqlite3.connect(":memory:")
        c = self.db_conn.cursor()
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                email TEXT NOT NULL UNIQUE, 
                password TEXT NOT NULL, 
                extra, 
                privileges TEXT NOT NULL DEFAULT '', 
                quota TEXT NOT NULL DEFAULT '0'
            );
        """)
        c.execute("""
            CREATE TABLE mfa (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                user_id INTEGER NOT NULL, 
                type TEXT NOT NULL, 
                secret TEXT NOT NULL, 
                mru_token TEXT, 
                label TEXT, 
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        
        # Insert a test user
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", ("test@example.com", "password_hash"))
        self.db_conn.commit()
        
        # Start patching open_database
        self.patcher = patch('mfa.open_database', side_effect=self.mock_open_database)
        self.patcher.start()
        
        self.env = {
            "PRIMARY_HOSTNAME": "box.example.com",
            "STORAGE_ROOT": "/tmp/storage"
        }

    def tearDown(self):
        self.patcher.stop()
        self.db_conn.close()

    def mock_open_database(self, env, with_connection=False):
        if not with_connection:
            return self.db_conn.cursor()
        return self.db_conn, self.db_conn.cursor()

    def test_get_user_id(self):
        c = self.db_conn.cursor()
        user_id = mfa.get_user_id("test@example.com", c)
        self.assertEqual(user_id, 1)
        
        with self.assertRaises(ValueError):
            mfa.get_user_id("nonexistent@example.com", c)

    def test_get_mfa_state_empty(self):
        state = mfa.get_mfa_state("test@example.com", self.env)
        self.assertEqual(len(state), 0)

    def test_provision_totp(self):
        res = mfa.provision_totp("test@example.com", self.env)
        self.assertEqual(res["type"], "totp")
        self.assertEqual(len(res["secret"]), 32)
        self.assertTrue(len(res["qr_code_base64"]) > 0)

    def test_enable_and_get_mfa_totp(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        token = totp.now()
        
        # Test validation of invalid secret length
        with self.assertRaises(ValueError):
            mfa.enable_mfa("test@example.com", "totp", "SHORTSECRET", token, "My Phone", self.env)
            
        # Test validation of invalid token
        with self.assertRaises(ValueError):
            mfa.enable_mfa("test@example.com", "totp", secret, "000000", "My Phone", self.env)

        # Test successful enablement
        mfa.enable_mfa("test@example.com", "totp", secret, token, "My Phone", self.env)
        
        # Verify mfa state
        state = mfa.get_mfa_state("test@example.com", self.env)
        self.assertEqual(len(state), 1)
        self.assertEqual(state[0]["type"], "totp")
        self.assertEqual(state[0]["secret"], secret)
        self.assertEqual(state[0]["label"], "My Phone")
        
        # Verify public state
        public_state = mfa.get_public_mfa_state("test@example.com", self.env)
        self.assertEqual(len(public_state), 1)
        self.assertEqual(public_state[0]["type"], "totp")
        self.assertEqual(public_state[0]["label"], "My Phone")
        self.assertNotIn("secret", public_state[0])

    def test_disable_mfa(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        token = totp.now()
        mfa.enable_mfa("test@example.com", "totp", secret, token, "My Phone", self.env)
        
        # Disable specific ID
        state = mfa.get_mfa_state("test@example.com", self.env)
        mfa_id = state[0]["id"]
        disabled = mfa.disable_mfa("test@example.com", mfa_id, self.env)
        self.assertTrue(disabled)
        
        state = mfa.get_mfa_state("test@example.com", self.env)
        self.assertEqual(len(state), 0)

    def test_validate_auth_mfa_totp(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        
        # No MFA enabled should pass immediately
        request = MagicMock()
        status, hints = mfa.validate_auth_mfa("test@example.com", request, self.env)
        self.assertTrue(status)
        self.assertEqual(hints, [])
        
        # Enable MFA
        token = totp.now()
        mfa.enable_mfa("test@example.com", "totp", secret, token, "My Phone", self.env)
        
        # Test missing token
        request.headers = {}
        status, hints = mfa.validate_auth_mfa("test@example.com", request, self.env)
        self.assertFalse(status)
        self.assertEqual(hints, ["missing-totp-token"])
        
        # Test invalid token
        request.headers = {'x-auth-token': '123456'}
        status, hints = mfa.validate_auth_mfa("test@example.com", request, self.env)
        self.assertFalse(status)
        self.assertEqual(hints, ["invalid-totp-token"])
        
        # Test valid token (generate a fresh token so it's not the setup one)
        # Using a slight time shift or generating standard TOTP token
        valid_token = totp.now()
        request.headers = {'x-auth-token': valid_token}
        status, hints = mfa.validate_auth_mfa("test@example.com", request, self.env)
        self.assertTrue(status)
        self.assertEqual(hints, [])
        
        # Test replay attack (using same token again)
        status, hints = mfa.validate_auth_mfa("test@example.com", request, self.env)
        self.assertFalse(status)
        self.assertEqual(hints, ["invalid-totp-token"])

    @patch('mfa.WEBAUTHN_AVAILABLE', True)
    @patch('mfa.generate_registration_options')
    @patch('mfa.verify_registration_response')
    def test_webauthn_flows(self, mock_verify, mock_generate):
        # Mock registration options generation
        mock_options = MagicMock()
        mock_options_json = '{"challenge": "mocked_challenge_bytes"}'
        mock_generate.return_value = mock_options
        
        with patch('mfa.options_to_json', return_value=mock_options_json):
            auth_service = MagicMock()
            auth_service.webauthn_challenges = {}
            
            # Test provision
            options = mfa.provision_webauthn("test@example.com", self.env, auth_service)
            self.assertEqual(options["challenge"], "mocked_challenge_bytes")
            self.assertEqual(auth_service.webauthn_challenges["test@example.com"], "mocked_challenge_bytes")
            
            # Mock verification
            mock_verification = MagicMock()
            mock_verification.credential_id = b"cred_id_123"
            mock_verification.credential_public_key = b"pub_key_456"
            mock_verification.sign_count = 0
            mock_verify.return_value = mock_verification
            
            # Test register_webauthn
            response_data = {"id": "cred_id_123_b64"}
            mfa.register_webauthn("test@example.com", response_data, "My Key", self.env, auth_service)
            
            # Confirm challenge was deleted from auth_service
            self.assertNotIn("test@example.com", auth_service.webauthn_challenges)
            
            # Check state has it
            state = mfa.get_mfa_state("test@example.com", self.env)
            self.assertEqual(len(state), 1)
            self.assertEqual(state[0]["type"], "webauthn")
            
            secret_data = json.loads(state[0]["secret"])
            self.assertEqual(secret_data["credential_id"], "Y3JlZF9pZF8xMjM") # base64url encoded b"cred_id_123"
            self.assertEqual(secret_data["public_key"], "cHViX2tleV80NTY")

    @patch('mfa.WEBAUTHN_AVAILABLE', False)
    def test_webauthn_library_unavailable(self):
        # Insert a webauthn credential directly into db
        c = self.db_conn.cursor()
        c.execute(
            "INSERT INTO mfa (user_id, type, secret, label) VALUES (?, ?, ?, ?)",
            (1, "webauthn", '{"credential_id": "xyz", "public_key": "abc", "sign_count": 0}', "My Key")
        )
        self.db_conn.commit()
        
        request = MagicMock()
        request.headers = {}
        status, hints = mfa.validate_auth_mfa("test@example.com", request, self.env)
        self.assertFalse(status)
        self.assertEqual(hints, ["webauthn-library-unavailable"])

if __name__ == '__main__':
    unittest.main()
