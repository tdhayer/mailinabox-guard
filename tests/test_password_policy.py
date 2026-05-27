import unittest
import sys
import os

# Add management directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

from mailconfig import validate_password

class TestPasswordPolicy(unittest.TestCase):
    def test_empty_password(self):
        with self.assertRaises(ValueError) as ctx:
            validate_password("")
        self.assertEqual(str(ctx.exception), "No password provided.")

        with self.assertRaises(ValueError) as ctx:
            validate_password("   ")
        self.assertEqual(str(ctx.exception), "No password provided.")

    def test_short_password(self):
        with self.assertRaises(ValueError) as ctx:
            validate_password("Ab1!")
        self.assertEqual(str(ctx.exception), "Passwords must be at least 10 characters.")

    def test_missing_uppercase(self):
        with self.assertRaises(ValueError) as ctx:
            validate_password("strongp@ss1")
        self.assertEqual(str(ctx.exception), "Password must contain at least one uppercase letter.")

    def test_missing_lowercase(self):
        with self.assertRaises(ValueError) as ctx:
            validate_password("STRONGP@SS1")
        self.assertEqual(str(ctx.exception), "Password must contain at least one lowercase letter.")

    def test_missing_digit(self):
        with self.assertRaises(ValueError) as ctx:
            validate_password("StrongP@ssword")
        self.assertEqual(str(ctx.exception), "Password must contain at least one digit.")

    def test_missing_special(self):
        with self.assertRaises(ValueError) as ctx:
            validate_password("StrongPassword1")
        self.assertEqual(str(ctx.exception), "Password must contain at least one special character.")

    def test_valid_passwords(self):
        # These should all pass without raising exceptions
        validate_password("StrongP@ss123")
        validate_password("Another#Password9")
        validate_password("V@lid123456789")
