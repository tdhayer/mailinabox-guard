import unittest
from unittest.mock import patch
import sys
import os

# Add management directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

from spamconfig import _get_editconf_path

class TestSpamConfigPath(unittest.TestCase):
    @patch('os.path.exists')
    def test_get_editconf_path_prod_exists(self, mock_exists):
        # Case 1: production path exists
        mock_exists.side_effect = lambda path: path == "/usr/local/lib/mailinabox/editconf.py"
        path = _get_editconf_path()
        self.assertEqual(path, "/usr/local/lib/mailinabox/editconf.py")

    @patch('os.path.exists')
    def test_get_editconf_path_dev_exists(self, mock_exists):
        # Case 2: production does not exist, but dev exists
        dev_expected = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools", "editconf.py"))
        mock_exists.side_effect = lambda path: path == dev_expected
        path = _get_editconf_path()
        self.assertEqual(path, dev_expected)

    @patch('os.path.exists')
    def test_get_editconf_path_neither_exists(self, mock_exists):
        # Case 3: neither exists (defaults to prod_path)
        mock_exists.return_value = False
        path = _get_editconf_path()
        self.assertEqual(path, "/usr/local/lib/mailinabox/editconf.py")

if __name__ == '__main__':
    unittest.main()
