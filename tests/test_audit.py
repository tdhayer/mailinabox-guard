import unittest
import tempfile
import shutil
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

from audit import log_admin_action, get_audit_log

class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.env = {"STORAGE_ROOT": self.test_dir}

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_audit_logs(self):
        # Log a few actions
        log_admin_action("admin@example.com", "user_add", "user1@example.com", None, self.env)
        log_admin_action("admin@example.com", "user_remove", "user2@example.com", "Archived account", self.env)
        log_admin_action("admin@example.com", "dns_update", "example.com", "Updated records", self.env)
        log_admin_action("admin@example.com", "mfa_enable", "admin@example.com", "totp", self.env)
        
        # Test fetching all logs
        logs = get_audit_log(1, 10, "all", self.env)
        self.assertEqual(logs["total_entries"], 4)
        self.assertEqual(len(logs["entries"]), 4)
        
        # Check order is DESC (latest first)
        self.assertEqual(logs["entries"][0]["action"], "mfa_enable")
        self.assertEqual(logs["entries"][1]["action"], "dns_update")
        self.assertEqual(logs["entries"][2]["action"], "user_remove")
        self.assertEqual(logs["entries"][3]["action"], "user_add")
        
        # Test filtering by users category
        users_logs = get_audit_log(1, 10, "users", self.env)
        self.assertEqual(users_logs["total_entries"], 2)
        self.assertEqual(len(users_logs["entries"]), 2)
        self.assertEqual(users_logs["entries"][0]["action"], "user_remove")
        self.assertEqual(users_logs["entries"][1]["action"], "user_add")
        
        # Test filtering by security category
        sec_logs = get_audit_log(1, 10, "security", self.env)
        self.assertEqual(sec_logs["total_entries"], 1)
        self.assertEqual(sec_logs["entries"][0]["action"], "mfa_enable")
        
        # Test pagination
        paged_logs = get_audit_log(1, 2, "all", self.env)
        self.assertEqual(paged_logs["total_pages"], 2)
        self.assertEqual(len(paged_logs["entries"]), 2)
        self.assertEqual(paged_logs["entries"][0]["action"], "mfa_enable")
        self.assertEqual(paged_logs["entries"][1]["action"], "dns_update")
        
        page2_logs = get_audit_log(2, 2, "all", self.env)
        self.assertEqual(len(page2_logs["entries"]), 2)
        self.assertEqual(page2_logs["entries"][0]["action"], "user_remove")
        self.assertEqual(page2_logs["entries"][1]["action"], "user_add")
