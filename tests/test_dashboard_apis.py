import unittest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Mock exclusiveprocess and other system-specific modules before imports
sys.modules['exclusiveprocess'] = MagicMock()

# Add management directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

# Mock utils.load_environment before importing daemon
import utils
utils.load_environment = MagicMock(return_value={
    "PRIMARY_HOSTNAME": "box.example.com",
    "STORAGE_ROOT": "/tmp/storage"
})

# Mock auth key initialization
import auth
auth.AuthService.init_system_api_key = MagicMock()
auth.AuthService.key = "dummy_api_key"

import daemon

class TestDashboardAPIs(unittest.TestCase):
    def setUp(self):
        daemon.app.config['TESTING'] = True
        self.app = daemon.app.test_client()

    @patch('daemon.auth_service.authenticate')
    @patch('daemon.utils.shell')
    def test_get_mail_queue(self, mock_shell, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_shell.return_value = (0, '{"queue_name": "deferred", "queue_id": "12345", "arrival_time": 1716723405, "message_size": 100, "sender": "test@example.com", "recipients": [{"address": "recip@example.com", "delay_reason": "Deferred"}]}\n')
        
        response = self.app.get('/system/mail-queue')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['queue_id'], '12345')
        mock_shell.assert_called_with('check_output', ['/usr/sbin/postqueue', '-j'], trap=True)

    @patch('daemon.auth_service.authenticate')
    @patch('daemon.utils.shell')
    def test_flush_mail_queue(self, mock_shell, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_shell.return_value = (0, 'OK')
        
        response = self.app.post('/system/mail-queue/flush')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'OK')
        mock_shell.assert_called_with('check_output', ['/usr/sbin/postqueue', '-f'], trap=True)

    @patch('daemon.auth_service.authenticate')
    @patch('daemon.utils.shell')
    def test_delete_mail_queue(self, mock_shell, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_shell.return_value = (0, 'OK')
        
        response = self.app.post('/system/mail-queue/delete', data={'queue_id': '12345'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'OK')
        mock_shell.assert_called_with('check_output', ['/usr/sbin/postsuper', '-d', '12345'], trap=True)

    @patch('daemon.auth_service.authenticate')
    @patch('daemon.utils.shell')
    def test_get_active_connections(self, mock_shell, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_shell.return_value = (0, 'service pid conn-id type username ip port\nimap 123 456 imap test@example.com 1.2.3.4 143\n')
        
        daemon.auth_service.sessions['dummy_token'] = {
            'email': 'admin@example.com',
            'password_token': 'dummy',
            'type': 'login'
        }
        
        response = self.app.get('/system/active-connections')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('web_sessions', data)
        self.assertIn('dovecot_connections', data)
        self.assertEqual(len(data['web_sessions']), 1)
        self.assertEqual(data['web_sessions'][0]['email'], 'admin@example.com')
        self.assertEqual(len(data['dovecot_connections']), 1)
        self.assertEqual(data['dovecot_connections'][0]['username'], 'test@example.com')

    @patch('daemon.auth_service.authenticate')
    @patch('backup.backup_status')
    def test_backup_stats(self, mock_backup_status, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_backup_status.return_value = {
            'backups': [{'date': '2026-05-26T12:00:00Z', 'size': 1024, 'full': True, 'volumes': 1, 'date_str': '2026-05-26', 'date_delta': '0 days', 'deleted_in': 'Never'}],
            'unmatched_file_size': 0
        }
        
        response = self.app.get('/system/backup/stats')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('backups', data)
        self.assertEqual(len(data['backups']), 1)
        self.assertEqual(data['backups'][0]['size'], 1024)

    @patch('daemon.auth_service.authenticate')
    @patch('mail_log.scan_mail_log')
    @patch('os.path.exists')
    @patch('glob.glob')
    def test_spam_dmarc_stats(self, mock_glob, mock_exists, mock_scan_mail_log, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        
        # Mock mail_log results
        mock_scan_mail_log.return_value = {
            "received_mail": {"user@example.com": {"received_count": 5}},
            "rejected": {"user@example.com": {"blocked": [(None, None, "Spam blocked")]}}
        }
        
        # Mock DMARC directory checks
        mock_exists.return_value = True
        mock_glob.return_value = []
        
        response = self.app.get('/system/spam-dmarc/stats')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('dmarc', data)
        self.assertIn('spam_7days', data)
        self.assertEqual(data['spam_7days']['received'], 5)
        self.assertEqual(data['spam_7days']['blocked'], 1)

    @patch('daemon.auth_service.authenticate')
    @patch('daemon.utils.shell')
    @patch('os.path.exists')
    def test_get_logs_tail(self, mock_exists, mock_shell, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_exists.return_value = True
        mock_shell.return_value = (0, "line 1\nline 2\nline 3\n")
        
        response = self.app.get('/system/logs?log_type=mail&lines=100')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['log_type'], 'mail')
        self.assertEqual(len(data['lines']), 3)
        mock_shell.assert_called_with('check_output', ['tail', '-n', '100', '/var/log/mail.log'], trap=True)

    @patch('daemon.auth_service.authenticate')
    @patch('daemon.utils.shell')
    @patch('os.path.exists')
    def test_get_logs_filter_regex(self, mock_exists, mock_shell, mock_authenticate):
        mock_authenticate.return_value = ('admin@example.com', ['admin'])
        mock_exists.return_value = True
        mock_shell.return_value = (0, "matched line 1\nmatched line 2\n")
        
        response = self.app.get('/system/logs?log_type=mail&lines=100&filter=matched&use_regex=true&case_sensitive=true')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['log_type'], 'mail')
        self.assertEqual(len(data['lines']), 2)
        mock_shell.assert_called_with('check_output', ['grep', '-E', 'matched', '/var/log/mail.log'], trap=True)

if __name__ == '__main__':
    unittest.main()

