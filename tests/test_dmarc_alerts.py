import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add management directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'management')))

import dmarc_alerts

class TestDmarcAlerts(unittest.TestCase):
    @patch('dmarc_alerts.load_environment')
    @patch('os.path.exists')
    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('builtins.open')
    @patch('dmarc_alerts.print')
    def test_dmarc_alerts_no_directory(self, mock_print, mock_open, mock_getmtime, mock_glob, mock_exists, mock_load_env):
        mock_load_env.return_value = {"STORAGE_ROOT": "/tmp/storage"}
        mock_exists.return_value = False
        
        dmarc_alerts.run_dmarc_check()
        mock_print.assert_not_called()

    @patch('dmarc_alerts.load_environment')
    @patch('os.path.exists')
    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('builtins.open')
    @patch('dmarc_alerts.print')
    def test_dmarc_alerts_high_failure(self, mock_print, mock_open, mock_getmtime, mock_glob, mock_exists, mock_load_env):
        mock_load_env.return_value = {"STORAGE_ROOT": "/tmp/storage"}
        mock_exists.return_value = True
        mock_glob.return_value = ["/tmp/storage/mail/dmarc/report.xml"]
        mock_getmtime.return_value = 100000000000.0 # Way in the future, past one_day_ago

        # Mock DMARC XML report with high failure rate
        xml_content = b"""<?xml version="1.0" encoding="UTF-8" ?>
        <feedback>
            <record>
                <row>
                    <source_ip>1.2.3.4</source_ip>
                    <count>10</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>fail</dkim>
                        <spf>fail</spf>
                    </policy_evaluated>
                </row>
            </record>
        </feedback>
        """
        
        mock_file = MagicMock()
        mock_file.read.return_value = xml_content
        mock_open.return_value.__enter__.return_value = mock_file

        dmarc_alerts.run_dmarc_check()

        # Check that warning was printed
        mock_print.assert_any_call("WARNING: High DMARC Authentication Failure Rates Detected!")
        mock_print.assert_any_call("Total Messages Reported: 10")
        mock_print.assert_any_call("SPF Failures: 10 (100.0%)")
        mock_print.assert_any_call("DKIM Failures: 10 (100.0%)")

    @patch('dmarc_alerts.load_environment')
    @patch('os.path.exists')
    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('builtins.open')
    @patch('dmarc_alerts.print')
    def test_dmarc_alerts_low_failure(self, mock_print, mock_open, mock_getmtime, mock_glob, mock_exists, mock_load_env):
        mock_load_env.return_value = {"STORAGE_ROOT": "/tmp/storage"}
        mock_exists.return_value = True
        mock_glob.return_value = ["/tmp/storage/mail/dmarc/report.xml"]
        mock_getmtime.return_value = 100000000000.0

        # Mock DMARC XML report with 0 failures
        xml_content = b"""<?xml version="1.0" encoding="UTF-8" ?>
        <feedback>
            <record>
                <row>
                    <source_ip>1.2.3.4</source_ip>
                    <count>10</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
            </record>
        </feedback>
        """
        
        mock_file = MagicMock()
        mock_file.read.return_value = xml_content
        mock_open.return_value.__enter__.return_value = mock_file

        dmarc_alerts.run_dmarc_check()
        mock_print.assert_not_called()

if __name__ == '__main__':
    unittest.main()
