import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import json

from aws_security_hub import get_findings_command, disable_security_hub_command, enable_security_hub_command, \
    get_master_account_command, list_members_command, update_findings_command, batch_update_findings_command, \
    feed_alerts


# Assume the following imports are correct for your environment
# from aws_security_hub import AwsSecurityHub, get_findings_command, disable_security_hub_command, etc.

class MockOrenctl:
    @staticmethod
    def getParam(param):
        params = {
            "access_key": "test_access_key",
            "secret_key": "test_secret_key",
            "region": "us-west-1",
            "proxy": None,
            "insecure": False,
            "retries": 5,
            "timeout": None
        }
        return params.get(param)

    @staticmethod
    def getArg(arg):
        args = {
            "raw_json": '{"Filters": {}}',
            "tags": [],
            "only_associated": "true",
            "next_token": None,
            "finding_id": "test-id",
            "recordState": "ACTIVE",
            "updated_by": "test-user",
            "note": "test-note",
            "finding_identifiers_id": "test-id",
            "finding_identifiers_product_arn": "test-product-arn",
            "note_text": "test-note-text",
            "note_updated_by": "test-note-updated-by",
            "severity_label": "CRITICAL",
            "verification_state": None,
            "types": None,
            "user_defined_fields": None,
            "workflow_status": None,
            "related_findings_product_arn": "test-related-product-arn",
            "related_findings_id": "test-related-id"
        }
        return args.get(arg)

    @staticmethod
    def getHeader(header):
        headers = {
            "aws_sh_severity": "CRITICAL",
            "finding_types": ["Software and Configuration Checks"],
            "workflow_status": ["NEW", "NOTIFIED"],
            "max_alert": "500",
            "product_name": "Security Hub",
            "archive_findings": True
        }
        return headers.get(header)

    @staticmethod
    def results(result):
        print(json.dumps(result))

    @staticmethod
    def error(message):
        return {"error": message}


class MockDatafeedctl:
    @staticmethod
    def get_last_run_status():
        return json.dumps({
            "extra_info": {
                "timestamp": int(time.time() * 1000) - 24 * 60 * 60 * 1000,  # 1 day ago
                "last_alert_id": "test-alert-id",
                "last_next_token": "test-next-token"
            }
        })

    @staticmethod
    def sync_alerts(alerts, extra_info):
        print(f"Alerts synced: {alerts}")
        print(f"Extra info: {extra_info}")


class MockAwsSecurityHub:
    @staticmethod
    def create_client():
        client = MagicMock()
        client.exceptions.InvalidInputException = Exception
        client.get_findings.return_value = {
            "Findings": [{"Id": "test-id", "CreatedAt": datetime.now(timezone.utc).isoformat()}],
            "NextToken": None
        }
        return client


class TestAwsSecurityHubCommands(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.get_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Findings": [{"Id": "test-id"}],
            "NextToken": None
        }
        self.mock_client.disable_security_hub.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.batch_update_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.enable_security_hub.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.get_master_account.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.list_members.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Members": [{"MemberId": "test-member"}]
        }
        self.mock_client.update_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_get_findings_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_findings_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "findings": [{"Id": "test-id"}]
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=lambda x: None if x == "raw_json" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_get_findings_command_no_filters(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_findings_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "findings": [{"Id": "test-id"}]
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_get_findings_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        expected_result = {
            "ResponseMetadata": {"HTTPStatusCode": 400},
        }
        self.mock_client.get_findings.return_value = expected_result
        mock_boto_client.return_value = self.mock_client

        get_findings_command()

        mock_results.assert_called_with({
            "status_command": "Fail",
            "findings": expected_result
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_disable_security_hub_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        disable_security_hub_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "security_hub": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=lambda x: None if x == "raw_json" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_disable_security_hub_command_no_raw_json(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        disable_security_hub_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "security_hub": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_disable_security_hub_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        expected_result = {
            "ResponseMetadata": {"HTTPStatusCode": 400},
        }
        self.mock_client.disable_security_hub.return_value = expected_result
        mock_boto_client.return_value = self.mock_client

        disable_security_hub_command()

        mock_results.assert_called_with({
            "status_command": "Fail",
            "security_hub": expected_result
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_enable_security_hub_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        enable_security_hub_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "security_hub": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=lambda x: None if x == "raw_json" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_enable_security_hub_command_no_raw_json(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        enable_security_hub_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "security_hub": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_enable_security_hub_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        self.mock_client.enable_security_hub.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_client

        enable_security_hub_command()

        mock_results.assert_called_with({
            "status_command": "Fail",
            "security_hub": {
                "ResponseMetadata": {"HTTPStatusCode": 400}
            }
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_get_master_account_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_master_account_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "master_account": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=lambda x: None if x == "raw_json" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_get_master_account_command_no_raw_json(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_master_account_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "master_account": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_get_master_account_command_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        self.mock_client.get_master_account.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_client

        get_master_account_command()

        mock_results.assert_called_with({
            "status_command": "Fail",
            "master_account": {
                "ResponseMetadata": {"HTTPStatusCode": 400}
            }
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_list_members_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        list_members_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "members": {"Members": [{"MemberId": "test-member"}]}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg',
           side_effect=lambda x: None if x == "only_associated" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_list_members_command_no_only_associated(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        list_members_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "members": {"Members": [{"MemberId": "test-member"}]}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_get_master_account_command_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        self.mock_client.list_members.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_client

        list_members_command()

        mock_results.assert_called_with({
            "status_command": "Fail",
            "members": {
                "ResponseMetadata": {"HTTPStatusCode": 400}
            }
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_update_findings_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        update_findings_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "updated_findings": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg',
           side_effect=lambda x: None if x == "finding_id" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_update_findings_command_no_finding_id(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        update_findings_command()

        mock_results.assert_called_with(
            {'Type': 2, 'Contents': 'finding_id is required', 'ContentsFormat': 'text'}
        )

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_security_hub.orenctl.results')
    def test_batch_update_findings_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        batch_update_findings_command()

        mock_results.assert_called_with({
            "status_command": "Success",
            "updated_findings": {}
        })

    @patch('aws_security_hub.boto3.client')
    @patch('aws_security_hub.orenctl.getArg',
           side_effect=lambda x: None if x == "finding_identifiers_id" else MockOrenctl.getArg(x))
    @patch('aws_security_hub.orenctl.results')
    def test_batch_update_findings_command_no_finding_id(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        batch_update_findings_command()

        mock_results.assert_called_with(
            {'Type': 2, 'Contents': 'finding_identifiers_id is required', 'ContentsFormat': 'text'}
        )

    @patch('aws_security_hub.orenctl', new=MockOrenctl)
    @patch('aws_security_hub.datafeedctl', new=MockDatafeedctl)
    @patch('aws_security_hub.AwsSecurityHub', new=MockAwsSecurityHub)
    def test_feed_alerts_success(self):
        alerts = feed_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertIn("test-id", alerts[0].get("security_hub_id", ""))

    @patch('aws_security_hub.orenctl', new=MockOrenctl)
    @patch('aws_security_hub.datafeedctl', new=MockDatafeedctl)
    @patch('aws_security_hub.AwsSecurityHub', new=MockAwsSecurityHub)
    def test_feed_alerts_no_last_alert(self):
        with patch.object(MockDatafeedctl, 'get_last_run_status', return_value=None):
            alerts = feed_alerts()
            self.assertEqual(len(alerts), 1)
            self.assertIn("test-id", alerts[0].get("security_hub_id", ""))

    @patch('aws_security_hub.orenctl', new=MockOrenctl)
    @patch('aws_security_hub.datafeedctl', new=MockDatafeedctl)
    @patch('aws_security_hub.AwsSecurityHub', new=MockAwsSecurityHub)
    def test_feed_alerts_fail_get_findings(self):
        client = MockAwsSecurityHub.create_client()
        client.get_findings.side_effect = [
            client.exceptions.InvalidInputException("InvalidInputException"),
            {"Findings": [], "NextToken": None}
        ]
        with patch('aws_security_hub.AwsSecurityHub.create_client', return_value=client):
            alerts = feed_alerts()
            self.assertEqual(alerts, None)

    @patch('aws_security_hub.orenctl', new=MockOrenctl)
    @patch('aws_security_hub.datafeedctl', new=MockDatafeedctl)
    @patch('aws_security_hub.AwsSecurityHub', new=MockAwsSecurityHub)
    def test_feed_alerts_archive_findings(self):
        alerts = feed_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertIn("test-id", alerts[0].get("security_hub_id", ""))


if __name__ == '__main__':
    unittest.main()
