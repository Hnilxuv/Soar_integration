import unittest
import requests_mock
from unittest.mock import patch, MagicMock
import orenctl
from azure_sql_management import (
    AzureSQLManagement,
    azure_sql_servers_list_command,
    azure_sql_db_list_command,
    azure_sql_db_audit_policy_list_command,
    azure_sql_db_audit_policy_create_update_command,
    azure_sql_db_threat_policy_create_update_command,
    azure_sql_db_threat_policy_get_command,
    subscriptions_list_command,
    resource_group_list_command
)


class TestAzureSQLManagement(unittest.TestCase):
    def setUp(self):
        # Mocking orenctl functions and parameters
        orenctl.getParam = MagicMock(side_effect=self.mock_get_param)
        orenctl.getArg = MagicMock(side_effect=self.mock_get_arg)

        # Mocking requests session and requests_mock
        self.mock_session = requests_mock.Mocker()
        self.mock_session.start()
        self.mock_session.post(
            f"https://login.microsoftonline.com/fake_tenant_id/oauth2/token",
            json={"access_token": "mocked_token"}
        )

        # Mocking AzureSQLManagement object
        self.mock_azure_sql_management = AzureSQLManagement()

    def tearDown(self):
        self.mock_session.stop()

    def mock_get_param(self, param_name):
        params = {
            "url": "https://fake.azure.com",
            "subscription_id": "fake_subscription_id",
            "resource_group_name": "fake_resource_group",
            "workspace_name": "fake_workspace",
            "tenant_id": "fake_tenant_id",
            "app_id": "fake_app_id",
            "app_secret": "fake_app_secret",
            "user_name": "fake_username",
            "password": "fake_password",
            "proxy": "https://fakeproxy.com",
            "auth_type": "client_credentials",
            "app_name": "fake_app_name",
            "verify": True,
            "api_version": "2022-01"
        }
        return params.get(param_name)

    def mock_get_arg(self, arg_name):
        args = {
            "offset": "0",
            "limit": "50",
            "resource_group_name": "fake_resource_group",
            "subscription_id": "fake_subscription_id",
            "server_name": "fake_server_name",
            "db_name": "fake_db_name",
            "state": "enabled",
            "audit_actions_groups": "DB_READ",
            "is_azure_monitor_target_enabled": "true",
            "is_storage_secondary_key_in_use": "false",
            "queue_delay_ms": "1000",
            "retention_days": "365",
            "storage_account_access_key": "fake_access_key",
            "storage_account_subscription_id": "fake_storage_subscription_id",
            "storage_endpoint": "https://fakestorage.blob.core.windows.net",
            "is_managed_identity_in_use": "false",
            "disabled_alerts": "High CPU Usage",
            "email_account_admins": "true",
            "email_addresses": "admin@example.com",
            "use_server_default": "true",
        }
        return args.get(arg_name)

    def test_servers_list_command(self):
        expected_result = {'status_command': 'Success', 'server_list': ['server1', 'server2'],
                           'message': 'The list of servers in the resource group: fake_resource_group'}
        self.mock_session.get(
            "https://fake.azure.com/subscriptions/fake_subscription_id/resourceGroups/"
            "fake_resource_group/providers/Microsoft.Sql/servers?api-version=2022-01",
            json={"value": ["server1", "server2"]}
        )

        with patch('orenctl.results') as mock_results:
            azure_sql_servers_list_command()
            mock_results.assert_called_once_with(expected_result)

    def test_db_list_command(self):
        expected_result = {"status_command": "Success", "database_list": ["db1", "db2"]}
        self.mock_session.get(
            "https://fake.azure.com/subscriptions/fake_subscription_id/resourceGroups/"
            "fake_resource_group/providers/Microsoft.Sql/servers/fake_server_name/databases",
            json={"value": ["db1", "db2"]}
        )

        with patch('orenctl.results') as mock_results:
            azure_sql_db_list_command()
            mock_results.assert_called_once_with(expected_result)

    def test_db_audit_policy_list_command(self):
        expected_result = {"status_command": "Success", "audit_policy_list": ["policy1", "policy2"]}
        self.mock_session.get(
            "https://fake.azure.com/subscriptions/fake_subscription_id/resourceGroups/"
            "fake_resource_group/providers/Microsoft.Sql/servers/fake_server_name/databases/"
            "fake_db_name/auditingSettings",
            json={"value": ["policy1", "policy2"]}
        )

        with patch('orenctl.results') as mock_results:
            azure_sql_db_audit_policy_list_command()
            mock_results.assert_called_once_with(expected_result)

    def test_db_audit_policy_create_update_command(self):
        expected_result = {"status_command": "Success", "audit_policy": {"state": "enabled"}}
        self.mock_session.put(
            "https://fake.azure.com/subscriptions/fake_subscription_id/resourceGroups/"
            "fake_resource_group/providers/Microsoft.Sql/servers/fake_server_name/databases/"
            "fake_db_name/auditingSettings/default",
            json={"state": "enabled"}
        )

        with patch('orenctl.results') as mock_results:
            azure_sql_db_audit_policy_create_update_command()
            mock_results.assert_called_once_with(expected_result)

    def test_db_threat_policy_create_update_command(self):
        expected_result = {"status_command": "Success", "threat_policy": {"state": "enabled"}}
        self.mock_session.put(
            "https://fake.azure.com/subscriptions/fake_subscription_id/resourceGroups/"
            "fake_resource_group/providers/Microsoft.Sql/servers/fake_server_name/databases/"
            "fake_db_name/auditingSettings/default",
            json={"state": "enabled"}
        )

        with patch('orenctl.results') as mock_results:
            azure_sql_db_threat_policy_create_update_command()
            mock_results.assert_called_once_with(expected_result)

    def test_db_threat_policy_get_command(self):
        expected_result = {"status_command": "Success", "threat_policy": {"state": "enabled"}}
        self.mock_session.get(
            "https://fake.azure.com/subscriptions/fake_subscription_id/resourceGroups/"
            "fake_resource_group/providers/Microsoft.Sql/servers/fake_server_name/databases/"
            "fake_db_name/securityAlertPolicies/default",
            json={"state": "enabled"}
        )

        with patch('orenctl.results') as mock_results:
            azure_sql_db_threat_policy_get_command()
            mock_results.assert_called_once_with(expected_result)

    def test_subscriptions_list_command(self):
        expected_result = {"status_command": "Success", "subscriptions_list": {"subscriptions": ["sub1", "sub2"]}}
        self.mock_session.get(
            "https://management.azure.com/subscriptions",
            json={"subscriptions": ["sub1", "sub2"]}
        )

        with patch('orenctl.results') as mock_results:
            subscriptions_list_command()
            mock_results.assert_called_once_with(expected_result)

    def test_resource_group_list_command(self):
        expected_result = {"status_command": "Success", "subscriptions_list": {"resource_groups": ["rg1", "rg2"]}}
        self.mock_session.get(
            "https://management.azure.com/subscriptions/fake_subscription_id/"
            "resourcegroups&$top=50?api-version=2022-01",
            json={"resource_groups": ["rg1", "rg2"]}
        )

        with patch('orenctl.results') as mock_results:
            resource_group_list_command()
            mock_results.assert_called_once_with(expected_result)


if __name__ == '__main__':
    unittest.main()
