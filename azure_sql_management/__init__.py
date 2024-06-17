import requests

import orenctl


def assign_params(keys_to_ignore=None, values_to_ignore=None, **kwargs):
    if values_to_ignore is None:
        values_to_ignore = (None, "", [], {}, ())
    if keys_to_ignore is None:
        keys_to_ignore = tuple()
    return {
        key: value for key, value in kwargs.items()
        if value not in values_to_ignore and key not in keys_to_ignore
    }


class AzureSQLManagement:
    def __init__(self):
        self.resource = orenctl.getArg("url")
        self.subscription_id = orenctl.getArg("subscription_id")
        self.resource_group_name = orenctl.getArg("resource_group_name")
        self.workspace_name = orenctl.getArg("workspace_name")
        self.base_url = f"{self.resource}/subscriptions/{self.subscription_id}/resourceGroups/" \
                        f"{self.resource_group_name}/providers"
        self.tenant_id = orenctl.getArg("tenant_id")
        self.app_id = orenctl.getArg("app_id")
        self.app_secret = orenctl.getArg("app_secret")
        self.user_name = orenctl.getArg("user_name")
        self.password = orenctl.getArg("password")
        self.proxy = orenctl.getArg("proxy")
        self.auth_type = orenctl.getArg("auth_type")
        self.app_name = orenctl.getArg("app_name")
        self.verify = orenctl.getArg("verify") if orenctl.getArg("verify") else False
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, url, *args, **kwargs):
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise Exception(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_access_token(self):

        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        if self.auth_type == "client_credentials":

            body = {
                "resource": self.resource,
                "client_id": self.app_id,
                "client_secret": self.app_secret,
                "grant_type": "client_credentials"
            }
        else:
            body = {
                "resource": self.resource,
                "client_id": self.app_id,
                "username": self.user_name,
                "password": self.password,
                "grant_type": "password"
            }
        response = self.http_request(url=url, method="POST", data=body, headers=headers)
        access_token = response.get("access_token")
        self.session.headers.update({"Authorization": f"Bearer {access_token}"})
        return access_token

    def azure_sql_db_audit_policy_create_update(self):
        properties = assign_params(state=orenctl.getArg("state"),
                                   auditActionsAndGroups=orenctl.getArg("audit_actions_groups"),
                                   isAzureMonitorTargetEnabled=orenctl.getArg("is_azure_monitor_target_enabled"),
                                   isStorageSecondaryKeyInUse=orenctl.getArg("is_storage_secondary_key_in_use"),
                                   queueDelayMs=orenctl.getArg("queue_delay_ms"),
                                   retentionDays=orenctl.getArg("retention_days"),
                                   storageAccountAccessKey=orenctl.getArg("storage_account_access_key"),
                                   storageAccountSubscriptionId=orenctl.getArg("storage_account_subscription_id"),
                                   storageEndpoint=orenctl.getArg("storage_endpoint"),
                                   isManagedIdentityInUse=orenctl.getArg("is_managed_identity_in_use"))
        server_name = orenctl.getArg("server_name")
        db_name = orenctl.getArg("db_name")
        request_body = {"properties": properties} if properties else {}
        url = self.base_url + f"/Microsoft.Sql/servers/{server_name}/databases/" \
                              f"{db_name}/auditingSettings/default"
        return self.http_request(method="PUT", url=url, data=request_body)

    def azure_sql_servers_list(self):
        resource_group_name = orenctl.getArg("server_name")
        url = self.base_url + f"/Microsoft.Sql/servers"
        if resource_group_name:
            return self.http_request("GET", f"/resourceGroups/{resource_group_name}/providers/Microsoft.Sql/servers")
        return self.http_request("GET", "/providers/Microsoft.Sql/servers")


    def azure_sql_db_list(self, server_name: str):
        return self.http_request("GET", f"resourceGroups/{self.resource_group_name}/providers/Microsoft.Sql/servers/"
                                        f"{server_name}/databases")

    def azure_sql_db_audit_policy_list(self, server_name: str, db_name: str, resource_group_name: str):
        return self.http_request("GET", f"resourceGroups/{resource_group_name}/providers/Microsoft.Sql/servers/"
                                        f"{server_name}/databases/{db_name}/auditingSettings")


    def azure_sql_db_threat_policy_get(self, server_name: str, db_name: str):
        return self.http_request("GET", f"resourceGroups/{self.resource_group_name}/providers/Microsoft.Sql/servers/"
                                        f"{server_name}/databases/{db_name}/securityAlertPolicies/default")


    def azure_sql_db_threat_policy_create_update(self):

        properties = assign_params(state=orenctl.getArg("state"),
                                   retentionDays=orenctl.getArg("retention_days"),
                                   storageAccountAccessKey=orenctl.getArg("storage_account_access_key"),
                                   storageEndpoint=orenctl.getArg("storage_endpoint"),
                                   disabledAlerts=orenctl.getArg("disabled_alerts"),
                                   emailAccountAdmins=orenctl.getArg("email_account_admins"),
                                   emailAddresses=orenctl.getArg("email_addresses"),
                                   use_server_default=orenctl.getArg("use_server_default"))
        server_name = orenctl.getArg("server_name")
        db_name = orenctl.getArg("db_name")
        request_body = {"properties": properties} if properties else {}
        url = self.base_url + f"/Microsoft.Sql/servers/{server_name}/databases/" \
                              f"{db_name}/auditingSettings/default"
        return self.http_request(method="PUT", url=url, data=request_body)