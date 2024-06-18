import copy
import requests
import orenctl
DEFAULT_API_VERSION = "2021-11-01"


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
        self.resource = orenctl.getParam("url")
        self.subscription_id = orenctl.getParam("subscription_id")
        self.resource_group_name = orenctl.getParam("resource_group_name")
        self.workspace_name = orenctl.getParam("workspace_name")
        self.base_url = self.resource
        self.tenant_id = orenctl.getParam("tenant_id")
        self.app_id = orenctl.getParam("app_id")
        self.app_secret = orenctl.getParam("app_secret")
        self.user_name = orenctl.getParam("user_name")
        self.password = orenctl.getParam("password")
        self.proxy = orenctl.getParam("proxy")
        self.auth_type = orenctl.getParam("auth_type")
        self.app_name = orenctl.getParam("app_name")
        self.verify = orenctl.getParam("verify") if orenctl.getArg("verify") else False
        self.api_version = orenctl.getParam("api_version") if orenctl.getParam("api_version") else DEFAULT_API_VERSION
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, url, *args, **kwargs):
        response = self.session.request(method=method, url=url, verify=self.verify, *args, **kwargs)
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

    def db_audit_policy_create_update(self, server_name, db_name, data, resource_group_name, subscription_id):
        if not resource_group_name:
            resource_group_name = self.resource_group_name
        if not subscription_id:
            subscription_id = self.subscription_id
        params = {"api-version": self.api_version}
        url = self.base_url + f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}" \
                              f"/providers/Microsoft.Sql/servers/{server_name}" \
                              f"/databases/{db_name}/auditingSettings/default"
        return self.http_request(method="PUT", url=url, data=data, params=params)

    def servers_list(self, resource_group_name, subscription_id):
        params = {"api-version": self.api_version}
        if not subscription_id:
            subscription_id = self.subscription_id
        url = self.base_url + f"/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers"
        if resource_group_name:
            url = self.base_url + f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}" \
                                  f"/providers/Microsoft.Sql/servers"
        return self.http_request(method="GET", url=url, params=params)

    def db_list(self, server_name, resource_group_name, subscription_id):
        params = {"api-version": self.api_version}
        if not subscription_id:
            subscription_id = self.subscription_id
        if not resource_group_name:
            resource_group_name = self.resource_group_name
        url = self.base_url + f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}" \
                              f"/providers/Microsoft.Sql/servers/" \
                              f"{server_name}/databases"
        return self.http_request(method="GET", url=url, params=params)

    def db_audit_policy_list(self, server_name, db_name, resource_group_name, subscription_id):
        if not resource_group_name:
            resource_group_name = self.resource_group_name
        if not subscription_id:
            subscription_id = self.subscription_id
        params = {"api-version": self.api_version}
        url = self.base_url + f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}" \
                              f"/providers/Microsoft.Sql/servers/" \
                              f"{server_name}/databases/{db_name}/auditingSettings"
        return self.http_request(method="GET", url=url, params=params)

    def db_threat_policy_get(self, server_name, db_name, resource_group_name, subscription_id,):
        params = {"api-version": self.api_version}
        if not subscription_id:
            subscription_id = self.subscription_id
        if not resource_group_name:
            resource_group_name = self.resource_group_name
        url = self.base_url + f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}" \
                              f"/providers/Microsoft.Sql/servers/" \
                              f"{server_name}/databases/{db_name}/securityAlertPolicies/default"
        return self.http_request(method="GET", url=url, params=params)

    def db_threat_policy_create_update(self, server_name, db_name, data, resource_group_name, subscription_id):
        params = {"api-version": self.api_version}
        if not resource_group_name:
            resource_group_name = self.resource_group_name
        if not subscription_id:
            subscription_id = self.subscription_id
        url = self.base_url + f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}" \
                              f"/providers/Microsoft.Sql/servers/" \
                              f"{server_name}/databases/{db_name}/auditingSettings/default"
        return self.http_request(method="PUT", url=url, data=data, params=params)

    def subscriptions_list_request(self):
        params = {"api-version": self.api_version}
        return self.http_request(
            method="GET",
            url="https://management.azure.com/subscriptions", params=params)

    def resource_group_list_request(self, subscription_id, tag, limit):
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups"
        params = {"api-version": self.api_version}
        if tag:
            tag_split = tag.split(":")
            tag_name = tag_split[0]
            tag_value = tag_split[1]
            url = f"{url}&$filter=tagName eq '{tag_name}' and tagValue eq '{tag_value}'"
        if limit:
            url = f"{url}&$top={limit}"
        return self.http_request(method="GET", url=url, params=params)


def azure_sql_servers_list_command():
    offset = int(orenctl.getArg("offset")) if orenctl.getArg("offset") else 0
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 50
    resource_group_name = orenctl.getArg("resource_group_name")
    subscription_id = orenctl.getArg("subscription_id")
    message = "Server List"
    if resource_group_name:
        message = f"The list of servers in the resource group: {resource_group_name}"
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.servers_list(resource_group_name, subscription_id)
    server_list = copy.deepcopy(result.get('value', '')[offset:(offset + limit)])
    orenctl.results({
        "status_command": "Success",
        "server_list": server_list,
        "message": message
    })


def azure_sql_db_list_command():
    offset = int(orenctl.getArg("offset")) if orenctl.getArg("offset") else 0
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 50
    server_name = orenctl.getArg("server_name")
    subscription_id = orenctl.getArg("subscription_id")
    resource_group_name = orenctl.getArg("resource_group_name")
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.db_list(server_name, resource_group_name, subscription_id)
    database_list = copy.deepcopy(result.get('value', '')[offset:(offset + limit)])
    orenctl.results({
        "status_command": "Success",
        "database_list": database_list,
    })


def azure_sql_db_audit_policy_list_command():
    offset = int(orenctl.getArg("offset")) if orenctl.getArg("offset") else 0
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 50
    server_name = orenctl.getArg("server_name")
    db_name = orenctl.getArg("db_name")
    resource_group_name = orenctl.getArg("resource_group_name")
    subscription_id = orenctl.getArg("subscription_id")
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.db_audit_policy_list(server_name, db_name, resource_group_name, subscription_id)
    audit_policy_list = copy.deepcopy(result.get('value', '')[offset:(offset + limit)])
    orenctl.results({
        "status_command": "Success",
        "audit_policy_list": audit_policy_list,
    })


def azure_sql_db_audit_policy_create_update_command():
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
    resource_group_name = orenctl.getArg("resource_group_name")
    subscription_id = orenctl.getArg("subscription_id")
    data = {"properties": properties} if properties else {}
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.db_audit_policy_create_update(server_name, db_name, data, resource_group_name, subscription_id)
    orenctl.results({
        "status_command": "Success",
        "audit_policy": result,
    })


def azure_sql_db_threat_policy_create_update_command():
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
    resource_group_name = orenctl.getArg("resource_group_name")
    subscription_id = orenctl.getArg("subscription_id")
    data = {"properties": properties} if properties else {}
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.db_threat_policy_create_update(server_name, db_name, data, resource_group_name, subscription_id)
    orenctl.results({
        "status_command": "Success",
        "threat_policy": result,
    })


def azure_sql_db_threat_policy_get_command():

    server_name = orenctl.getArg("server_name")
    db_name = orenctl.getArg("db_name")
    resource_group_name = orenctl.getArg("resource_group_name")
    subscription_id = orenctl.getArg("subscription_id")
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.db_threat_policy_get(server_name, db_name, resource_group_name, subscription_id)
    orenctl.results({
        "status_command": "Success",
        "threat_policy": result,
    })


def subscriptions_list_command():
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.subscriptions_list_request()
    orenctl.results({
        "status_command": "Success",
        "subscriptions_list": result,
    })


def resource_group_list_command():
    subscription_id = orenctl.getArg("subscription_id")
    tag = orenctl.getArg("tag")
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 50
    ASM = AzureSQLManagement()
    ASM.get_access_token()
    result = ASM.resource_group_list_request(subscription_id, tag, limit)
    orenctl.results({
        "status_command": "Success",
        "subscriptions_list": result,
    })


if orenctl.command() == "azure_sql_subscriptions_list":
    subscriptions_list_command()
if orenctl.command() == "azure_sql_resource_group_list":
    resource_group_list_command()
if orenctl.command() == "azure_sql_servers_list":
    azure_sql_servers_list_command()
if orenctl.command() == "azure_sql_db_list":
    azure_sql_db_list_command()
if orenctl.command() == "azure_sql_db_audit_policy_list":
    azure_sql_db_audit_policy_list_command()
if orenctl.command() == "azure_sql_db_threat_policy_get":
    azure_sql_db_threat_policy_get_command()
if orenctl.command() == "azure_sql_db_threat_policy_create_update":
    azure_sql_db_threat_policy_create_update_command()
if orenctl.command() == "azure_sql_db_audit_policy_create_update":
    azure_sql_db_audit_policy_create_update_command()


