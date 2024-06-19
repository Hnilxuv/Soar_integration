import json
import re
import time
from datetime import datetime, timezone, timedelta
import boto3
import dateparser
from botocore.config import Config
import urllib3
import orenctl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SERVICE_NAME = "securityhub"
from aws_security_hub import datafeedctl


def camel_to_snake(name):
    # Thêm dấu gạch dưới trước các chữ cái viết hoa và chuyển tất cả về chữ thường
    snake = re.sub("([A-Z])", r"_\1", name).lower()
    # Xóa dấu gạch dưới ở đầu (nếu có)
    if snake.startswith("_"):
        snake = snake[1:]
    return snake


class AwsSecurityHub(object):
    def __init__(self):
        self.access_key = orenctl.getParam("access_key")
        self.secret_key = orenctl.getParam("secret_key")
        self.region = orenctl.getParam("region")
        self.proxy = orenctl.getParam("proxy")
        self.verify = True if orenctl.getParam("insecure") else False
        self.retries = orenctl.getParam("retries") or 5
        self.timeout = orenctl.getParam("timeout")
        self.proxy_dict = {}
        if self.proxy:
            self.proxy_dict = {
                "http": self.proxy,
                "https": self.proxy
            }
        if int(self.retries) > 10:
            self.retries = 10

    def create_client(self):
        try:
            boto_config = Config(retries=dict(
                max_attempts=int(self.retries)
            ))
            if self.proxy_dict:
                boto_config.merge(Config(proxies=self.proxy_dict))

            if self.timeout:
                boto_config.merge(Config(connect_timeout=int(self.timeout)))

            client = boto3.client(service_name=SERVICE_NAME,
                                  region_name=self.region,
                                  aws_access_key_id=self.access_key,
                                  aws_secret_access_key=self.secret_key,
                                  verify=self.verify,
                                  config=boto_config)
            return client
        except Exception as e:
            orenctl.results(orenctl.error("Could not create boto3 client: {0}".format(e)))
            raise Exception("Could not create boto3 client: {0}".format(e))


def remove_empty_elements(d):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary.
    :param d: Input dictionary.
    :type d: dict
    :return: Dictionary with all empty lists, and empty dictionaries removed.
    :rtype: dict
    """

    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


def safe_load_json(json_object):
    """
    Safely loads a JSON object from an argument. Allows the argument to accept either a JSON in string form,
    or an entry ID corresponding to a JSON file.

    :param json_object: Entry ID or JSON string.
    :type json_object: str
    :return: Dictionary object from a parsed JSON file or string.
    :rtype: dict
    """
    safe_json = None
    if isinstance(json_object, dict) or isinstance(json_object, list):
        return json_object
    try:
        safe_json = json.loads(json_object)
    except ValueError as e:
        orenctl.results(orenctl.error((
                "Unable to parse JSON string. Please verify the JSON is valid." + str(e))))

    return safe_json


def get_findings_command():
    kwargs = {}
    kwargs = get_raw_json_arg(kwargs)
    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.get_findings(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        return orenctl.results({
            "status_command": "Fail",
            "findings": response
        })

    findings = response.get("Findings", [])
    next_token = response.get("NextToken")
    while next_token:
        kwargs["NextToken"] = next_token
        findings.extend(response.get("Findings"))
        response = client.get_findings(**kwargs)
        next_token = response.get("NextToken")

    orenctl.results({
        "status_command": "Success",
        "findings": findings
    })
    return


def get_raw_json_arg(kwargs):
    raw_json = orenctl.getArg("raw_json")
    if raw_json and not kwargs:
        del kwargs
        kwargs = safe_load_json(raw_json)
    elif orenctl.getArg("raw_json") is not None and kwargs:
        orenctl.results(orenctl.error("Please remove other arguments before using \"raw-json\"."))
        return
    return kwargs


def disable_security_hub_command():
    kwargs = safe_load_json(orenctl.getArg("raw_json")) if orenctl.getArg("raw_json") else {}

    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.disable_security_hub(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "security_hub": response
        })
        return
    del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "security_hub": response
    })
    return


def enable_security_hub_command():
    kwargs = {
        "Tags": orenctl.getArg("tags") if orenctl.getArg("tags") else []

    }
    kwargs = remove_empty_elements(kwargs)
    kwargs = get_raw_json_arg(kwargs)
    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.enable_security_hub(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "security_hub": response
        })
        return
    del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "security_hub": response
    })
    return


def get_master_account_command():
    kwargs = safe_load_json(orenctl.getArg("raw_json")) if orenctl.getArg("raw_json") else {}

    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.get_master_account(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "master_account": response
        })
        return
    del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "master_account": response
    })
    return


def list_members_command():
    kwargs = {
        "OnlyAssociated": True if orenctl.getArg("only_associated") == "true" else None,
        "NextToken": orenctl.getArg("next_token")
    }
    kwargs = remove_empty_elements(kwargs)
    get_raw_json_arg(kwargs)
    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.list_members(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "members": response
        })
        return
    del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "members": response
    })
    return


def update_findings_command():
    finding_id = orenctl.getArg("finding_id")
    if not finding_id:
        return orenctl.results(orenctl.error("finding_id is required"))
    kwargs = {
        "Filters": {
            "Id": [
                {
                    "Value": finding_id,
                    "Comparison": "EQUALS"
                },
            ]
        },
        "RecordState": orenctl.getArg("recordState"),
    }
    note = orenctl.getArg("note")
    updated_by = orenctl.getArg("updated_by")
    if note and updated_by:
        kwargs["Note"] = {
            "Text": note,
            "UpdateBy": updated_by
        }
    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.update_findings(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "updated_findings": response
        })
        return
    del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "updated_findings": response
    })
    return


def batch_update_findings_command():
    finding_identifiers_id = orenctl.getArg("finding_identifiers_id")
    if not finding_identifiers_id:
        return orenctl.results(orenctl.error("finding_identifiers_id is required"))
    finding_identifiers_product_arn = orenctl.getArg("finding_identifiers_product_arn")
    if not finding_identifiers_product_arn:
        return orenctl.results(orenctl.error("finding_identifiers_product_arn is required"))
    kwargs = {
        "FindingIdentifiers": [
            {
                "Id": finding_identifiers_id,
                "ProductArn": finding_identifiers_product_arn,
            },
        ],
        "Note": {
            "Text": orenctl.getArg("note_text"),
            "UpdatedBy": orenctl.getArg("note_updated_by"),

        },
        "Severity": {
            "Label": orenctl.getArg("severity_label"),

        },
        "VerificationState": orenctl.getArg("verification_state"),
        "Types": orenctl.getArg("types"),
        "UserDefinedFields": orenctl.getArg("user_defined_fields"),
        "Workflow": {
            "Status": orenctl.getArg("workflow_status"),
        },
        "RelatedFindings": [{
            "ProductArn": orenctl.getArg("related_findings_product_arn"),
            "Id": orenctl.getArg("related_findings_id"),
        }],
    }
    kwargs = remove_empty_elements(kwargs)
    get_raw_json_arg(kwargs)
    ASH = AwsSecurityHub()
    client = ASH.create_client()
    response = client.batch_update_findings(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "updated_findings": response
        })
        return
    del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "updated_findings": response
    })
    return


def feed_alerts():
    def get_last_alert():
        """
        Lấy alert cuối cùng đã từng lấy. nếu không có thì lấy tối đa 3 ngày trước đó.
        :return:
        """

        result = datafeedctl.get_last_run_status()
        # orenctl.log(f"get_last_run_status = {result}")
        if not result:
            return {}
        if isinstance(result, str):
            try:
                result = json.loads(result)
                result = result.get("extra_info")
            except Exception as e:
                raise Exception(
                    f"get_last_run_status error. data={result}. Exception={e}"
                )
        else:
            result = result.get("extra_info")
        timestamp = None
        last_alert_id = None
        last_next_token = None
        if result and isinstance(result, dict):
            for key, value in result.items():
                if key == "timestamp":
                    timestamp = value
                if key == "last_alert_id":
                    last_alert_id = value
                if key == "last_next_token":
                    last_next_token = value
        last_10m = int(time.time() * 1000) - 10 * 60 * 1000

        if timestamp > last_10m:
            return last_10m
        last_alert = {
            "last_alert_time": timestamp,
            "last_alert_id": last_alert_id,
            "last_next_token": last_next_token
        }
        return last_alert

    def normalize_alert(alert_list):
        normalize_alerts = []
        for alert in alert_list:
            alert = {camel_to_snake(key): value for key, value in alert.items()}

            if "organization_group" not in alert:
                alert["organization_group"] = ""

            if "owner" not in alert:
                alert["owner"] = ""

            if "source" not in alert:
                alert["owner"] = "AWS Security Hub"

            if "id" in alert:
                alert["security_hub_id"] = alert.get("id")
            create_time = dateparser.parse(alert.get("created_at"))
            alert["timestamp"] = int(create_time.timestamp() * 1000)

            delete_key = []
            for key in alert:
                if alert[key] is None:
                    delete_key.append(key)
            for key in delete_key:
                del alert[key]
            normalize_alerts.append(alert)

        return normalize_alerts

    def build_severity_label_obj(label: str):
        severity_dict = {
            "Informational": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }
        severity_label_obj = []
        num = severity_dict.get(label, -1)  # -1 is smaller than all -> all the severities will be in the object.
        for lbl in severity_dict:
            key = severity_dict.get(lbl, 5)  # 5 is bigger than all -> all the severities will be in the object.
            # in order to get incident with equal or higher severity we need to add all the relevant severities to 
            # this object, and then the API will return all the incidents that are equal to one of the severities we 
            # provided.
            if key >= num:
                severity_label_obj.append({
                    "Comparison": "EQUALS",
                    "Value": lbl.upper()
                })
        return severity_label_obj

    def create_filters_list_dictionaries(arr, compare_param):
        result_arr = []
        for item in arr:
            d = {
                "Comparison": compare_param,
                "Value": item
            }
            result_arr.append(d)
        return result_arr

    aws_sh_severity = orenctl.getHeader("aws_sh_severity")
    finding_types = orenctl.getHeader("finding_types")
    workflow_status = orenctl.getHeader("workflow_status")
    max_alert = int(orenctl.getHeader("max_alert")) if orenctl.getHeader("max_alert") else 500
    product_name = orenctl.getHeader("product_name")
    archive_findings = orenctl.getHeader("archive_findings")

    last_alert = get_last_alert()
    last_alert_time = last_alert.get("last_alert_time", None)
    last_next_token = last_alert.get("last_next_token", None)
    last_alert_id = last_alert.get("last_alert_id", None)
    if not last_alert_time:
        date_from = dateparser.parse("{3 days UTC")
        last_alert_time = date_from.isoformat()
    now = datetime.now(timezone.utc)
    filters = {
        "CreatedAt": [{
            "Start": last_alert_time,
            "End": now.isoformat()
        }]
    }

    if aws_sh_severity:
        filters["SeverityLabel"] = build_severity_label_obj(aws_sh_severity)
    if finding_types:
        filters["Type"] = create_filters_list_dictionaries(finding_types, "PREFIX")
    if workflow_status:
        statuses = [stat.upper() for stat in workflow_status]
        filters["WorkflowStatus"] = create_filters_list_dictionaries(statuses, "EQUALS")
    if product_name:
        filters["ProductName"] = create_filters_list_dictionaries(product_name, "EQUALS")

    alerts: list[dict] = []
    ASH = AwsSecurityHub()
    client = ASH.create_client()
    if last_next_token:
        try:
            response = client.get_findings(NextToken=last_next_token)

        # In case a new request is made with another input the nextToken will be revoked
        except client.exceptions.InvalidInputException as e:
            # orenctl.log(f"The {last_next_token=} is not valid.\nThe exception is {e}")
            response = client.get_findings(Filters=filters)
    else:
        response = client.get_findings(Filters=filters)

    alerts = response["Findings"]
    last_next_token = response.get("NextToken")
    if len(alerts) >= max_alert:
        alerts = alerts[:max_alert]

    if not alerts:
        datafeedctl.sync_alerts(alerts, extra_info=last_alert)
        return
    # orenctl.log(f"alerts qty: {len(alerts)}")
    the_last_alert = max(alerts, key=lambda alert: alert.get("CreatedAt"))
    last_created_alert_dt = dateparser.parse(the_last_alert.get("CreatedAt")) + timedelta(milliseconds=1)
    last_alert_time = last_created_alert_dt.isoformat()
    alerts = normalize_alert(alerts)
    extra_info = {
        "last_alert_time": last_alert_time,
        "last_alert_id": the_last_alert.get("security_hub_id"),
        "last_next_token": last_next_token
    }
    # orenctl.log(f"extra_info = {extra_info}")
    datafeedctl.sync_alerts(alerts, extra_info=extra_info)
    if archive_findings and alerts:
        kwargs = {
            "FindingIdentifiers": [
                {"Id": alert.get("security_hub_id"), "ProductArn": alert.get("product_arn")} for alert in alerts
            ],
            "Workflow": {
                "Status": "NOTIFIED",
            },
            "Note": {
                "Text": "Archived by Cycir",
                "UpdatedBy": "Cycir"
            }
        }

        client.batch_update_findings(**kwargs)
    return alerts


if orenctl.command() == 'aws_securityhub_get_findings':
    get_findings_command()
elif orenctl.command() == 'aws_securityhub_get_master_account':
    get_master_account_command()
elif orenctl.command() == 'aws_securityhub_list_members':
    list_members_command()
elif orenctl.command() == 'aws_securityhub_enable_security_hub':
    enable_security_hub_command()
elif orenctl.command() == 'aws_securityhub_disable_security_hub':
    disable_security_hub_command()
elif orenctl.command() == 'aws_securityhub_update_findings':
    update_findings_command()
elif orenctl.command() == 'aws_securityhub_batch_update_findings':
    batch_update_findings_command()
elif orenctl.command() == 'feed_alerts':
    feed_alerts()
