import json
import re
import time
import dateparser
import boto3
from botocore.config import Config
import urllib3
import orenctl
from typing import TYPE_CHECKING, Tuple, Dict

from aws_guard_duty import datafeedctl

# The following import are used only for type hints and autocomplete.
# It is not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_guardduty import GuardDutyClient
    from mypy_boto3_guardduty.type_defs import (
        ConditionTypeDef
    )

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SERVICE_NAME = "guardduty"
FINDING_FREQUENCY = {
    "Fifteen Minutes": "FIFTEEN_MINUTES",
    "One Hour": "ONE_HOUR",
    "Six Hours": "SIX_HOURS"
}
MAX_RESULTS_RESPONSE = 50


def arg_to_boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ["true", "yes"]:
            return True
        elif value.lower() in ["false", "no"]:
            return False
        else:
            orenctl.results(orenctl.error("Argument does not contain a valid boolean-like value"))
            return
    else:
        orenctl.results(orenctl.error("Argument is neither a string nor a boolean"))
        return


def get_pagination_args():
    """
    Gets and validates pagination arguments.
    :param args: The command arguments (page, page_size or limit)
    :return: limit, page_size, page after validation and convert
    """

    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else MAX_RESULTS_RESPONSE
    page = int(orenctl.getArg("page")) if orenctl.getArg("limit") else 1
    if page <= 0:
        orenctl.results(orenctl.error("page argument must be greater than 0"))
        return

    page_size = int(orenctl.getArg("page_size")) if orenctl.getArg("page_size") else MAX_RESULTS_RESPONSE
    if not 0 < page_size <= MAX_RESULTS_RESPONSE:
        orenctl.results(orenctl.error(f"page_size argument must be between 1 to {MAX_RESULTS_RESPONSE}"))
        return

    if page:
        limit = page * page_size

    return limit, page_size, page


def camel_to_snake(name):
    # Thêm dấu gạch dưới trước các chữ cái viết hoa và chuyển tất cả về chữ thường
    snake = re.sub("([A-Z])", r"_\1", name).lower()
    # Xóa dấu gạch dưới ở đầu (nếu có)
    if snake.startswith("_"):
        snake = snake[1:]
    return snake


class AwsGuardDuty(object):
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

            client: "GuardDutyClient" = boto3.client(service_name=SERVICE_NAME,
                                                     region_name=self.region,
                                                     aws_access_key_id=self.access_key,
                                                     aws_secret_access_key=self.secret_key,
                                                     verify=self.verify,
                                                     config=boto_config)
            return client
        except Exception as e:
            orenctl.results(orenctl.error("Could not create boto3 client: {0}".format(e)))
            raise Exception("Could not create boto3 client: {0}".format(e))


def create_detector():
    enabled = orenctl.getArg("enabled") if orenctl.getArg("enabled") else False
    kwargs = {
        "Enable": enabled
    }
    if orenctl.getArg("finding_frequency"):
        kwargs["FindingPublishingFrequency"] = FINDING_FREQUENCY.get(orenctl.getArg("finding_frequency"))

    get_data_sources = dict()

    if orenctl.getArg("enableKubernetesLogs"):
        get_data_sources.update(
            {"Kubernetes": {"AuditLogs": {"Enable": arg_to_boolean(orenctl.getArg("enableKubernetesLogs"))}}})
    if orenctl.getArg("ebsVolumesMalwareProtection"):
        get_data_sources.update({"MalwareProtection": {
            "ScanEc2InstanceWithFindings": {
                "EbsVolumes": arg_to_boolean(orenctl.getArg("ebsVolumesMalwareProtection"))}}})
    if orenctl.getArg("enableS3Logs"):
        get_data_sources.update({"S3Logs": {"Enable": arg_to_boolean(orenctl.getArg("enableS3Logs"))}})
    if get_data_sources:
        kwargs["DataSources"] = get_data_sources

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.create_detector(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "detect_id": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "detect_id": response.get("DetectorId")
    })
    return


def delete_detector():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.delete_detector(DetectorId=detect_id)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 204:
        orenctl.results({
            "status_command": "Fail",
            "message": f"The Detector {detect_id} failed to delete.",
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The Detector {detect_id} has been deleted"
    })
    return


def get_detector():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.get_detector(DetectorId=detect_id)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "detector": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "detector": response.get("DetectorId")
    })
    return


def update_detector():
    enabled = orenctl.getArg("enabled") if orenctl.getArg("enabled") else False
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return

    kwargs = {
        "Enable": enabled,
        "DetectorId": detect_id
    }
    if orenctl.getArg("finding_frequency"):
        kwargs["FindingPublishingFrequency"] = FINDING_FREQUENCY.get(orenctl.getArg("finding_frequency"))

    get_data_sources = dict()

    if orenctl.getArg("enableKubernetesLogs"):
        get_data_sources.update(
            {"Kubernetes": {"AuditLogs": {"Enable": arg_to_boolean(orenctl.getArg("enableKubernetesLogs"))}}})
    if orenctl.getArg("ebsVolumesMalwareProtection"):
        get_data_sources.update({"MalwareProtection": {
            "ScanEc2InstanceWithFindings": {
                "EbsVolumes": arg_to_boolean(orenctl.getArg("ebsVolumesMalwareProtection"))}}})
    if orenctl.getArg("enableS3Logs"):
        get_data_sources.update({"S3Logs": {"Enable": arg_to_boolean(orenctl.getArg("enableS3Logs"))}})
    if get_data_sources:
        kwargs["DataSources"] = get_data_sources

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.update_detector(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "detector": f"Detector {detect_id} failed to update. Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The Detector {detect_id} has been updated successfully"
    })
    return


def list_detectors():
    limit, page_size, page = get_pagination_args()
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    paginator = client.get_paginator("list_detectors")
    response_iterator = paginator.paginate(
        PaginationConfig={
            "MaxItems": limit,
            "PageSize": page_size,
        }
    )

    detectors = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for detector in page_response["DetectorIds"]:
                detectors.append({"detect_id": detector})
            if page:
                break

    orenctl.results({
        "status_command": "Success",
        "detectors": detectors if detectors else None
    })
    return


def create_ip_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    kwargs = {
        "DetectorId": detect_id
    }
    if orenctl.getArg("activate"):
        kwargs["Activate"] = arg_to_boolean(orenctl.getArg("activate"))
    if orenctl.getArg("format"):
        kwargs["Format"] = orenctl.getArg("format")
    if orenctl.getArg("location"):
        kwargs["Location"] = orenctl.getArg("location")
    if orenctl.getArg("name"):
        kwargs["Name"] = orenctl.getArg("name")

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.create_ip_set(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "ip_set_id": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "ip_set_id": response.get("IpSetId")
    })
    return


def delete_ip_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    ip_set_id = orenctl.getArg("ip_set_id")
    if not ip_set_id:
        orenctl.results(orenctl.error("Ip_set_id is required"))
        return

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.delete_ip_set(
        DetectorId=detect_id,
        IpSetId=ip_set_id
    )
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to delete ip set {ip_set_id} . Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The IPSet {ip_set_id} has been deleted from Detector {detect_id}"
    })
    return


def update_ip_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    ip_set_id = orenctl.getArg("ip_set_id")
    if not ip_set_id:
        orenctl.results(orenctl.error("Ip_set_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id,
        "IpSetId": ip_set_id
    }
    if orenctl.getArg("activate"):
        kwargs["Activate"] = arg_to_boolean(orenctl.getArg("activate"))
    if orenctl.getArg("location"):
        kwargs["Location"] = orenctl.getArg("location")
    if orenctl.getArg("name"):
        kwargs["Name"] = orenctl.getArg("name")
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.update_ip_set(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to update ip set {ip_set_id} . Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The IPSet {ip_set_id} has been Updated"
    })
    return


def get_ip_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    ip_set_id = orenctl.getArg("ip_set_id")
    if not ip_set_id:
        orenctl.results(orenctl.error("Ip_set_id is required"))
        return

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.get_ip_set(
        DetectorId=detect_id,
        IpSetId=ip_set_id
    )

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "ip_set": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "ip_set": {"DetectorId": detect_id,
                   "IpSetId": ip_set_id,
                   "Format": response["Format"],
                   "Location": response["Location"],
                   "Name": response["Name"],
                   "Status": response["Status"]}
    })


def list_ip_sets():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    limit, page_size, page = get_pagination_args()
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    paginator = client.get_paginator("list_ip_sets")
    response_iterator = paginator.paginate(
        DetectorId=detect_id,
        PaginationConfig={
            "MaxItems": limit,
            "PageSize": page_size,
        }
    )
    ip_sets = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for ipSet in page_response["IpSetIds"]:
                ip_sets.append({"IpSetId": ipSet})
            if page:
                break

    orenctl.results({
        "status_command": "Success",
        "ip_sets": ip_sets if ip_sets else None
    })
    return


def create_threat_intel_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id
    }
    if orenctl.getArg("activate"):
        kwargs["Activate"] = arg_to_boolean(orenctl.getArg("activate"))
    if orenctl.getArg("format"):
        kwargs["Format"] = orenctl.getArg("format")
    if orenctl.getArg("location"):
        kwargs["Location"] = orenctl.getArg("location")
    if orenctl.getArg("name"):
        kwargs["Name"] = orenctl.getArg("name")

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.create_threat_intel_set(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "threat_intel_set": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "threat_intel_set": response.get("ThreatIntelSetId")
    })
    return


def delete_threat_intel_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    threat_intel_set_id = orenctl.getArg("threat_intel_set_id")
    if not threat_intel_set_id:
        orenctl.results(orenctl.error("Threat_intel_set_id is required"))
        return

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.delete_threat_intel_set(
        DetectorId=detect_id,
        ThreatIntelSetId=threat_intel_set_id
    )
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to delete ThreatIntel set {threat_intel_set_id} . Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The ThreatIntel set {threat_intel_set_id} has been deleted from Detector {detect_id}"
    })
    return


def update_threat_intel_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    threat_intel_set_id = orenctl.getArg("threat_intel_set_id")
    if not threat_intel_set_id:
        orenctl.results(orenctl.error("Threat_intel_set_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id,
        "ThreatIntelSetId": threat_intel_set_id
    }
    if orenctl.getArg("activate"):
        kwargs["Activate"] = arg_to_boolean(orenctl.getArg("activate"))
    if orenctl.getArg("location"):
        kwargs["Location"] = orenctl.getArg("location")
    if orenctl.getArg("name"):
        kwargs["Name"] = orenctl.getArg("name")
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.update_threat_intel_set(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to update ThreatIntel set {threat_intel_set_id} . Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The ThreatIntel set {threat_intel_set_id} has been Updated"
    })
    return


def get_threat_intel_set():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    threat_intel_set_id = orenctl.getArg("threat_intel_set_id")
    if not threat_intel_set_id:
        orenctl.results(orenctl.error("Threat_intel_set_id is required"))
        return

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.get_threat_intel_set(
        DetectorId=detect_id,
        ThreatIntelSetId=threat_intel_set_id
    )

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "threat_intel_set": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "threat_intel_set": {"DetectorId": detect_id,
                             "ThreatIntelSetId": threat_intel_set_id,
                             "Format": response["Format"],
                             "Location": response["Location"],
                             "Name": response["Name"],
                             "Status": response["Status"]}
    })


def list_threat_intel_sets():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    limit, page_size, page = get_pagination_args()
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    paginator = client.get_paginator("list_threat_intel_sets")
    response_iterator = paginator.paginate(
        DetectorId=detect_id,
        PaginationConfig={
            "MaxItems": limit,
            "PageSize": page_size,
        }
    )
    threat_intel_sets = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for ThreatIntelSet in page_response["ThreatIntelSetIds"]:
                threat_intel_sets.append({"ThreatIntelSetId": ThreatIntelSet})
            if page:
                break

    orenctl.results({
        "status_command": "Success",
        "threat_intel_sets": threat_intel_sets if threat_intel_sets else None
    })
    return


def list_findings():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    limit, page_size, page = get_pagination_args()
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    paginator = client.get_paginator("list_findings")
    response_iterator = paginator.paginate(
        DetectorId=detect_id,
        PaginationConfig={
            "MaxItems": limit,
            "PageSize": page_size,
        }
    )
    findings = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for finding in page_response["FindingIds"]:
                findings.append({"FindingId": finding})
            if page:
                break

    orenctl.results({
        "status_command": "Success",
        "findings": findings if findings else None
    })
    return


def get_findings():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    finding_ids = orenctl.getArg("finding_ids")
    if not finding_ids or not isinstance(finding_ids, list):
        orenctl.results(orenctl.error("Finding_ids is required and a list"))
        return

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.get_threat_intel_set(
        DetectorId=detect_id,
        findingIds=finding_ids
    )

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "findings": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "findings": response.get("findings", [])
    })


def create_sample_findings():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id
    }
    if orenctl.getArg("finding_types"):
        kwargs["FindingTypes"] = orenctl.getArg("finding_types")

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.create_sample_findings(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to generate findings. Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"Sample Findings were generated"
    })
    return


def archive_findings():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id
    }
    if orenctl.getArg("finding_types"):
        kwargs["FindingTypes"] = orenctl.getArg("finding_types")

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.create_sample_findings(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to archive findings. Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"Findings were archived"
    })
    return


def unarchive_findings():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id
    }
    if orenctl.getArg("finding_types"):
        kwargs["FindingTypes"] = orenctl.getArg("finding_types")

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.create_sample_findings(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to unarchived findings. Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"Findings were unarchived"
    })
    return


def update_findings_feedback():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return

    kwargs = {
        "DetectorId": detect_id
    }
    if orenctl.getArg("finding_ids"):
        kwargs["FindingIds"] = orenctl.getArg("finding_ids")
    if orenctl.getArg("comments"):
        kwargs["Comments"] = orenctl.getArg("comments")
    if orenctl.getArg("feedback"):
        kwargs["Feedback"] = orenctl.getArg("feedback")

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.update_findings_feedback(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Failed to send findings feedback. Response was: {response}"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": "Findings Feedback sent!"
    })
    return


def list_members():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    limit, page_size, page = get_pagination_args()
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    paginator = client.get_paginator("list_members")
    response_iterator = paginator.paginate(
        DetectorId=detect_id,
        PaginationConfig={
            "MaxItems": limit,
            "PageSize": page_size,
        }
    )
    findings = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for member in page_response["Members"]:
                findings.append({"Member": member})
            if page:
                break

    orenctl.results({
        "status_command": "Success",
        "findings": findings if findings else None
    })
    return


def get_members():
    detect_id = orenctl.getArg("detect_id")
    if not detect_id:
        orenctl.results(orenctl.error("Detect_id is required"))
        return
    account_ids = orenctl.getArg("account_ids")
    if not account_ids or not isinstance(account_ids, list):
        orenctl.results(orenctl.error("Account_ids is required and a list"))
        return

    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.get_threat_intel_set(
        DetectorId=detect_id,
        AccountIds=account_ids
    )

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "members": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "members": response.get("Members", [])
    })


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
        timestamp = oldest_time
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
                alert["owner"] = "AWS GuardDuty"

            if "id" in alert:
                alert["guard_duty_id"] = alert.get("id")
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

    severity_condition = orenctl.getHeader("severity_condition")
    max_alert = int(orenctl.getHeader("max_alert")) if orenctl.getHeader("max_alert") else 500
    if not severity_condition:
        orenctl.results(orenctl.error("severity_condition is required"))
    is_archive = orenctl.getHeader("is_archive")

    last_alert = get_last_alert()
    last_time = int(time.time()*1000) - 3*24*60*60*1000
    last_alert_time = last_alert.get("last_alert_time", last_time)
    last_next_token = last_alert.get("last_next_token", None)
    last_alert_id = last_alert.get("last_alert_id", None)

    criterion_conditions: Dict[str, "ConditionTypeDef"] = {"severity": {"Gte": int(severity_condition)},
                                                           "createdAt": {"Gte": last_alert_time}}

    if is_archive:
        # orenctl.log("Fetching Amazon GuardDuty with Archive")
        criterion_conditions["service.archived"] = {"Eq": ["false"]}

    alerts: list[dict] = []
    AGD = AwsGuardDuty()
    client = AGD.create_client()
    response = client.list_detectors()
    detector = response["DetectorIds"]
    while True:
        left_to_fetch = max_alert - len(alerts)
        max_results = min(MAX_RESULTS_RESPONSE, left_to_fetch)
        list_findings_res = client.list_findings(
            DetectorId=detector[0],
            FindingCriteria={"Criterion": criterion_conditions},
            SortCriteria={"AttributeName": "createdAt", "OrderBy": "ASC"},
            MaxResults=max_results,
            NextToken=last_next_token
        )
        last_next_token = list_findings_res.get("NextToken", "")
        finding_ids = list_findings_res.get("FindingIds", [])
        get_findings_res = client.get_findings(DetectorId=detector[0], FindingIds=finding_ids,
                                               SortCriteria={"AttributeName": "createdAt", "OrderBy": "ASC"})
        alerts.extend(get_findings_res.get("Findings"))

        if alerts and is_archive:
            # Archive findings
            # orenctl.log(f"Archived {len(finding_ids)} findings.")
            client.archive_findings(DetectorId=detector[0], FindingIds=finding_ids)

        if not last_next_token or max_alert - len(alerts) == 0:
            # orenctl.log("fetch_limit has been reached or there is no next token")
            break

    if not alerts:
        datafeedctl.sync_alerts(alerts, extra_info=last_alert)
        return
    # orenctl.log(f"alerts qty: {len(alerts)}")

    alerts = normalize_alert(alerts)
    last_alert = alerts[-1]
    extra_info = {
        "last_alert_time": last_alert.get("timestamp"),
        "last_alert_id": last_alert_id.get("guard_duty_id"),
        "last_next_token": last_next_token
    }
    # orenctl.log(f"extra_info = {extra_info}")
    datafeedctl.sync_alerts(alerts, extra_info=extra_info)
    return alerts


if orenctl.command == "feed_alert":
    feed_alerts()
if orenctl.command == "aws_create_detector":
    create_detector()
if orenctl.command == "aws_delete_detector":
    delete_detector()
if orenctl.command == "aws_get_detector":
    get_detector()
if orenctl.command == "aws_update_detector":
    update_detector()
if orenctl.command == "aws_create_ip_set":
    create_ip_set()
if orenctl.command == "aws_delete_ip_set":
    delete_ip_set()
if orenctl.command == "aws_list_detectors":
    list_detectors()
if orenctl.command == "aws_update_ip_set":
    update_ip_set()
if orenctl.command == "aws_get_ip_set":
    get_ip_set()
if orenctl.command == "aws_list_ip_sets":
    list_ip_sets()
if orenctl.command == "aws_create_threat_intel_set":
    create_threat_intel_set()
if orenctl.command == "aws_delete_threat_intel_set":
    delete_threat_intel_set()
if orenctl.command == "aws_get_threat_intel_set":
    get_threat_intel_set()
if orenctl.command == "aws_list_threat_intel_sets":
    list_threat_intel_sets()
if orenctl.command == "aws_update_threat_intel_set":
    update_threat_intel_set()
if orenctl.command == "aws_list_findings":
    list_findings()
if orenctl.command == "aws_get_findings":
    get_findings()
if orenctl.command == "aws_create_sample_findings":
    create_sample_findings()
if orenctl.command == "aws_archive_findings":
    archive_findings()
if orenctl.command == "aws_unarchive_findings":
    unarchive_findings()
if orenctl.command == "aws_update_findings_feedback":
    update_findings_feedback()
if orenctl.command == "aws_list_members":
    list_members()
if orenctl.command == "aws_get_members":
    get_members()
