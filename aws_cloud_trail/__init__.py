import boto3
from botocore.config import Config
import urllib3
import orenctl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SERVICE_NAME = "cloudtrail"


class AwsCloudTrail(object):
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


def create_trail():
    name = orenctl.getArg("name")
    if not name:
        orenctl.results(orenctl.error("Name is required"))
        return

    s3_bucket_name = orenctl.getArg("s3_bucket_name")
    if not s3_bucket_name:
        orenctl.results(orenctl.error("S3_bucket_name is required"))
        return
    kwargs = {
        "Name": name,
        "S3BucketName": s3_bucket_name,
    }
    if orenctl.getArg("s3_key_prefix"):
        kwargs["S3KeyPrefix"] = orenctl.getArg("s3_key_prefix")
    if orenctl.getArg("sns_topic_name"):
        kwargs["SnsTopicName"] = orenctl.getArg("sns_topic_name")
    if orenctl.getArg("include_global_service_events"):
        kwargs["IncludeGlobalServiceEvents"] = orenctl.getArg("include_global_service_events") == "True"
    if orenctl.getArg("is_multi_region_trail"):
        kwargs["IsMultiRegionTrail"] = orenctl.getArg("is_multi_region_trail") == "True"
    if orenctl.getArg("enable_log_file_validation"):
        kwargs["EnableLogFileValidation"] = orenctl.getArg("enable_log_file_validation") == "True"
    if orenctl.getArg("cloud_watch_logs_log_group_arn"):
        kwargs["CloudWatchLogsLogGroupArn"] = orenctl.getArg("cloud_watch_logs_log_group_arn")
    if orenctl.getArg("cloud_watch_logs_role_arn"):
        kwargs["CloudWatchLogsRoleArn"] = orenctl.getArg("cloud_watch_logs_role_arn")
    if orenctl.getArg("kms_key_id"):
        kwargs["KmsKeyId"] = orenctl.getArg("kms_key_id")

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.create_trail(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "trail": None
        })
        return
    if "ResponseMetadata" in response:
        del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "trail": response
    })
    return


def delete_trail():
    name = orenctl.getArg("name")
    if not name:
        orenctl.results(orenctl.error("Name is required"))
        return

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.delete_trail(Name=name)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"The Trail {name} could not be deleted"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"The Trail {name} was deleted"
    })
    return


def describe_trails():
    kwargs = {}
    if orenctl.getArg("trail_name_list"):
        kwargs["trailNameList"] = orenctl.getArg("trail_name_list")
    if orenctl.getArg("include_shadow_trails"):
        kwargs["include_shadow_trails"] = orenctl.getArg("include_shadow_trails") == "True"

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.describe_trails(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "trails": None
        })
        return

    orenctl.results({
        "status_command": "Success",
        "trails": response.get("trailList")
    })
    return


def get_trail_status():
    name = orenctl.getArg("name")
    if not name:
        orenctl.results(orenctl.error("Name is required"))
        return

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.get_trail_status(Name=name)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "trail_status": None
        })
        return
    if "ResponseMetadata" in response:
        del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "trail_status": response
    })
    return


def update_trail():
    name = orenctl.getArg("name")
    if not name:
        orenctl.results(orenctl.error("Name is required"))
        return
    kwargs = {
        "Name": name
    }

    if orenctl.getArg("s3_key_prefix"):
        kwargs["S3KeyPrefix"] = orenctl.getArg("s3_key_prefix")
    if orenctl.getArg("sns_topic_name"):
        kwargs["SnsTopicName"] = orenctl.getArg("sns_topic_name")
    if orenctl.getArg("include_global_service_events"):
        kwargs["IncludeGlobalServiceEvents"] = orenctl.getArg("include_global_service_events") == "True"
    if orenctl.getArg("is_multi_region_trail"):
        kwargs["IsMultiRegionTrail"] = orenctl.getArg("is_multi_region_trail") == "True"
    if orenctl.getArg("enable_log_file_validation"):
        kwargs["EnableLogFileValidation"] = orenctl.getArg("enable_log_file_validation") == "True"
    if orenctl.getArg("cloud_watch_logs_log_group_arn"):
        kwargs["CloudWatchLogsLogGroupArn"] = orenctl.getArg("cloud_watch_logs_log_group_arn")
    if orenctl.getArg("cloud_watch_logs_role_arn"):
        kwargs["CloudWatchLogsRoleArn"] = orenctl.getArg("cloud_watch_logs_role_arn")
    if orenctl.getArg("kms_key_id"):
        kwargs["KmsKeyId"] = orenctl.getArg("kms_key_id")

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.update_trail(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "trail": None
        })
        return
    if "ResponseMetadata" in response:
        del response["ResponseMetadata"]
    orenctl.results({
        "status_command": "Success",
        "trail": response
    })
    return


def start_logging():
    name = orenctl.getArg("name")
    if not name:
        orenctl.results(orenctl.error("Name is required"))
        return
    kwargs = {
        "Name": name
    }

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.start_logging(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"The Trail {name} could not start logging"
        })
        return
    orenctl.results({
        "status_command": "Success",
        "message": f"The Trail {name} started logging"
    })
    return


def stop_logging():
    name = orenctl.getArg("name")
    if not name:
        orenctl.results(orenctl.error("Name is required"))
        return
    kwargs = {
        "Name": name
    }

    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.stop_logging(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"The Trail {name} could not stopped logging"
        })
        return
    orenctl.results({
        "status_command": "Success",
        "message": f"The Trail {name} stopped logging"
    })
    return


def lookup_events():
    attribute_key = orenctl.getArg("attribute_key")
    if not attribute_key:
        orenctl.results(orenctl.error("Attribute_key is required"))
        return
    attribute_value = orenctl.getArg("attribute_value")
    if not attribute_value:
        orenctl.results(orenctl.error("Attribute_value is required"))
        return

    kwargs = {
        "LookupAttributes": [{
            "AttributeKey": attribute_key,
            "AttributeValue": attribute_value
        }]
    }

    if orenctl.getArg("start_time"):
        kwargs["StartTime"] = orenctl.getArg("start_time")
    if orenctl.getArg("end_time"):
        kwargs["EndTime"] = orenctl.getArg("end_time")
    ACT = AwsCloudTrail()
    client = ACT.create_client()
    client.lookup_events(**kwargs)
    paginator = client.get_paginator("lookup_events")
    events = []
    for response in paginator.paginate(**kwargs):
        for i, event in enumerate(response["Events"]):
            events.append(event)
            if "Username" in event:
                events[i].update({"Username": event["Username"]})

    orenctl.results({
        "status_command": "Success",
        "events": events
    })
    return


def test_function():
    ACT = AwsCloudTrail()
    client = ACT.create_client()
    response = client.describe_trails()
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": response
        })
        return
    orenctl.results({
        "status_command": "Success",
        "message": "OK"
    })
    return


if orenctl.command() == 'test_module':
    test_function()
if orenctl.command() == 'aws_cloudtrail_create_trail':
    create_trail()
if orenctl.command() == 'aws_cloudtrail_delete_trail':
    delete_trail()
if orenctl.command() == 'aws_cloudtrail_describe_trails':
    describe_trails()
if orenctl.command() == 'aws_cloudtrail_update_trail':
    update_trail()
if orenctl.command() == 'aws_cloudtrail_start_logging':
    start_logging()
if orenctl.command() == 'aws_cloudtrail_stop_logging':
    stop_logging()
if orenctl.command() == 'aws_cloudtrail_lookup_events':
    lookup_events()
if orenctl.command() == 'aws_cloudtrail_get_trail_status':
    get_trail_status()