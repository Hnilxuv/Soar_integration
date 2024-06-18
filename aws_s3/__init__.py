import json
import os
import tempfile

import boto3
from botocore.config import Config
import urllib3
from aws_s3 import orenctl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SERVICE_NAME = "S3"


class AwsS3(object):
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


def create_bucket_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return
    kwargs = {
        "Bucket": bucket.lower()
    }
    if orenctl.getArg("acl"):
        kwargs["ACL"] = orenctl.getArg("acl")
    if orenctl.getArg("location_constraint"):
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": orenctl.getArg("location_constraint")}
    if orenctl.getArg("grant_full_control"):
        kwargs["GrantFullControl"] = orenctl.getArg("grant_full_control")
    if orenctl.getArg("grant_read"):
        kwargs["GrantRead"] = orenctl.getArg("grant_read")
    if orenctl.getArg("grant_read_acp"):
        kwargs["GrantReadACP"] = orenctl.getArg("grant_read_acp")
    if orenctl.getArg("grant_write"):
        kwargs["GrantWrite"] = orenctl.getArg("grant_write")
    if orenctl.getArg("grant_write_acp"):
        kwargs["GrantWriteACP"] = orenctl.getArg("grant_write_acp")

    S3 = AwsS3()
    client = S3.create_client()
    response = client.create_bucket(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "location": None,
            "bucket_name": bucket
        })
        return

    orenctl.results({
        "status_command": "Success",
        "location": response.get("Location"),
        "bucket_name": bucket
    })
    return


def delete_bucket_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return

    S3 = AwsS3()
    client = S3.create_client()
    response = client.delete_bucket(Bucket=bucket.lower())

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 204:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Bucket {bucket} was not deleted",
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"Bucket {bucket} was deleted"
    })
    return


def list_buckets_command():
    S3 = AwsS3()
    client = S3.create_client()
    response = client.list_buckets()
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "buckets": None,
        })
        return
    buckets = response.get("Buckets")
    orenctl.results({
        "status_command": "Success",
        "buckets": buckets
    })
    return


def get_bucket_policy_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return

    S3 = AwsS3()
    client = S3.create_client()
    response = client.get_bucket_policy(Bucket=bucket.lower())
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "bucket_policy": None,
        })
        return
    policy = json.loads(response.get("Policy"))
    orenctl.results({
        "status_command": "Success",
        "bucket_policy": policy
    })
    return


def put_bucket_policy_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return
    policy = orenctl.getArg("policy").lower()
    if not bucket:
        orenctl.results(orenctl.error("Bucket policy is required"))
        return

    kwargs = {
        "Bucket": bucket.lower(),
        "Policy": policy
    }
    if orenctl.getArg("confirm_remove_self_bucket_access"):
        kwargs["ConfirmRemoveSelfBucketAccess"] = True \
            if orenctl.getArg("confirm_remove_self_bucket_access") == "True" \
            else False
    S3 = AwsS3()
    client = S3.create_client()
    response = client.put_bucket_policy(**kwargs)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Couldn't apply bucket policy to {bucket} bucket"
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"Successfully applied bucket policy to {bucket} bucket"
    })
    return


def delete_bucket_policy_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return

    S3 = AwsS3()
    client = S3.create_client()
    response = client.delete_bucket_policy(Bucket=bucket.lower())

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 204:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Policy was not deleted from {bucket}",
        })
        return

    orenctl.results({
        "status_command": "Success",
        "message": f"Policy was deleted from {bucket.lower()}"
    })
    return


def download_file_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return
    key = orenctl.getArg("key")
    S3 = AwsS3()
    client = S3.create_client()
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, key)
    with open(path, "wb") as data:
        client.download_fileobj(bucket.lower(), key, data)
    location = orenctl.upload_file(path, None)
    os.remove(path)
    os.rmdir(tmpdir)
    orenctl.results({
        "status_command": "Success",
        "location": location,
        "file_name": key
    })
    return


def list_objects_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return
    kwargs = {
        "Bucket": bucket.lower(),
    }
    if orenctl.getArg("delimiter"):
        kwargs["Delimiter"] = orenctl.getArg("delimiter")
    if orenctl.getArg("prefix"):
        kwargs["Prefix"] = orenctl.getArg("prefix")

    S3 = AwsS3()
    client = S3.create_client()
    client.list_objects(**kwargs)
    paginator = client.get_paginator("list_objects")
    objects = [response.get("Contents", None) for response in paginator.paginate(**kwargs) if response]

    orenctl.results({
        "status_command": "Success",
        "objects": objects
    })
    return


def get_public_access_block_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return

    S3 = AwsS3()
    client = S3.create_client()
    response = client.get_public_access_block(Bucket=bucket.lower())
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "public_access_block": None,
        })
        return
    public_access_block_configuration = response.get("PublicAccessBlockConfiguration")
    orenctl.results({
        "status_command": "Success",
        "public_access_block": public_access_block_configuration,
    })
    return


def put_public_access_block_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return
    kwargs = {
        "Bucket": bucket.lower(),
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": orenctl.getArg("block_public_acls"),
            "IgnorePublicAcls": orenctl.getArg("ignore_public_acls"),
            "BlockPublicPolicy": orenctl.getArg("block_public_policy"),
            "RestrictPublicBuckets": orenctl.getArg("restrict_public_buckets")
        }
    }

    S3 = AwsS3()
    client = S3.create_client()
    response = client.put_public_access_block(**kwargs)
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "message": f"Couldn't apply public access block to the {bucket} bucket"
        })
        return
    orenctl.results({
        "status_command": "Success",
        "message": f"Successfully applied public access block to the {bucket} bucket"
    })
    return


def get_bucket_encryption_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return
    kwargs = {
        "Bucket": bucket.lower()
    }

    if orenctl.getArg("expected_bucket_owner"):
        kwargs["ExpectedBucketOwner"] = orenctl.getArg("expected_bucket_owner")
    S3 = AwsS3()
    client = S3.create_client()
    try:
        response = client.get_bucket_encryption(**kwargs)
    except client.exceptions.ClientError as ex:
        if ex.response.get('Error', {}).get('Code', '') != 'ServerSideEncryptionConfigurationNotFoundError':
            raise ex
        response = {}
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        orenctl.results({
            "status_command": "Fail",
            "public_access_block": None,
        })
        return
    orenctl.results({
        "status_command": "Success",
        "server_side_encryption_configuration": response.get('ServerSideEncryptionConfiguration'),
    })
    return


def upload_file_command():
    bucket = orenctl.getArg("bucket")
    if not bucket:
        orenctl.results(orenctl.error("Bucket S3 is required"))
        return

    key = orenctl.getArg("key")
    location = orenctl.getArg("location")

    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, key)
    orenctl.download_file(location, path)
    S3 = AwsS3()
    client = S3.create_client()
    with open(path, 'rb') as data:
        client.upload_fileobj(data, bucket.lower(), key)
        data.close()
        orenctl.results({
            "status_command": "Success",
            "message": f"File {key} was uploaded successfully to {bucket}",
        })
    os.remove(path)
    os.rmdir(tmpdir)
    return


if orenctl.command == "aws_s3_create_bucket":
    create_bucket_command()
elif orenctl.command == "aws_s3_delete_bucket":
    delete_bucket_command()
elif orenctl.command == "aws_s3_list_buckets":
    list_buckets_command()
elif orenctl.command == "aws_s3_get_bucket_policy":
    get_bucket_policy_command()
elif orenctl.command == "aws_s3_put_bucket_policy":
    put_bucket_policy_command()
elif orenctl.command == "aws_s3_delete_bucket_policy":
    delete_bucket_policy_command()
elif orenctl.command == "aws_s3_download_file'":
    download_file_command()
elif orenctl.command == "aws_s3_list_bucket_objects":
    list_objects_command()
elif orenctl.command == "aws_s3_upload_file":
    upload_file_command()
elif orenctl.command == "aws_s3_get_public_access_block":
    get_public_access_block_command()
elif orenctl.command == "aws_s3_put_public_access_block":
    put_public_access_block_command()
elif orenctl.command == "aws_s3_get_bucket_encryption":
    get_bucket_encryption_command()
