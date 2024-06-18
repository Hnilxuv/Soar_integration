import unittest
from unittest.mock import patch, MagicMock
import json

from aws_cloud_trail import (
    create_trail, delete_trail, describe_trails, get_trail_status,
    update_trail, start_logging, stop_logging, lookup_events, test_function
)


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
    def getArg(param):
        args = {
            "name": "test-trail",
            "s3_bucket_name": "test-bucket",
            "s3_key_prefix": "test-prefix",
            "sns_topic_name": "test-topic",
            "include_global_service_events": "True",
            "is_multi_region_trail": "True",
            "enable_log_file_validation": "True",
            "cloud_watch_logs_log_group_arn": "arn:aws:logs:us-west-1:123456789012:log-group:test-log-group",
            "cloud_watch_logs_role_arn": "arn:aws:iam::123456789012:role/test-role",
            "kms_key_id": "arn:aws:kms:us-west-1:123456789012:key/test-key",
            "trail_name_list": ["test-trail"],
            "include_shadow_trails": "True",
            "attribute_key": "Username",
            "attribute_value": "test-user",
            "start_time": "2023-01-01T00:00:00Z",
            "end_time": "2023-01-02T00:00:00Z",
        }
        return args.get(param)

    @staticmethod
    def results(result):
        print(json.dumps(result))

    @staticmethod
    def error(message):
        return {"error": message}


class TestAwsCloudTrail(unittest.TestCase):

    def setUp(self):
        self.mock_cloudtrail_client = MagicMock()
        self.mock_cloudtrail_client.create_trail.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "TrailARN": "arn:aws:cloudtrail:us-west-1:123456789012:trail/test-trail"
        }
        self.mock_cloudtrail_client.delete_trail.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_cloudtrail_client.describe_trails.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "trailList": [{"Name": "test-trail"}]
        }
        self.mock_cloudtrail_client.get_trail_status.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "IsLogging": True
        }
        self.mock_cloudtrail_client.update_trail.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "CloudWatchLogsLogGroupArn": "string",
            "CloudWatchLogsRoleArn": "string",
            "IncludeGlobalServiceEvents": True,
            "IsMultiRegionTrail": True,
            "IsOrganizationTrail": True,
            "KmsKeyId": "string",
            "LogFileValidationEnabled": True,
            "Name": "string",
            "S3BucketName": "string",
            "S3KeyPrefix": "string",
            "SnsTopicARN": "string",
            "SnsTopicName": "string",
            "TrailARN": "string"
        }
        self.mock_cloudtrail_client.start_logging.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_cloudtrail_client.stop_logging.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_paginator = MagicMock()
        self.mock_paginator.paginate.return_value = [
            {"Events": [{"EventId": "1", "Username": "test-user"}]}
        ]
        self.mock_cloudtrail_client.get_paginator.return_value = self.mock_paginator

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_create_trail_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        create_trail()
        mock_results.assert_called_with({
            "status_command": "Success",
            "trail": {"TrailARN": "arn:aws:cloudtrail:us-west-1:123456789012:trail/test-trail"}
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_create_trail_no_name(self, mock_results, mock_getArg, mock_boto_client):
        create_trail()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "s3_bucket_name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_create_trail_no_s3_bucket_name(self, mock_results, mock_getArg, mock_boto_client):
        create_trail()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'S3_bucket_name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_delete_trail_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        delete_trail()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The Trail test-trail was deleted"
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_delete_trail_no_name(self, mock_results, mock_getArg, mock_boto_client):
        delete_trail()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.results')
    def test_describe_trails_success(self, mock_results, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        describe_trails()
        mock_results.assert_called_with({
            "status_command": "Success",
            "trails": [{"Name": "test-trail"}]
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_get_trail_status_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        get_trail_status()
        mock_results.assert_called_with({
            "status_command": "Success",
            "trail_status": {"IsLogging": True}
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_get_trail_status_no_name(self, mock_results, mock_getArg, mock_boto_client):
        get_trail_status()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_update_trail_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        update_trail()
        mock_results.assert_called_with({
            "status_command": "Success",
            "trail": {"CloudWatchLogsLogGroupArn": "string",
            "CloudWatchLogsRoleArn": "string",
            "IncludeGlobalServiceEvents": True,
            "IsMultiRegionTrail": True,
            "IsOrganizationTrail": True,
            "KmsKeyId": "string",
            "LogFileValidationEnabled": True,
            "Name": "string",
            "S3BucketName": "string",
            "S3KeyPrefix": "string",
            "SnsTopicARN": "string",
            "SnsTopicName": "string",
            "TrailARN": "string"}
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_update_trail_no_name(self, mock_results, mock_getArg, mock_boto_client):
        update_trail()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_start_logging_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        start_logging()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The Trail test-trail started logging"
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_start_logging_no_name(self, mock_results, mock_getArg, mock_boto_client):
        start_logging()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_stop_logging_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        stop_logging()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The Trail test-trail stopped logging"
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "name" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_stop_logging_no_name(self, mock_results, mock_getArg, mock_boto_client):
        stop_logging()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Name is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_cloud_trail.orenctl.results')
    def test_lookup_events_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        lookup_events()
        mock_results.assert_called_with({
            "status_command": "Success",
            "events": [{"EventId": "1", "Username": "test-user"}]
        })

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "attribute_key" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_lookup_events_no_attribute_key(self, mock_results, mock_getArg, mock_boto_client):
        lookup_events()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Attribute_key is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.getArg', side_effect=lambda x: None if x == "attribute_value" else MockOrenctl.getArg(x))
    @patch('aws_cloud_trail.orenctl.results')
    def test_lookup_events_no_attribute_value(self, mock_results, mock_getArg, mock_boto_client):
        lookup_events()
        mock_results.assert_called_with({'Type': 2, 'Contents': 'Attribute_value is required', 'ContentsFormat': 'text'})

    @patch('aws_cloud_trail.boto3.client')
    @patch('aws_cloud_trail.orenctl.results')
    def test_test_function_success(self, mock_results, mock_boto_client):
        mock_boto_client.return_value = self.mock_cloudtrail_client

        test_function()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "OK"
        })


if __name__ == '__main__':
    unittest.main()
