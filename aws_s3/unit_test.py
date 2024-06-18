import unittest
from unittest.mock import patch, MagicMock
import json

from aws_s3 import (
    create_bucket_command, delete_bucket_command, list_buckets_command,
    get_bucket_policy_command, put_bucket_policy_command, delete_bucket_policy_command,
    download_file_command, list_objects_command, get_public_access_block_command,
    put_public_access_block_command, get_bucket_encryption_command, upload_file_command
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
    def getArg(arg):
        args = {
            "bucket": "test-bucket",
            "acl": None,
            "location_constraint": None,
            "grant_full_control": None,
            "grant_read": None,
            "grant_read_acp": None,
            "grant_write": None,
            "grant_write_acp": None,
            "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": '
                      '"s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"}]}',
            "confirm_remove_self_bucket_access": None,
            "key": "test-key",
            "delimiter": None,
            "prefix": None,
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
            "expected_bucket_owner": None,
            "location": "/path/to/local/file"
        }
        return args.get(arg)

    @staticmethod
    def results(result):
        print(json.dumps(result))

    @staticmethod
    def error(message):
        return {"error": message}


class TestAwsS3(unittest.TestCase):

    def setUp(self):
        self.mock_s3_client = MagicMock()
        self.mock_s3_client.create_bucket.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Location": "test-location"
        }
        self.mock_s3_client.delete_bucket.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 204}
        }
        self.mock_s3_client.list_buckets.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Buckets": [{"Name": "test-bucket"}]
        }
        self.mock_s3_client.get_bucket_policy.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Policy": json.dumps({"Version": "2012-10-17", "Statement": []})
        }
        self.mock_s3_client.get_public_access_block.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        self.mock_s3_client.get_bucket_encryption.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "ServerSideEncryptionConfiguration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }
        }
        self.mock_paginator = MagicMock()
        self.mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": "test1"}, {"Key": "test2"}]},
            {"Contents": [{"Key": "test3"}]}
        ]
        self.mock_s3_client.get_paginator.return_value = self.mock_paginator

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_s3.orenctl.results')
    def test_create_bucket_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_s3_client

        create_bucket_command()
        mock_results.assert_called_with({
            "status_command": "Success",
            "location": "test-location",
            "bucket_name": "test-bucket"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_s3.orenctl.results')
    def test_create_bucket_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        self.mock_s3_client.create_bucket.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_s3_client

        create_bucket_command()
        mock_results.assert_called_with({
            "status_command": "Fail",
            "location": None,
            "bucket_name": "test-bucket"
        })

    @patch('aws_s3.orenctl.getArg', side_effect=lambda x: None if x == "bucket" else MockOrenctl.getArg(x))
    @patch('aws_s3.orenctl.results')
    def test_create_bucket_command_no_bucket(self, results, mock_getArg):
        create_bucket_command()

        results.assert_called_with(
            {'Type': 2, 'Contents': 'Bucket S3 is required', 'ContentsFormat': 'text'}
        )

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_s3.orenctl.results')
    def test_delete_bucket_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_s3_client

        delete_bucket_command()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "Bucket test-bucket was deleted"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_s3.orenctl.results')
    def test_delete_bucket_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        self.mock_s3_client.delete_bucket.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_s3_client

        delete_bucket_command()
        mock_results.assert_called_with({
            "status_command": "Fail",
            "message": "Bucket test-bucket was not deleted"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.results')
    def test_list_buckets_command_success(self, mock_results, mock_boto_client):
        mock_boto_client.return_value = self.mock_s3_client

        list_buckets_command()
        mock_results.assert_called_with({
            "status_command": "Success",
            "buckets": [{"Name": "test-bucket"}]
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.results')
    def test_list_buckets_command_fail(self, mock_results, mock_boto_client):
        self.mock_s3_client.list_buckets.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_s3_client

        list_buckets_command()
        mock_results.assert_called_with({
            "status_command": "Fail",
            "buckets": None
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_s3.orenctl.results')
    def test_get_bucket_policy_command_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_s3_client

        get_bucket_policy_command()
        mock_results.assert_called_with({
            "status_command": "Success",
            "bucket_policy": json.loads(self.mock_s3_client.get_bucket_policy.return_value['Policy'])
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl.getArg', side_effect=MockOrenctl.getArg)
    @patch('aws_s3.orenctl.results')
    def test_get_bucket_policy_command_fail(self, mock_results, mock_getArg, mock_boto_client):
        self.mock_s3_client.get_bucket_policy.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 400}
        }
        mock_boto_client.return_value = self.mock_s3_client

        get_bucket_policy_command()
        mock_results.assert_called_with({
            "status_command": "Fail",
            "bucket_policy": None
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_put_bucket_policy_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client
        self.mock_s3_client.put_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

        put_bucket_policy_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "message": "Successfully applied bucket policy to test-bucket bucket"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_delete_bucket_policy_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client
        self.mock_s3_client.delete_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": 204}}

        delete_bucket_policy_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "message": "Policy was deleted from test-bucket"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_download_file_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()
        mock_orenctl.upload_file = MagicMock(return_value="https://example.com/file")

        mock_boto_client.return_value = self.mock_s3_client

        with patch('tempfile.mkdtemp', return_value='/tmp/test'):
            with patch('builtins.open', new_callable=unittest.mock.mock_open):
                with patch('os.remove'):
                    with patch('os.rmdir'):
                        download_file_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "location": "https://example.com/file",
            "file_name": "test-key"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_list_objects_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client

        list_objects_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "objects": [
                [{"Key": "test1"}, {"Key": "test2"}],
                [{"Key": "test3"}]
            ]
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_get_public_access_block_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client

        get_public_access_block_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_put_public_access_block_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client
        self.mock_s3_client.put_public_access_block.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

        put_public_access_block_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "message": "Successfully applied public access block to the test-bucket bucket"
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_get_bucket_encryption_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client

        get_bucket_encryption_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "server_side_encryption_configuration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }
        })

    @patch('aws_s3.boto3.client')
    @patch('aws_s3.orenctl')
    def test_upload_file_command(self, mock_orenctl, mock_boto_client):
        mock_orenctl.getArg.side_effect = MockOrenctl.getArg
        mock_orenctl.results = MagicMock()
        mock_orenctl.error = MagicMock()

        mock_boto_client.return_value = self.mock_s3_client

        with patch('tempfile.mkdtemp', return_value='/tmp/test'):
            with patch('builtins.open', new_callable=unittest.mock.mock_open):
                with patch('os.remove'):
                    with patch('os.rmdir'):
                        upload_file_command()

        mock_orenctl.results.assert_called_with({
            "status_command": "Success",
            "message": "File test-key was uploaded successfully to test-bucket"
        })


if __name__ == '__main__':
    unittest.main()
