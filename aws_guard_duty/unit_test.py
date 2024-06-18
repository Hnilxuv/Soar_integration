import os
import unittest
from unittest.mock import patch, MagicMock
import json

from aws_guard_duty import (
    create_detector,
    delete_detector,
    get_detector,
    update_detector,
    list_detectors,
    create_ip_set,
    delete_ip_set,
    update_ip_set,
    get_ip_set,
    list_ip_sets,
    create_threat_intel_set,
    delete_threat_intel_set,
    update_threat_intel_set,
    get_threat_intel_set,
    list_threat_intel_sets,
    list_findings,
    get_findings,
    create_sample_findings,
    archive_findings,
    unarchive_findings,
    update_findings_feedback,
    list_members,
    get_members
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
            "enabled": True,
            "finding_frequency": "FIFTEEN_MINUTES",
            "enable_kubernetes_logs": True,
            "ebs_volumes_malware_protection": True,
            "enable_s3_logs": False,
            "activate": True,
            "format": "TXT",
            "location": "us-east-1",
            "name": "example_name",
            "detect_id": "example_detect_id",
            "ip_set_id": "example_ip_set_id",
            "threat_intel_set_id": "example_threat_intel_set_id",
            "finding_ids": ["finding_id_1", "finding_id_2"],
            "account_ids": ["account_id_1", "account_id_2"],
            "finding_types": ["UnauthorizedAccess:EC2/TorIPCaller"]
        }
        return args.get(arg)

    @staticmethod
    def results(result):
        print(json.dumps(result))

    @staticmethod
    def error(message):
        return {"error": message}


class TestAwsGuardDuty(unittest.TestCase):

    def setUp(self):
        mock_data_file = os.path.join(os.path.dirname(__file__), "test_data", "test_data.json")
        with open(mock_data_file, "r") as f:
            self.mock_data = json.load(f)
        self.finding = self.mock_data.get("FINDING")
        self.detector = self.mock_data.get("DETECTOR_RESPONSE")
        self.member = self.mock_data.get("GET_MEMBERS_RESPONSE")

        self.mock_client = MagicMock()
        self.mock_client.create_detector.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "DetectorId": "test-detector-id"
        }
        self.mock_client.delete_detector.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.get_detector.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            **self.detector
        }
        self.mock_client.update_detector.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.create_ip_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "IpSetId": "test-ip-set-id"
        }
        self.mock_client.delete_ip_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.update_ip_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.get_ip_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Format": "TXT",
            "Location": "s3://example-bucket/ip-set.txt",
            "Name": "test-ip-set",
            "Status": "ACTIVE"
        }
        self.mock_client.create_threat_intel_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "ThreatIntelSetId": "test-threat-intel-set-id"
        }
        self.mock_client.delete_threat_intel_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.update_threat_intel_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.get_threat_intel_set.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Format": "TXT",
            "Location": "s3://example-bucket/threat-intel-set.txt",
            "Name": "test-threat-intel-set",
            "Status": "ACTIVE"
        }
        self.mock_client.get_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "findings": [self.finding, self.finding]
        }
        self.mock_client.create_sample_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.archive_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.unarchive_findings.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.update_findings_feedback.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }
        self.mock_client.get_members.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            **self.member
        }

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_create_detector_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        create_detector()
        mock_results.assert_called_with({
            "status_command": "Success",
            "detect_id": "test-detector-id"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_delete_detector_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        delete_detector()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The Detector example_detect_id has been deleted"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_get_detector_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_detector()
        mock_results.assert_called_with({
            "status_command": "Success",
            "detector": self.detector
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_update_detector_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        update_detector()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The Detector example_detect_id has been updated successfully"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_list_detectors_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_paginator = MagicMock()
        mock_paginate = MagicMock()

        # Example response structure for paginate
        mock_paginate_response = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "DetectorIds": ["test-detector-id"]
        }

        self.mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = mock_paginate
        mock_paginate.__iter__.return_value = iter([mock_paginate_response])

        mock_boto_client.return_value = self.mock_client

        list_detectors()
        mock_results.assert_called_with({
            "status_command": "Success",
            "detectors": [{"detect_id": "test-detector-id"}]
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_create_ip_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        create_ip_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "ip_set_id": "test-ip-set-id"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_delete_ip_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        delete_ip_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The IPSet example_ip_set_id has been deleted from Detector example_detect_id"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_update_ip_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        update_ip_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The IPSet example_ip_set_id has been Updated"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_get_ip_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_ip_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "ip_set": {
                "Format": "TXT",
                "Location": "s3://example-bucket/ip-set.txt",
                "Name": "test-ip-set",
                "Status": "ACTIVE"
            }
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_list_ip_sets_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_paginator = MagicMock()
        mock_paginate = MagicMock()

        # Example response structure for paginate
        mock_paginate_response = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "IpSetIds": ["test-ip-set-id"]
        }

        self.mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = mock_paginate
        mock_paginate.__iter__.return_value = iter([mock_paginate_response])

        mock_boto_client.return_value = self.mock_client

        list_ip_sets()
        mock_results.assert_called_with({
            "status_command": "Success",
            "ip_sets": [{"IpSetId": "test-ip-set-id"}]
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_create_threat_intel_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        create_threat_intel_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "threat_intel_set_id": "test-threat-intel-set-id"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_delete_threat_intel_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        delete_threat_intel_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The ThreatIntel set example_threat_intel_set_id has been deleted from Detector example_detect_id"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_update_threat_intel_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        update_threat_intel_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "The ThreatIntel set example_threat_intel_set_id has been Updated"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_get_threat_intel_set_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_threat_intel_set()
        mock_results.assert_called_with({
            "status_command": "Success",
            "threat_intel_set": {
                "Format": "TXT",
                "Location": "s3://example-bucket/threat-intel-set.txt",
                "Name": "test-threat-intel-set",
                "Status": "ACTIVE"
            }
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_list_threat_intel_sets_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_paginator = MagicMock()
        mock_paginate = MagicMock()

        # Example response structure for paginate
        mock_paginate_response = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "ThreatIntelSetIds": ["test-threat-intel-set-id"]
        }

        self.mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = mock_paginate
        mock_paginate.__iter__.return_value = iter([mock_paginate_response])

        mock_boto_client.return_value = self.mock_client
        list_threat_intel_sets()
        mock_results.assert_called_with({
            "status_command": "Success",
            "threat_intel_sets": [{"ThreatIntelSetId": "test-threat-intel-set-id"}]
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_list_findings_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_paginator = MagicMock()
        mock_paginate = MagicMock()

        # Example response structure for paginate
        mock_paginate_response = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "FindingIds": ["finding-id-1", "finding-id-2"]
        }

        self.mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = mock_paginate
        mock_paginate.__iter__.return_value = iter([mock_paginate_response])

        mock_boto_client.return_value = self.mock_client

        list_findings()
        mock_results.assert_called_with({
            "status_command": "Success",
            "findings": [{"FindingId": "finding-id-1"}, {"FindingId": "finding-id-2"}]
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_get_findings_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_findings()
        mock_results.assert_called_with({
            "status_command": "Success",
            "findings": [self.finding, self.finding]
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_create_sample_findings_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        create_sample_findings()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "Sample Findings were generated"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_archive_findings_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        archive_findings()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "Findings were archived"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_unarchive_findings_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        unarchive_findings()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "Findings were unarchived"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_update_findings_feedback_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        update_findings_feedback()
        mock_results.assert_called_with({
            "status_command": "Success",
            "message": "Findings Feedback sent!"
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_list_members_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_paginator = MagicMock()
        mock_paginate = MagicMock()

        # Example response structure for paginate
        mock_paginate_response = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Members": ["member-1", "member-2"]
        }

        self.mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = mock_paginate
        mock_paginate.__iter__.return_value = iter([mock_paginate_response])

        mock_boto_client.return_value = self.mock_client

        list_members()
        mock_results.assert_called_with({
            "status_command": "Success",
            "members": [{"Member": "member-1"}, {"Member": "member-2"}]
        })

    @patch("aws_guard_duty.boto3.client")
    @patch("aws_guard_duty.orenctl.getArg", side_effect=MockOrenctl.getArg)
    @patch("aws_guard_duty.orenctl.results")
    def test_get_members_success(self, mock_results, mock_getArg, mock_boto_client):
        mock_boto_client.return_value = self.mock_client

        get_members()
        mock_results.assert_called_with({
            "status_command": "Success",
            "members": self.member.get("Members")
        })


if __name__ == "__main__":
    unittest.main()

