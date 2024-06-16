import json
import os
import unittest
import requests_mock
from microfocus_smax import MicrofocusSmax, get_entities, get_entity, update_entity, create_entity, feed_alert
import orenctl
from microfocus_smax import datafeedctl


class TestSmax(unittest.TestCase):
    def setUp(cls):
        mock_data_file = os.path.join(os.path.dirname(__file__), "test_data", "test_data.json")
        with open(mock_data_file, 'r') as f:
            cls.mock_data = json.load(f)

        orenctl.set_params({
            "url": "https://test.com",
            "username": "test",
            "password": "test,",
            "tenant_id": "test",
            "insecure": False
        })
        cls.mock_smax = MicrofocusSmax()
        cls.mocker = requests_mock.Mocker()
        cls.mocker.start()
        cls.mocker.post(f"{cls.mock_smax.url}/auth/authentication-endpoint/authenticate/"
                        f"login?TENANTID={cls.mock_smax.tenant_id}", text="token")

    def tearDown(cls):
        cls.mocker.stop()

    def test_get_entities(self):
        orenctl.set_input_args({
            "entity_type": "Incident",
            "entity_fields": "FullLayout.properties",
            "query_filter": "EmsCreationTime btw (133123123123,143123123123)",
            "order_by": "Id desc",
            "size": 250,
            "skip": None
        })
        entity_type = orenctl.getArg('entity_type')
        expected_result = self.mock_data['get_entities']
        self.mocker.get(f"{self.mock_smax.url}/rest/{self.mock_smax.tenant_id}/ems/{entity_type}",
                        json=expected_result)
        get_entities()
        result = orenctl.get_results().get("results")[0].get("Contents")
        if isinstance(result, str):
            result = json.loads(result)
        self.assertEqual(result.get("data_entities"), expected_result)

    def test_get_entity(self):
        orenctl.set_input_args({
            "entity_type": "Incident",
            "entity_fields": "FullLayout.properties",
            "entity_id": "11704",
        })
        entity_type = orenctl.getArg('entity_type')
        entity_id = orenctl.getArg('entity_id')
        expected_result = self.mock_data['get_entities']
        self.mocker.get(f"{self.mock_smax.url}/rest/{self.mock_smax.tenant_id}/ems/{entity_type}/{entity_id}",
                        json=expected_result)
        get_entity()
        result = orenctl.get_results().get("results")[0].get("Contents")
        if isinstance(result, str):
            result = json.loads(result)
        self.assertEqual(result.get("data_entity"), expected_result)

    def test_update_entity(self):
        orenctl.set_input_args({
            "entity_type": "Incident",
            "entity_properties": {
                "Status": "Complete",
            },
        })
        entity_type = orenctl.getArg('entity_type')
        expected_result = self.mock_data['update_entity']
        self.mocker.post(f"{self.mock_smax.url}/rest/{self.mock_smax.tenant_id}/ems/bulk",
                         json=expected_result)
        update_entity()
        result = orenctl.get_results().get("results")[0].get("Contents")
        if isinstance(result, str):
            result = json.loads(result)
        self.assertEqual(result.get("data_update"), expected_result)

    def test_create_entity(self):
        orenctl.set_input_args({
            "entity_type": "Incident",
            "entity_properties": {
                "ImpactScope": "SingleUser",
                "Active": True,
                "RequestedByPerson": "10073",
                "PhaseId": "Log",
                "ProcessId": "normal",
                "FirstTouch": True,
                "Urgency": "SlightDisruption",
                "RegisteredForActualService": "10916",
                "ServiceDeskGroup": "10646",
                "CompletionCode": True,
                "DisplayLabel": "Test_Incident",
                "Priority": "LowPriority",
                "Description": "<p>Test</p>"
            },
        })
        entity_type = orenctl.getArg('entity_type')
        expected_result = self.mock_data['create_entity']
        self.mocker.post(f"{self.mock_smax.url}/rest/{self.mock_smax.tenant_id}/ems/bulk",
                         json=expected_result)
        create_entity()
        result = orenctl.get_results().get("results")[0].get("Contents")
        if isinstance(result, str):
            result = json.loads(result)
        self.assertEqual(result.get("data_create"), expected_result)

    def test_feed_alert(self):
        orenctl.set_headers({
            "condition": None,
            "fields": "FullLayout.properties",
            "limit_alert": "100",
        })
        expected_result = self.mock_data['get_entities']
        self.mocker.get(f"{self.mock_smax.url}/rest/{self.mock_smax.tenant_id}/ems/Incident",
                        json=expected_result)
        feed_alert()
        fed_alert = datafeedctl.fed_alert
        last_alert_timestamp = datafeedctl.last_run.get("extra_info").get("timestamp")
        assert len(fed_alert) == len(expected_result.get("entities"))
        assert last_alert_timestamp == expected_result.get("entities")[0].get("properties").get("EmsCreationTime")


