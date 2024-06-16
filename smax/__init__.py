import time
from datetime import datetime
import requests
import json
import orenctl
from microfocus_smax import datafeedctl


class MicrofocusSmax(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.tenant_id = orenctl.getParam("tenant_id")
        self.session = requests.session()
        self.session.headers = {
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        token = self.get_api_key()
        self.session.headers.update({"Cookie": f"SMAX_AUTH_TOKEN={token}"})
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise Exception(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_api_key(self):
        url = self.url + f"/auth/authentication-endpoint/authenticate/login?TENANTID={self.tenant_id}"
        data = {
            "Login": self.username,
            "Password": self.password
        }
        response = requests.post(url=url, data=json.dumps(data), verify=False)
        token = response.text
        if not token:
            orenctl.results(
                orenctl.error(f"Authorization Error: please check your credentials. \n\nError:\n{response}"))
        return token

    def get_entity(self, entity_type, entity_id, entity_fields):
        url_suffix = f"/rest/{self.tenant_id}/ems/{entity_type}/{entity_id}"
        params = {"layout": entity_fields}
        return self.http_request(method="GET", url_suffix=url_suffix, params=params)

    def query_entities(self, entity_type, query_filter, entity_fields, order_by, size, skip):
        url_suffix = f"/rest/{self.tenant_id}/ems/{entity_type}"
        params = {
            "layout": entity_fields,
            "meta": "TotalCount,Count"
        }
        if query_filter:
            params.update({"filter": query_filter})
        if order_by:
            params.update({"order": order_by})
        if size:
            params.update({"size": size})
        if skip:
            params.update({"skip": skip})
        return self.http_request(method="GET", url_suffix=url_suffix, params=params)

    def bulk_action(self, action_type, entities):
        if type(entities) == str:
            entities = json.loads(entities)
        url_suffix = f"/rest/{self.tenant_id}/ems/bulk"
        payload = {
            "entities": entities,
            "operation": action_type
        }
        return self.http_request(method="POST", url_suffix=url_suffix, data=json.dumps(payload))


def get_entities():
    entity_type = orenctl.getArg("entity_type")
    entity_fields = orenctl.getArg("entity_fields")
    query_filter = orenctl.getArg("query_filter")
    order_by = orenctl.getArg("order_by")
    size = orenctl.getArg("size")
    skip = orenctl.getArg("skip")
    ms = MicrofocusSmax()
    result = ms.query_entities(
        entity_type=entity_type,
        query_filter=query_filter,
        entity_fields=entity_fields,
        order_by=order_by,
        size=int(size),
        skip=skip
    )
    orenctl.results({
        "data_entities": result
    })


def get_entity():
    entity_type = orenctl.getArg("entity_type")
    entity_id = orenctl.getArg("entity_id")
    entity_fields = orenctl.getArg("entity_fields")
    ms = MicrofocusSmax()
    result = ms.get_entity(entity_type=entity_type, entity_id=entity_id, entity_fields=entity_fields)
    orenctl.results({
        "data_entity": result
    })


def create_entity():
    entity_type = orenctl.getArg("entity_type")
    entity_properties = orenctl.getArg("entity_properties")
    ms = MicrofocusSmax()
    entities = [
        {
            "entity_type": entity_type,
            "properties": entity_properties
        }
    ]
    result = ms.bulk_action(action_type="CREATE", entities=entities)
    orenctl.results({
        "data_create": result
    })


def update_entity():
    entity_type = orenctl.getArg("entity_type")
    entity_properties = orenctl.getArg("entity_properties")
    ms = MicrofocusSmax()
    entities = [
        {
            "entity_type": entity_type,
            "properties": entity_properties
        }
    ]
    result = ms.bulk_action(action_type="UPDATE", entities=entities)
    orenctl.results({
        "data_update": result
    })


def feed_alert():
    def get_last_alert():
        """
        Lấy alert cuối cùng đã từng lấy. nếu không có thì lấy tối đa 3 ngày trước đó.
        :return:
        """
        oldest_time = int(time.time() * 1000) - 3 * 24 * 60 * 60 * 1000
        result = datafeedctl.get_last_run_status()
        # orenctl.log(f"get_last_run_status = {result}")
        if not result:
            return oldest_time
        if isinstance(result, str):
            try:
                result = json.loads(result)
                # orenctl.log(f"get_last_run_status={result}")
                result = result.get("extra_info")
                # orenctl.log(f"debug_extra_info={result}")
            except Exception as e:
                raise Exception(
                    f"get_last_run_status error. data={result}. Exception={e}"
                )
        else:
            result = result.get("extra_info")
        timestamp = oldest_time
        if result and isinstance(result, dict):
            for key, value in result.items():
                if key == "timestamp":
                    timestamp = value
        last_10m = int(time.time() * 1000) - 10 * 60 * 1000

        if timestamp > last_10m:
            return last_10m
        return timestamp

    def normalize_alert(alert_list):
        normalize_alerts = []
        for alert in alert_list:
            alert = {key.lower(): value for key, value in alert.items()}
            if "id" in alert:
                alert["smax_id"] = alert.get("id")

            delete_key = []
            for key in alert:
                if alert[key] is None:
                    delete_key.append(key)
            for key in delete_key:
                del alert[key]
            normalize_alerts.append(alert)
        return normalize_alerts

    config = {
        "condition": orenctl.getHeader("condition"),
        "fields": orenctl.getHeader("fields"),
        "limit_alert": orenctl.getHeader("limit_alert"),
    }

    timestamp_last_alert = get_last_alert()

    if timestamp_last_alert is None:
        raise Exception("Error occur when getting last alert")

    query_filter = f"EmsCreationTime btw ({timestamp_last_alert},{round((datetime.now().timestamp() * 1000))})"
    if config["condition"]:
        query_filter += config["condition"]
    fields = config.get("fields")
    if not fields:
        fields = "FullLayout.properties, FullLayout.related_properties"
    size = config.get("limit_alert")
    if not size:
        size = 250
    ms = MicrofocusSmax()
    results = ms.query_entities(
        entity_type="Incident",
        query_filter=query_filter,
        entity_fields=fields,
        order_by="Id asc",
        size=int(size),
        skip=None
    )
    incident = results.get("entities")
    alerts = [incident.get("properties") for incident in incident]

    if not alerts:
        datafeedctl.sync_alerts(alerts, extra_info=timestamp_last_alert)
        return
    # orenctl.log(f"alerts qty: {len(alerts)}")

    alerts = normalize_alert(alerts)
    last_alert = alerts[-1]
    timestamp_last_alert = last_alert.get("emscreationtime")
    extra_info = {"timestamp": timestamp_last_alert}
    # orenctl.log(f"extra_info = {extra_info}")
    datafeedctl.sync_alerts(alerts, extra_info=extra_info)
    return alerts


if orenctl.command() == "get_entities":
    get_entities()
elif orenctl.command() == "get_entity":
    get_entity()
elif orenctl.command() == "create_entity":
    create_entity()
elif orenctl.command() == "update_entity":
    update_entity()
elif orenctl.command() == "feed_alert":
    feed_alert()





