import time
from datetime import datetime, timezone

import dateparser
last_alert = {}
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

print(filters)