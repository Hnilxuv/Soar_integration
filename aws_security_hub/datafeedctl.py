last_run = {}
fed_alert = []


def get_last_run_status():
    return last_run


def set_last_run(extra_info):
    last_run.update({"extra_info": extra_info})


def sync_alerts(alerts, extra_info):
    fed_alert.extend(alerts)
    set_last_run(extra_info)
    return
