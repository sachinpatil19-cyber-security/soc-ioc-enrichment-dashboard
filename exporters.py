import os
import requests
import json

ELASTIC_URL = os.getenv("ELASTIC_URL")  # e.g. http://localhost:9200
ELASTIC_USER = os.getenv("ELASTIC_USER")
ELASTIC_PASS = os.getenv("ELASTIC_PASS")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")  # e.g. https://splunk.example:8088
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")


def push_to_elasticsearch(event, index="ioc-events"):
    """Push a single event document to Elasticsearch (index/_doc). Returns dict with status info."""
    if not ELASTIC_URL:
        return {"error": "no_elastic_url"}
    url = ELASTIC_URL.rstrip("/") + f"/{index}/_doc"
    headers = {"Content-Type": "application/json"}
    auth = (ELASTIC_USER, ELASTIC_PASS) if ELASTIC_USER and ELASTIC_PASS else None
    try:
        r = requests.post(url, json=event, headers=headers, auth=auth, timeout=10)
    except Exception as e:
        return {"error": str(e)}
    if r.status_code in (200, 201):
        return {"ok": True, "resp": r.json()}
    return {"error": r.text, "status_code": r.status_code}


def push_bulk_to_elasticsearch(events, index="ioc-events"):
    """Push multiple events to Elasticsearch using bulk API. Returns (success_count, failed_count, details)."""
    if not ELASTIC_URL:
        return {"error": "no_elastic_url"}
    url = ELASTIC_URL.rstrip("/") + "/_bulk"
    headers = {"Content-Type": "application/x-ndjson"}
    auth = (ELASTIC_USER, ELASTIC_PASS) if ELASTIC_USER and ELASTIC_PASS else None
    lines = []
    for ev in events:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(ev))
    data = "\n".join(lines) + "\n"
    try:
        r = requests.post(url, data=data.encode("utf-8"), headers=headers, auth=auth, timeout=30)
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 200:
        return {"ok": True, "resp": r.json()}
    return {"error": r.text, "status_code": r.status_code}


def push_to_splunk(event, index=None, host=None):
    """Push a single event to Splunk HEC. `index` optional; host optional."""
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return {"error": "no_splunk_hec_config"}
    url = SPLUNK_HEC_URL.rstrip("/") + "/services/collector/event"
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}", "Content-Type": "application/json"}
    payload = {"event": event}
    if index:
        payload["index"] = index
    if host:
        payload.setdefault("host", host)
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10, verify=False)
    except Exception as e:
        return {"error": str(e)}
    if r.status_code in (200, 201):
        return {"ok": True, "resp": r.json()}
    return {"error": r.text, "status_code": r.status_code}


def push_bulk_to_splunk(events, index=None, host=None):
    """Push multiple events to Splunk HEC one-by-one (HEC doesn't have a true bulk endpoint)."""
    results = {"ok": 0, "failed": 0, "details": []}
    for ev in events:
        res = push_to_splunk(ev, index=index, host=host)
        if res.get("ok"):
            results["ok"] += 1
        else:
            results["failed"] += 1
        results["details"].append(res)
    return results
