import os
import requests

ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
URL = "https://api.abuseipdb.com/api/v2/check"


def lookup_ip(ip, max_age_days=90):
    """Query AbuseIPDB for `ip`. Returns dict with keys: abuseConfidenceScore, countryCode, totalReports, raw
    If API key is not set returns {'error':'no_key'}"""
    if not ABUSE_KEY:
        return {"error": "no_key"}
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    try:
        r = requests.get(URL, headers=headers, params=params, timeout=10)
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 200:
        d = r.json().get("data", {})
        return {
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "countryCode": d.get("countryCode"),
            "totalReports": d.get("totalReports"),
            "raw": d,
        }
    else:
        return {"error": r.text, "status_code": r.status_code}
