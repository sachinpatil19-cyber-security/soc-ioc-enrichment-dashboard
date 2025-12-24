# IOC Enrichment + Streamlit Dashboard (POC)

Quick prototype to ingest enriched events and browse/tag them with a Streamlit dashboard.

## Requirements
- Python 3.10+
- Install dependencies: `pip install -r requirements.txt`

## Usage
1. Ingest sample data:
   ```bash
   python ingest.py sample_data.jsonl
   ```
2. Start the dashboard (local):
   ```bash
   streamlit run app.py
   ```
3. Start the dashboard with Docker (recommended for POC):
   - Create a `.env` (or export) with `APP_PASSWORD` if you want to enable a password gate.
   - Build and run with docker-compose:
   ```bash
   docker-compose up --build
   ```
4. Auth behavior:
   - If `APP_PASSWORD` is set, you'll be required to enter it in the sidebar before the dashboard content is shown.
   - If `APP_PASSWORD` is not set, the dashboard remains open for local use.

## Files
- `ingest.py` — CLI to import JSONL into `events.db` (SQLite).
- `app.py` — Streamlit dashboard to search, view enrichment details, auto-tag events, manually tag events, and push events to SIEM (Elasticsearch and Splunk HEC).
- `sample_data.jsonl` — demo dataset.

## Auto-tagging
The IP Reputation panel includes an **Auto-tagging** control where you can set thresholds (e.g., malicious >= 80, suspicious >= 50), perform a dry-run to see counts, and apply tags to all events in the current view based on AbuseIPDB scores.

## SIEM Pushback / Export
You can push individual events or the whole filtered view to Elasticsearch or Splunk HEC.

Configuration (set via environment or `.env`):
- `ELASTIC_URL` — e.g., `http://localhost:9200`
- `ELASTIC_USER` / `ELASTIC_PASS` — optional basic auth for Elasticsearch
- `SPLUNK_HEC_URL` — e.g., `https://splunk.example:8088`
- `SPLUNK_HEC_TOKEN` — Splunk HEC token

In the Event Detail view you can:
- Click **Push this event -> Elasticsearch**
- Click **Push this event -> Splunk HEC**

In the IP Reputation panel you can:
- Select **Destination** (Elasticsearch / Splunk / both)
- Set an ES index and Splunk index and click **Push filtered events to destination**

Notes & cautions:
- Bulk pushes may be slow and can trigger rate limits on Splunk HEC or your Elasticsearch cluster; use the UI warnings and perform bulk pushes during maintenance windows for production systems.
- For production, consider adding a background worker (Celery/RQ) and robust error handling / retries / logging.

## Notes
- This is a POC. For production, add authentication, pagination, rate-limited enrichment lookups (VirusTotal/OTX/MISP integrations), caching, and tests.
- Set `VT_API_KEY` in env if you plan to add live enrichment.
