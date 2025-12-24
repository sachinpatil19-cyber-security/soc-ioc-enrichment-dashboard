import sqlite3
import json
import streamlit as st
import pandas as pd
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()
APP_PASSWORD = os.getenv("APP_PASSWORD")

DB_PATH = "events.db"

st.set_page_config(page_title="IOC Dashboard", layout="wide")
st.title("IOC Enrichment Dashboard")

# Simple password gate: if APP_PASSWORD is set, require it to view the dashboard
if APP_PASSWORD:
    if 'auth' not in st.session_state:
        st.session_state['auth'] = False
    if not st.session_state['auth']:
        with st.sidebar:
            pw = st.text_input("Dashboard password", type="password")
            if st.button("Login"):
                if pw == APP_PASSWORD:
                    st.session_state['auth'] = True
                    st.experimental_rerun()
                else:
                    st.warning("Incorrect password")
        st.stop()

@st.cache_data
def load_events(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT id, raw, iocs, enrichment, tags, ts FROM events ORDER BY ts DESC", conn)
    conn.close()
    # parse JSON columns
    for col in ["iocs", "enrichment", "tags"]:
        df[col] = df[col].apply(lambda x: json.loads(x) if x else {})
    return df


def update_tag(event_id, new_tag, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT tags FROM events WHERE id=?", (event_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False
    tags = json.loads(row[0]) if row[0] else []
    if new_tag not in tags:
        tags = [new_tag]
    else:
        tags = [new_tag]
    cur.execute("UPDATE events SET tags=? WHERE id=?", (json.dumps(tags), event_id))
    conn.commit()
    conn.close()
    st.experimental_rerun()


def set_event_tags(event_id, tags, db_path=DB_PATH):
    """Set tags for an event without triggering a rerun."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE events SET tags=? WHERE id=?", (json.dumps(tags), event_id))
    conn.commit()
    conn.close()


try:
    df = load_events()
except Exception as e:
    st.error(f"Database error: {e}")
    with st.sidebar:
        st.markdown("**No `events` table found or DB missing.**")
        st.write("You can create the DB and ingest the demo dataset (`sample_data.jsonl`).")
        if st.button("Create DB & ingest sample data"):
            try:
                from ingest import create_db, ingest
                create_db()
                ingest("sample_data.jsonl")
                st.success("Ingest completed — reloading...")
                st.experimental_rerun()
            except Exception as ie:
                st.error(f"Failed to ingest sample data: {ie}")
    st.stop()

with st.sidebar:
    st.header("Filters")
    q = st.text_input("Search IOC / free text")
    all_tags = set(sum([t if isinstance(t, list) else [] for t in df['tags'].tolist()], []))
    tag_filter = st.multiselect("Tags", options=sorted(list(all_tags)))
    start_ts = st.date_input("From")
    end_ts = st.date_input("To")
    if st.button("Refresh"):
        st.cache_data.clear()
        df = load_events()

# Apply filters
fdf = df.copy()
if q:
    fdf = fdf[fdf['raw'].str.contains(q, case=False, na=False) | fdf['iocs'].astype(str).str.contains(q, case=False, na=False)]
if tag_filter:
    fdf = fdf[fdf['tags'].apply(lambda t: any(x in t for x in tag_filter) if isinstance(t, list) else False)]
# date filter (by ts date)
try:
    fdf['date'] = pd.to_datetime(fdf['ts']).dt.date
    fdf = fdf[(fdf['date'] >= start_ts) & (fdf['date'] <= end_ts)]
except Exception:
    pass

st.subheader(f"Events ({len(fdf)})")
st.dataframe(fdf[['id','ts','raw','tags']].rename(columns={'ts':'time','raw':'event'}))

selected_id = st.selectbox("Select event id to view details", options=[None] + fdf['id'].tolist())
if selected_id:
    row = fdf[fdf['id'] == selected_id].iloc[0]
    st.markdown("### Event detail")
    st.write("**Time:**", row['ts'])
    st.write("**Raw:**", row['raw'])
    st.markdown("**IOCs:**")
    st.json(row['iocs'])

    st.markdown("**IP reputation (AbuseIPDB)**")
    ips = row['iocs'].get('ipv4', []) if isinstance(row['iocs'], dict) else []
    if ips:
        for ip in ips:
            ip_enr = row['enrichment'].get('ips', {}).get(ip, {}) if isinstance(row['enrichment'], dict) else {}
            abuse_info = ip_enr.get('abuseipdb') if isinstance(ip_enr, dict) else None
            col_a, col_b = st.columns([3,2])
            with col_a:
                st.write(f"**{ip}**")
                if abuse_info:
                    score = abuse_info.get('abuseConfidenceScore')
                    reports = abuse_info.get('totalReports')
                    country = abuse_info.get('countryCode')
                    st.write(f"Score: {score}  | Reports: {reports}  | Country: {country}")
                else:
                    st.write("No AbuseIPDB data")
            with col_b:
                if st.button(f"Check AbuseIPDB: {ip}"):
                    # perform lookup and update DB
                    from abuseipdb import lookup_ip
                    res = lookup_ip(ip)
                    # store result in DB
                    def update_ip_enrichment(event_id, ip_addr, data, db_path=DB_PATH):
                        conn = sqlite3.connect(db_path)
                        cur = conn.cursor()
                        cur.execute("SELECT enrichment FROM events WHERE id=?", (event_id,))
                        rowe = cur.fetchone()
                        enrich = json.loads(rowe[0]) if rowe and rowe[0] else {}
                        enrich.setdefault('ips', {})
                        enrich['ips'].setdefault(ip_addr, {})
                        enrich['ips'][ip_addr].setdefault('abuseipdb', {})
                        enrich['ips'][ip_addr]['abuseipdb'].update(data)
                        cur.execute("UPDATE events SET enrichment=? WHERE id=?", (json.dumps(enrich), event_id))
                        conn.commit()
                        conn.close()
                    update_ip_enrichment(selected_id, ip, res)
                    st.success(f"AbuseIPDB lookup saved for {ip}")
                    st.experimental_rerun()

    st.markdown("**Enrichment:**")
    st.json(row['enrichment'])
    st.markdown("**Tags:**")
    st.write(row['tags'])
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Tag: malicious"):
            update_tag(selected_id, "malicious")
    with col2:
        if st.button("Tag: suspicious"):
            update_tag(selected_id, "suspicious")
    with col3:
        if st.button("Tag: unknown"):
            update_tag(selected_id, "unknown")

    # per-event push to SIEM
    st.markdown("**Push to SIEM / Export**")
    se1, se2 = st.columns(2)
    with se1:
        if st.button("Push this event -> Elasticsearch"):
            try:
                from exporters import push_to_elasticsearch
                ev = {"id": row['id'], "ts": row['ts'], "raw": row['raw'], "iocs": row['iocs'], "enrichment": row['enrichment'], "tags": row['tags']}
                res = push_to_elasticsearch(ev)
                if res.get('ok'):
                    st.success("Event pushed to Elasticsearch")
                else:
                    st.error(f"Elasticsearch push failed: {res}")
            except Exception as e:
                st.error(f"Error: {e}")
    with se2:
        if st.button("Push this event -> Splunk HEC"):
            try:
                from exporters import push_to_splunk
                ev = {"id": row['id'], "ts": row['ts'], "raw": row['raw'], "iocs": row['iocs'], "enrichment": row['enrichment'], "tags": row['tags']}
                res = push_to_splunk(ev)
                if res.get('ok'):
                    st.success("Event pushed to Splunk HEC")
                else:
                    st.error(f"Splunk push failed: {res}")
            except Exception as e:
                st.error(f"Error: {e}")

# ----------------- IP Reputation Dashboard -----------------
st.header("IP Reputation Dashboard")
st.write("Aggregated IPs (from current filtered events) with AbuseIPDB scores and counts.")

# Build summary across filtered events
ip_map = {}
for _, r in fdf.iterrows():
    ts = r.get('ts')
    iocs = r.get('iocs') if isinstance(r.get('iocs'), dict) else {}
    ips = iocs.get('ipv4', []) if isinstance(iocs, dict) else []
    for ip in ips:
        rec = ip_map.setdefault(ip, {'count': 0, 'last_seen': None, 'score': None, 'total_reports': None, 'country': None})
        rec['count'] += 1
        try:
            if ts and (rec['last_seen'] is None or ts > rec['last_seen']):
                rec['last_seen'] = ts
        except Exception:
            pass
        ip_enr = r.get('enrichment') if isinstance(r.get('enrichment'), dict) else {}
        abuse = ip_enr.get('ips', {}).get(ip, {}).get('abuseipdb') if isinstance(ip_enr, dict) else None
        if abuse:
            # prefer recorded score (no timestamp in abuse record) - override
            rec['score'] = abuse.get('abuseConfidenceScore')
            rec['total_reports'] = abuse.get('totalReports')
            rec['country'] = abuse.get('countryCode')

# Build DataFrame
if ip_map:
    rows = []
    for ip, v in ip_map.items():
        rows.append({
            'ip': ip,
            'count': v['count'],
            'score': v['score'] if v['score'] is not None else -1,
            'reports': v.get('total_reports') or 0,
            'country': v.get('country') or '',
            'last_seen': v.get('last_seen')
        })
    ip_df = pd.DataFrame(rows)
    ip_df = ip_df.sort_values(['score', 'count'], ascending=[False, False])
    st.dataframe(ip_df[['ip', 'count', 'score', 'reports', 'country', 'last_seen']])

    # Auto-tagging controls
    st.markdown("**Auto-tagging**")
    st.write("Set thresholds and apply tags to events in the current view based on AbuseIPDB score (0-100).")
    c1, c2, c3 = st.columns([2,2,1])
    with c1:
        mal_thr = st.number_input("Malicious threshold", min_value=0, max_value=100, value=80, help=">= this score -> malicious")
        sus_thr = st.number_input("Suspicious threshold", min_value=0, max_value=100, value=50, help=">= this score -> suspicious")
    with c2:
        dry_run = st.checkbox("Dry run (show counts only)", value=True)
    with c3:
        if st.button("Apply auto-tags to view"):
            counts = {"malicious": 0, "suspicious": 0, "updated_events": 0}
            for ip in ip_df['ip'].tolist():
                try:
                    score = float(ip_df.loc[ip_df['ip'] == ip, 'score'].iloc[0])
                except Exception:
                    score = None
                if score is None or score < 0:
                    continue
                tag = None
                if score >= mal_thr:
                    tag = 'malicious'
                elif score >= sus_thr:
                    tag = 'suspicious'
                if tag:
                    events_to_update = fdf[fdf['iocs'].apply(lambda x: isinstance(x, dict) and ip in x.get('ipv4', []))]
                    counts[tag] += len(events_to_update)
                    if not dry_run:
                        for eid in events_to_update['id'].tolist():
                            set_event_tags(eid, [tag])
                            counts['updated_events'] += 1
            if dry_run:
                st.info(f"Dry run: would tag malicious={counts['malicious']} events, suspicious={counts['suspicious']} events.")
            else:
                st.success(f"Tagged {counts['updated_events']} events (malicious: {counts['malicious']}, suspicious: {counts['suspicious']})")
                st.experimental_rerun()

    selected_ip = st.selectbox("Select IP for details", options=[None] + ip_df['ip'].tolist())
    if selected_ip:
        st.markdown("**Details**")
        st.json(ip_map[selected_ip])
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"Refresh AbuseIPDB for {selected_ip}"):
                from abuseipdb import lookup_ip
                res = lookup_ip(selected_ip)
                # update enrichment for events that include this IP
                events_to_update = fdf[fdf['iocs'].apply(lambda x: isinstance(x, dict) and selected_ip in x.get('ipv4', []))]
                for eid in events_to_update['id'].tolist():
                    conn = sqlite3.connect(DB_PATH)
                    cur = conn.cursor()
                    cur.execute("SELECT enrichment FROM events WHERE id=?", (eid,))
                    rowe = cur.fetchone()
                    enrich = json.loads(rowe[0]) if rowe and rowe[0] else {}
                    enrich.setdefault('ips', {})
                    enrich['ips'].setdefault(selected_ip, {})
                    enrich['ips'][selected_ip].setdefault('abuseipdb', {})
                    enrich['ips'][selected_ip]['abuseipdb'].update(res)
                    cur.execute("UPDATE events SET enrichment=? WHERE id=?", (json.dumps(enrich), eid))
                    conn.commit()
                    conn.close()
                st.success(f"AbuseIPDB lookup saved for {selected_ip} on {len(events_to_update)} events.")
                st.experimental_rerun()
        with col2:
            if st.button("Bulk refresh all IPs (obey your rate limits)"):
                st.warning("This will query AbuseIPDB for each IP — ensure you are within your rate limits.")
                from abuseipdb import lookup_ip
                for ip in ip_df['ip'].tolist():
                    res = lookup_ip(ip)
                    events_to_update = fdf[fdf['iocs'].apply(lambda x: isinstance(x, dict) and ip in x.get('ipv4', []))]
                    for eid in events_to_update['id'].tolist():
                        conn = sqlite3.connect(DB_PATH)
                        cur = conn.cursor()
                        cur.execute("SELECT enrichment FROM events WHERE id=?", (eid,))
                        rowe = cur.fetchone()
                        enrich = json.loads(rowe[0]) if rowe and rowe[0] else {}
                        enrich.setdefault('ips', {})
                        enrich['ips'].setdefault(ip, {})
                        enrich['ips'][ip].setdefault('abuseipdb', {})
                        enrich['ips'][ip]['abuseipdb'].update(res)
                        cur.execute("UPDATE events SET enrichment=? WHERE id=?", (json.dumps(enrich), eid))
                        conn.commit()
                        conn.close()
                st.success("Bulk refresh completed.")
                st.experimental_rerun()

        # --- bulk push to SIEM for IPs/events ---
        st.markdown("**Push filtered events to SIEM / Export**")
        dest = st.selectbox("Destination", options=["elasticsearch", "splunk", "both"] )
        es_index = st.text_input("ES index (for Elasticsearch)", value="ioc-events")
        splunk_index = st.text_input("Splunk index (optional)", value="main")
        if st.button("Push filtered events to destination"):
            events = []
            for _, er in fdf.iterrows():
                events.append({"id": er['id'], "ts": er['ts'], "raw": er['raw'], "iocs": er['iocs'], "enrichment": er['enrichment'], "tags": er['tags']})
            successes = 0
            failures = 0
            details = []
            if dest in ("elasticsearch", "both"):
                from exporters import push_bulk_to_elasticsearch
                res = push_bulk_to_elasticsearch(events, index=es_index)
                if res.get('ok'):
                    successes += len(events)
                else:
                    failures += 1
                    details.append(res)
            if dest in ("splunk", "both"):
                from exporters import push_bulk_to_splunk
                res2 = push_bulk_to_splunk(events, index=splunk_index)
                if res2.get('ok') is None:  # splunk returns counts
                    successes += res2.get('ok',0)
                    failures += res2.get('failed',0)
                else:
                    # unexpected
                    details.append(res2)
            st.success(f"Push completed: successes={successes}, failures={failures}")
            if details:
                st.json(details)

else:
    st.info("No IPs found in the current view.")

st.markdown("---")
st.markdown("**Tips:** Use `python ingest.py sample_data.jsonl` to load demo data, then `streamlit run app.py` to start the dashboard.")

if __name__ == "__main__":
    import sys
    print("This is a Streamlit app — run with: streamlit run app.py")
    sys.exit(1)
