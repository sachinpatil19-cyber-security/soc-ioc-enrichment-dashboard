import argparse
import sqlite3
import json
from datetime import datetime

DB_PATH = "events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw TEXT,
    iocs TEXT,
    enrichment TEXT,
    tags TEXT,
    ts TEXT
);
"""


def create_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA)
    conn.commit()
    conn.close()


def ingest(jsonl_path, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            raw = obj.get("raw")
            iocs = json.dumps(obj.get("iocs", {}))
            enrichment = json.dumps(obj.get("enrichment", {}))
            tags = json.dumps(obj.get("tags", []))
            ts = obj.get("ts") or datetime.utcnow().isoformat() + "Z"
            cur.execute(
                "INSERT INTO events (raw,iocs,enrichment,tags,ts) VALUES (?,?,?,?,?)",
                (raw, iocs, enrichment, tags, ts),
            )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Ingest JSONL of enriched events into SQLite DB")
    p.add_argument("input", help="JSONL input file")
    p.add_argument("--db", default=DB_PATH, help="SQLite DB path")
    args = p.parse_args()
    create_db(args.db)
    ingest(args.input, args.db)
    print(f"Ingested {args.input} -> {args.db}")
