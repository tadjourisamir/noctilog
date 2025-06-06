import sqlite3
import json
import hashlib

def generate_event_hash(event):
    h = hashlib.sha256()
    content = f"{event.get('event_type')}|{event.get('message')}|{json.dumps(event.get('extra', {}), sort_keys=True)}"
    h.update(content.encode("utf-8"))
    return h.hexdigest()

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            message TEXT,
            source TEXT,
            severity TEXT,
            acknowledged INTEGER DEFAULT 0,
            extra_data TEXT,
            event_hash TEXT UNIQUE
        )
    """)
    conn.commit()
    return conn

def insert_event(conn, event):
    try:
        cur = conn.cursor()
        event_hash = generate_event_hash(event)
        extra_json = json.dumps(event.get("extra", {}))
        acknowledged = int(event.get("acknowledged", False))

        cur.execute("""
            INSERT OR IGNORE INTO events (
                timestamp, event_type, message, source, severity,
                acknowledged, extra_data, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("event_type"),
            event.get("message"),
            event.get("source"),
            event.get("severity"),
            acknowledged,
            extra_json,
            event_hash
        ))
        conn.commit()
    except Exception as e:
        print(f"[DB Error] Failed to insert event: {e}")
