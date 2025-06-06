from main import (
    read_audit_log,
    run_detectors,
    generate_event_hash,
    jsonl_contains_hash,
    load_config,
    load_deleted_hashes,
    log_debug,
)
from core import db
import json

def run_analysis():
    config = load_config()
    deleted_hashes = load_deleted_hashes()
    tail_lines = config.get("log_tail_lines", 200)
    audit_lines = read_audit_log(tail_lines=tail_lines)
    log_debug(f"{len(audit_lines)} audit lines to analyze.")

    if not audit_lines:
        log_debug("No new audit lines found.")
        return

    detected_events = run_detectors(config, audit_lines)
    log_debug(f"{len(detected_events)} event(s) detected.")

    conn = db.init_db(config["output"]["db"])
    log_debug("Connected to database.")

    for event in detected_events:
        event_hash = generate_event_hash(event)
        event["event_hash"] = event_hash

        if event_hash in deleted_hashes:
            log_debug(f"Skipped deleted event: {event.get('event_type')} ({event_hash})")
            continue

        db.insert_event(conn, event)

        if not jsonl_contains_hash(config["output"]["jsonl"], event_hash):
            try:
                with open(config["output"]["jsonl"], "a") as f:
                    f.write(json.dumps(event) + "\n")
                log_debug(f"Added event to JSONL: {event.get('event_type')}")
            except Exception as e:
                log_debug(f"Failed to write event to JSONL: {e}")
        else:
            log_debug(f"Duplicate event skipped in JSONL: {event.get('event_type')}")
