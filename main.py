import os
import sys
import yaml
import json
import hashlib
import datetime
from core import db
from detectors import auditd_sudo_fail, auditd_failed_login

DELETED_HASHES_PATH = "output/deleted_hashes.json"
AUDIT_LOG_PATH = "/var/log/audit/audit.log"

if os.geteuid() != 0:
    print("❌ This script must be run as root. Use: sudo python3 main.py")
    sys.exit(1)

def log_debug(message):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.datetime.now().isoformat()
    full_msg = f"[{timestamp}] [Noctilog] {message}"
    with open("output/debug_log.txt", "a") as f:
        f.write(full_msg + "\n")
    print(full_msg)

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def ensure_rules_installed():
    rules_path = "/etc/audit/rules.d/noctilog.rules"
    if not os.path.exists(rules_path):
        log_debug("Persistent rules not found. Installing...")
        try:
            from install_rules import install_persistent_rules
            install_persistent_rules()
        except Exception as e:
            log_debug(f"Failed to install persistent rules: {e}")
    else:
        log_debug("Persistent audit rules already present.")

def load_auditd_rules():
    try:
        os.system("auditctl -D")
        result = os.system("auditctl -R config/auditd.rules")
        if result == 0:
            log_debug("Auditd rules loaded successfully.")
        else:
            log_debug("Failed to load auditd rules.")
    except Exception as e:
        log_debug(f"Exception while loading auditd rules: {e}")

def load_deleted_hashes():
    if not os.path.exists(DELETED_HASHES_PATH):
        return set()
    try:
        with open(DELETED_HASHES_PATH, "r") as f:
            return set(json.load(f))
    except Exception as e:
        log_debug(f"Failed to load deleted hashes: {e}")
        return set()

def read_audit_log(tail_lines=200):
    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            return f.readlines()[-tail_lines:]
    except Exception as e:
        log_debug(f"Error reading audit log: {e}")
        return []

def run_detectors(config, audit_lines):
    events = []
    if config["modules"].get("auditd_failed_login"):
        events += auditd_failed_login.detect(audit_lines)
    if config["modules"].get("auditd_sudo_fail"):
        events += auditd_sudo_fail.detect(audit_lines)
    return events

def generate_event_hash(event):
    h = hashlib.sha256()
    timestamp = event.get("timestamp", "")
    content = f"{timestamp}|{event.get('event_type')}|{event.get('message')}|{json.dumps(event.get('extra', {}), sort_keys=True)}"
    h.update(content.encode("utf-8"))
    return h.hexdigest()

def jsonl_contains_hash(jsonl_path, event_hash):
    if not os.path.exists(jsonl_path):
        return False
    with open(jsonl_path, "r") as f:
        for line in f:
            try:
                if json.loads(line).get("event_hash") == event_hash:
                    return True
            except:
                continue
    return False

def main():
    config = load_config()
    ensure_rules_installed()
    load_auditd_rules()
    log_debug("Configuration loaded.")

    deleted_hashes = load_deleted_hashes()
    tail_lines = config.get("log_tail_lines", 200)
    audit_lines = read_audit_log(tail_lines)
    log_debug(f"{len(audit_lines)} audit lines to analyze.")

    if not audit_lines:
        log_debug("No new audit lines found.")
        return

    try:
        with open("output/logs_snapshot.txt", "w") as f:
            f.write("".join(audit_lines))
        log_debug("Audit log snapshot saved.")
    except Exception as e:
        log_debug(f"Failed to save snapshot: {e}")

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

if __name__ == "__main__":
    main()
