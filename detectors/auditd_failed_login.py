import re
import pwd
from datetime import datetime
from models.event import create_event

def uid_to_user(uid):
    try:
        if int(uid) == 4294967295:
            return "unknown"
        return pwd.getpwuid(int(uid)).pw_name
    except Exception:
        return f"UID:{uid}"

def extract_field(line, key):
    match = re.search(rf"{key}=([^\s]+)", line)
    return match.group(1).strip('"') if match else "N/A"

def detect(lines, source="audit.log"):
    events = []

    for line in lines:
        if "USER_LOGIN" not in line or "res=failed" not in line:
            continue

        # Timestamp
        ts_match = re.search(r"audit\((\d+\.\d+):\d+\)", line)
        try:
            ts_float = float(ts_match.group(1)) if ts_match else None
            timestamp = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else datetime.utcnow().isoformat()
        except Exception:
            timestamp = datetime.utcnow().isoformat()

        uid = extract_field(line, "uid")
        auid = extract_field(line, "auid")
        pid = extract_field(line, "pid")
        exe = extract_field(line, "exe")

        events.append(create_event(
            event_type="FAILED_LOGIN",
            message=f"Auditd login failed - exe={exe}",
            source=source,
            severity="medium",
            timestamp=timestamp,
            extra={
                "uid": uid,
                "auid": auid,
                "user": uid_to_user(auid),
                "pid": pid
            }
        ))

    return events
