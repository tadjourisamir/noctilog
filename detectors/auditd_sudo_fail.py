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

def detect(lines, source="audit.log"):
    events = []

    for line in lines:
        if 'type=USER_AUTH' not in line or 'res=failed' not in line:
            continue
        if 'exe="/usr/bin/sudo"' not in line:
            continue

        ts = re.search(r'audit\((\d+\.\d+):\d+\)', line)
        timestamp = datetime.utcfromtimestamp(float(ts.group(1))).isoformat() if ts else datetime.utcnow().isoformat()

        uid = re.search(r'uid=(\d+)', line)
        auid = re.search(r'auid=(\d+)', line)
        pid = re.search(r'pid=(\d+)', line)
        exe = re.search(r'exe="([^"]+)"', line)

        auid_val = auid.group(1) if auid else "N/A"

        events.append(create_event(
            event_type="SUDO_FAIL",
            message=f"Sudo failed authentication: {exe.group(1) if exe else 'N/A'}",
            source=source,
            severity="high",
            timestamp=timestamp,
            extra={
                "uid": uid.group(1) if uid else "N/A",
                "auid": auid_val,
                "user": uid_to_user(auid_val),
                "pid": pid.group(1) if pid else "N/A"
            }
        ))

    return events
