import re
from models.event import create_event

def detect(lines, source="auth.log"):
    events = []

    pattern = re.compile(r"user (\w+) is not in the sudoers", re.IGNORECASE)

    for line in lines:
        match = pattern.search(line)
        if match:
            user = match.group(1)
            pid = extract_pid(line)

            events.append(create_event(
                event_type="SUDO_FAIL",
                message=line.strip(),
                source=source,
                severity="high",
                extra={
                    "user": user,
                    "pid": pid
                }
            ))
    return events

def extract_pid(line):
    match = re.search(r'\[(\d+)\]', line)
    return match.group(1) if match else None
