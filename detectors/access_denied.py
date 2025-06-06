import re
from models.event import create_event

def detect(lines, source="auth.log"):
    events = []
    # Matches common "Permission denied" or "Access denied" messages
    pattern = re.compile(r"(Permission denied|access denied)", re.IGNORECASE)

    for line in lines:
        if pattern.search(line):
            pid = extract_pid(line)

            events.append(create_event(
                event_type="ACCESS_DENIED",
                message=line.strip(),
                source=source,
                severity="high",
                extra={
                    "pid": pid
                }
            ))
    return events

def extract_pid(line):
    match = re.search(r'\[(\d+)\]', line)
    return match.group(1) if match else None
