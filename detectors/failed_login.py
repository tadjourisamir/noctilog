import re
from models.event import create_event

def detect(lines, source="auth.log"):
    events = []
    # Matches: sshd[1234]: Failed password for (invalid user) <user> from <ip> port <port>
    pattern = re.compile(
        r"sshd\[(\d+)\]: Failed password for (invalid user )?(\w+) from ([\d.]+) port (\d+)",
        re.IGNORECASE
    )

    for line in lines:
        match = pattern.search(line)
        if match:
            pid = match.group(1)
            user = match.group(3)
            ip = match.group(4)
            port = match.group(5)

            events.append(create_event(
                event_type="FAILED_LOGIN",
                message=f"Failed login for user '{user}' from {ip}:{port}",
                source=source,
                severity="medium",
                extra={
                    "user": user,
                    "ip": ip,
                    "port": port,
                    "pid": pid
                }
            ))
    return events
