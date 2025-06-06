import hashlib
import json

def generate_event_hash(event):
    h = hashlib.sha256()
    timestamp = event.get("timestamp", "")[:16]
    content = f"{timestamp}|{event.get('event_type')}|{event.get('message')}|{json.dumps(event.get('extra', {}), sort_keys=True)}"
    h.update(content.encode("utf-8"))
    return h.hexdigest()
