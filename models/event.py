from datetime import datetime

def create_event(event_type, message, source, severity="medium", extra=None, timestamp=None):
    """
    Creates a dictionary representing a security event.

    If `timestamp` is not provided, the current UTC datetime will be used.
    For accurate tracking, provide the original timestamp extracted from the log source.
    """
    return {
        "timestamp": timestamp or datetime.utcnow().isoformat(),
        "event_type": event_type,
        "message": message,
        "source": source,
        "severity": severity,
        "extra": extra or {},
        "acknowledged": False
    }
