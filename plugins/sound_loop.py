
import os
import json
import time
import threading

SOUND_FILES = {
    "low": "sounds/low.wav",
    "medium": "sounds/medium.wav",
    "high": "sounds/high.wav"
}

sound_enabled = False
sound_thread = None
stop_event = threading.Event()
thread_lock = threading.Lock()

def get_highest_severity(events):
    priority = {"low": 1, "medium": 2, "high": 3}
    highest = None
    for e in events:
        if not e.get("acknowledged", False):
            sev = e.get("severity", "low")
            if not highest or priority[sev] > priority[highest]:
                highest = sev
    return highest

def load_events():
    try:
        with open("output/events.jsonl", "r") as f:
            return [json.loads(line) for line in f if line.strip()]
    except Exception:
        return []

def sound_loop():
    while not stop_event.is_set():
        if sound_enabled:
            events = load_events()
            highest = get_highest_severity(events)
            if highest:
                path = SOUND_FILES.get(highest)
                if path and os.path.exists(path):
                    os.system(f"aplay -q {path} &")
        time.sleep(1.0)
    print("[Sound Loop] Stopped.")

def start_sound_loop():
    global sound_thread
    with thread_lock:
        if sound_thread is None or not sound_thread.is_alive():
            stop_event.clear()
            sound_thread = threading.Thread(target=sound_loop, daemon=True)
            sound_thread.start()

def set_sound_enabled(state: bool):
    global sound_enabled
    sound_enabled = state
    if not state:
        print("[Sound Loop] Disabled.")

def stop_sound_loop():
    stop_event.set()
