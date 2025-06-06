import os

SOUND_FILES = {
    "low": "sounds/low.wav",
    "medium": "sounds/medium.wav",
    "high": "sounds/high.wav"
}

def notify(event):
    severity = event.get("severity", "medium")
    path = SOUND_FILES.get(severity)
    if path and os.path.exists(path):
        try:
            os.system(f"aplay -q {path} &")
        except Exception as e:
            print(f"[Sound Error] {e}")
    else:
        print(f"[Sound] No sound file found for {severity}")
