import json
import re
from datetime import datetime
from collections import defaultdict

def read_logs(filepath, tail_lines=200):
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
            return lines[-tail_lines:]
    except Exception as e:
        print(f"[Log Reader Error] {e}")
        return []

def append_jsonl(event, filepath):
    try:
        with open(filepath, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print(f"[Append JSONL Error] {e}")

def read_logs_indexed(filepaths, tail_lines=200):
    logs_by_pid_ts = defaultdict(list)

    pid_pattern = re.compile(r'pid=(\d+)')
    ts_pattern = re.compile(r'audit\((\d+\.\d+):\d+\)')

    for path in filepaths:
        lines = read_logs(path, tail_lines)
        for line in lines:
            ts_match = ts_pattern.search(line)
            pid_match = pid_pattern.search(line)

            if ts_match and pid_match:
                try:
                    ts_float = float(ts_match.group(1))
                    dt = datetime.fromtimestamp(ts_float)
                    ts_min = dt.replace(second=0, microsecond=0).isoformat(timespec="minutes")
                    pid = pid_match.group(1)
                    key = f"{pid}|{ts_min}"
                    logs_by_pid_ts[key].append(line)
                except Exception:
                    continue

    return logs_by_pid_ts
