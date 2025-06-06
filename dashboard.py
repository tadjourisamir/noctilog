from core.analyzer import run_analysis
from core.hash_utils import generate_event_hash
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
from textual.containers import Container
from textual.timer import Timer
import json
import datetime
import yaml
from pathlib import Path

def log_debug(message):
    with open("output/debug_log.txt", "a") as f:
        timestamp = datetime.datetime.now().isoformat()
        f.write(f"[{timestamp}] {message}\n")

class NoctilogDashboard(App):
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f", "filter", "Toggle Filter"),
        ("s", "sort", "Sort Events"),
        ("v", "view_event", "Mark as Viewed"),
        ("e", "export", "Export Selected"),
        ("a", "toggle_ack", "Toggle Acknowledge"),
        ("x", "delete_event", "Delete Acknowledged")
    ]
    REFRESH_INTERVAL = 10
    FILTER_OPTIONS = [None, "FAILED_LOGIN", "SUDO_FAIL", "ACCESS_DENIED"]
    SORT_OPTIONS = ["none", "timestamp_asc", "timestamp_desc", "severity", "new_first", "ack_first"]
    VIEWED_IDS_FILE = Path("output/viewed_ids.json")

    def __init__(self):
        super().__init__()
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
        self.current_filter_index = 0
        self.current_sort_index = 0
        self.events = []
        self.viewed_ids = set()
        self.load_viewed_ids()

    def load_viewed_ids(self):
        if self.VIEWED_IDS_FILE.exists():
            try:
                with open(self.VIEWED_IDS_FILE, "r") as f:
                    self.viewed_ids = set(json.load(f))
            except Exception:
                self.viewed_ids = set()

    def save_viewed_ids(self):
        try:
            with open(self.VIEWED_IDS_FILE, "w") as f:
                json.dump(list(self.viewed_ids), f)
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static("🦉 Noctilog - SIEM Dashboard", id="status"),
            DataTable(id="events_table"),
            id="main"
        )
        yield Footer()

    def on_mount(self):
        self.status: Static = self.query_one("#status")
        self.table: DataTable = self.query_one("#events_table")
        self.table.cursor_type = "row"
        self.table.add_columns("🆕", "Timestamp", "Type", "Severity", "User", "PID", "Message", "Ack")
        self.refresh_data()
        self.refresh_timer: Timer = self.set_interval(self.REFRESH_INTERVAL, self.refresh_data)

    def refresh_data(self):
        run_analysis()
        self.table.clear()
        self.events = []

        severity_emoji = {"low": "🟡", "medium": "🟠", "high": "🔴"}
        severity_rank = {"low": 1, "medium": 2, "high": 3}
        filter_type = self.FILTER_OPTIONS[self.current_filter_index]
        sort_mode = self.SORT_OPTIONS[self.current_sort_index]
        events_path = Path("output/events.jsonl")

        if events_path.exists():
            with open(events_path, "r") as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if filter_type and event.get("event_type") != filter_type:
                            continue
                        self.events.append(event)
                    except json.JSONDecodeError:
                        continue

        for e in self.events:
            e["_is_viewed"] = (e.get("timestamp", "") + e.get("event_type", "")) in self.viewed_ids
            e["_ack"] = e.get("acknowledged", False)
            e["_severity_rank"] = severity_rank.get(e.get("severity", "medium"), 2)

        if sort_mode == "timestamp_asc":
            self.events.sort(key=lambda e: e.get("timestamp", ""))
        elif sort_mode == "timestamp_desc":
            self.events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        elif sort_mode == "severity":
            self.events.sort(key=lambda e: e["_severity_rank"], reverse=True)
        elif sort_mode == "new_first":
            self.events.sort(key=lambda e: e["_is_viewed"])
        elif sort_mode == "ack_first":
            self.events.sort(key=lambda e: not e["_ack"])

        for event in self.events:
            extra = event.get("extra", {})
            sev = event.get("severity", "medium")
            sev_display = f"{severity_emoji.get(sev, '')} {sev}"
            event_id = event.get("timestamp", "") + event.get("event_type", "")
            new_status = "🆕" if not event["_is_viewed"] else ""
            self.table.add_row(
                new_status,
                event.get("timestamp", ""),
                event.get("event_type", ""),
                sev_display,
                extra.get("user", "—"),
                str(extra.get("pid", "—")),
                event.get("message", "")[:80] + "..." if len(event.get("message", "")) > 80 else event.get("message", ""),
                "Yes" if event["_ack"] else "No"
            )

        filter_label = self.FILTER_OPTIONS[self.current_filter_index] or "All"
        sort_label = self.SORT_OPTIONS[self.current_sort_index]
        self.status.update(f"🟢 Noctilog - {len(self.events)} events (Filter: {filter_label}, Sort: {sort_label})")

    def action_view_event(self):
        if not self.events or self.table.cursor_row is None:
            return
        idx = self.table.cursor_row
        event = self.events[idx]
        event_id = event.get("timestamp", "") + event.get("event_type", "")
        self.viewed_ids.add(event_id)
        self.save_viewed_ids()
        self.refresh_data()

    def action_toggle_ack(self):
        if not self.events or self.table.cursor_row is None:
            return
        idx = self.table.cursor_row
        event = self.events[idx]
        event["acknowledged"] = not event.get("acknowledged", False)
        event_id = event.get("timestamp", "") + event.get("event_type", "")
        self.viewed_ids.add(event_id)
        self.save_viewed_ids()
        with open("output/events.jsonl", "w") as f:
            for e in self.events:
                f.write(json.dumps(e) + "\n")
        self.refresh_data()

    def action_delete_event(self):
        if not self.events or self.table.cursor_row is None:
            return
        idx = self.table.cursor_row
        event = self.events[idx]
        if event.get("acknowledged"):
            self.archive_event(event)
            event_hash = event.get("event_hash")
            if not event_hash:
                event_hash = generate_event_hash(event)
            save_deleted_hash(event_hash)
            del self.events[idx]
            with open("output/events.jsonl", "w") as f:
                for e in self.events:
                    f.write(json.dumps(e) + "\n")
            self.refresh_data()

    def action_filter(self):
        self.current_filter_index = (self.current_filter_index + 1) % len(self.FILTER_OPTIONS)
        self.refresh_data()

    def action_sort(self):
        self.current_sort_index = (self.current_sort_index + 1) % len(self.SORT_OPTIONS)
        self.refresh_data()

    def action_export(self):
        if not self.events or self.table.cursor_row is None:
            return
        event = self.events[self.table.cursor_row]
        export_dir = Path("output/exports")
        export_dir.mkdir(parents=True, exist_ok=True)
        ts = event.get("timestamp", "").replace(":", "-").replace("T", "_")
        etype = event.get("event_type", "UNKNOWN")
        filename = export_dir / f"event_{ts}_{etype}.txt"
        with open(filename, "w") as f:
            f.write(f"Timestamp : {event.get('timestamp', '')}\n")
            f.write(f"Type      : {event.get('event_type', '')}\n")
            f.write(f"Severity  : {event.get('severity', '')}\n")
            f.write(f"Message   : {event.get('message', '')}\n")
            f.write(f"Extra     : {json.dumps(event.get('extra', {}), indent=2)}\n")
            f.write(f"Acknowledged : {'Yes' if event.get('acknowledged', False) else 'No'}\n")
        self.status.update(f"📁 Exported to {filename}")

    def archive_event(self, event):
        archive_path = Path("output/archived_events.jsonl")
        with open(archive_path, "a") as f:
            f.write(json.dumps(event) + "\n")

def save_deleted_hash(event_hash):
    path = Path("output/deleted_hashes.json")
    if not path.exists():
        path.write_text("[]")
    try:
        hashes = set(json.loads(path.read_text()))
    except:
        hashes = set()
    hashes.add(event_hash)
    path.write_text(json.dumps(list(hashes)))

if __name__ == "__main__":
    from core.analyzer import run_analysis
    NoctilogDashboard().run()
