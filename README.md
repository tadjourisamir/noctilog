![29604650-906f-4a3e-88ac-7bfe371a40fb](https://github.com/user-attachments/assets/175b713e-cee9-44eb-b1e3-9fc991198548)

# 🦉 Noctilog - Lightweight SIEM Dashboard for Linux

**Noctilog** is a minimalist and educational SIEM (Security Information and Event Management) tool designed for **Unix-like systems**, specifically tested on **Debian-based distributions** (e.g. Ubuntu, Xubuntu, Kali, etc.).

⚠️ **This project is not production-ready.**  
It's a **personal experiment** developed while learning about Linux systems, auditing, and security monitoring.  

It currently **does not support** other Linux families like Fedora, Arch, or SELinux-based systems.

---


## 🚀 Features

- 🔍 **Log Analysis**:
  - Detects failed login attempts (e.g. SSH)
  - Detects unauthorized `sudo` attempts
  - Detects access denials (disabled in current version)

- 📦 **Event Storage**:
  - Events saved in `.jsonl` and SQLite `.db` format
  - Events include timestamp, user, command, and more

- 🖥️ **Textual Dashboard**:
  - Terminal UI with filtering, sorting, and export
  - View and acknowledge events

- 🧱 Modular Design:
  - Detection modules are easy to extend

---

## ⚠️ Notes

- This project is **work-in-progress**
- Built for **learning purposes**
- Many components (e.g. detection accuracy) are basic and may need refinement
- Sound alerts have been removed in this version
- Only basic log parsing from `/var/log/audit/audit.log` is supported

---

## 📁 Project Structure

```
noctilog/
├── config.yaml              # Configuration file
├── core/                    # Main logic, DB handler, hash, analyzer
├── detectors/               # Detection logic for login/sudo/etc.
├── models/                  # Event creation helpers
├── output/                  # JSONL, DB, debug logs (auto-generated)
├── dashboard.py             # Terminal UI
├── main.py                  # Entry point
├── Makefile                 # Helper commands
└── requirements.txt         # Python dependencies
```

---

## ⚙️ Installation

### Requirements

- Linux system (tested on Ubuntu/Debian)
- Python 3.8+
- `auditd` must be installed and active
- Root access (required for log access and auditd rules)

### Setup (run as root)

```bash
git clone https://github.com/yourusername/noctilog.git
cd noctilog

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## 🛡️ Auditd Rules Setup

Rules are required to track failed logins, sudo attempts, and access control.

1. Run the project once with:
```bash
sudo python3 main.py
```

2. This will:
   - Install persistent auditd rules from `config/auditd.rules` (if missing)
   - Load them via `auditctl`

3. You can manually view or edit:
   - `/etc/audit/rules.d/noctilog.rules`

---

## 🔧 Configuration (`config.yaml`)

```yaml
log_files:
  - /var/log/audit/audit.log

modules:
  auditd_failed_login: true
  auditd_sudo_fail: true
  auditd_sensitive_access: false

output:
  jsonl: output/events.jsonl
  db: output/events.db

log_tail_lines: 200
```

---

## 📊 Usage

| Command              | Description                              |
|----------------------|------------------------------------------|
| `make run`           | Run log processing (main.py)            |
| `make dashboard`     | Launch the terminal UI (Textual)        |
| `make clean`         | Clear output files                      |
| `make install`       | Install Python dependencies             |

---

## 👨‍💻 Author & License

Built by a Linux security learner.  
MIT License. See `LICENSE`.

Feel free to contribute or fork. Just know it’s not fully mature — yet 🙂
