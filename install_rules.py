import shutil
import subprocess
import os

RULES_SRC = "config/auditd.rules"
RULES_DST = "/etc/audit/rules.d/noctilog.rules"

def install_persistent_rules():
    if not os.path.exists(RULES_SRC):
        print(f"[!] Rules file not found: {RULES_SRC}")
        return

    try:
        shutil.copy(RULES_SRC, RULES_DST)
        subprocess.run(["augenrules", "--load"], check=True)
        subprocess.run(["systemctl", "restart", "auditd"], check=True)
        print("[+] Persistent audit rules installed and auditd restarted.")
    except Exception as e:
        print(f"[!] Failed to install persistent rules: {e}")
