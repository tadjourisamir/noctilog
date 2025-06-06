import sys
import os

if os.geteuid() != 0:
    print("❌ This script must be run as root. Use: sudo python3 run.py")
    sys.exit(1)

from main import main
from dashboard import NoctilogDashboard

main()
NoctilogDashboard().run()
