import json
from datetime import datetime, timezone
from pathlib import Path

event = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "source_ip": "192.168.1.10",
    "username": "test_user",
    "result": "success"
}

log_path = Path(__file__).parent / "auth.log"

with log_path.open("a", encoding="utf-8") as log_file:
    log_file.write(json.dumps(event) + "\n")

print("Authentication event saved to:", log_path)