import argparse
import json
import hashlib
import math
import time
from datetime import datetime, timedelta
from pathlib import Path

def alert_id(alert):
    """Identify the same rule, IP, and triggering window across repeated runs."""
    identity = {key: alert[key] for key in (
        "rule", "source_ip", "failed_login_count", "window_seconds",
        "first_event_time", "last_event_time",
    )}
    for key in ("username", "usernames"):
        if key in alert:
            identity[key] = alert[key]
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def detection_alerts(events, threshold=5, window_seconds=60, username_threshold=5, success_threshold=3):
    failures_by_ip = {}
    failures_by_account = {}
    for event in events:
        result = event["result"]
        if result not in ("failure", "success"):
            continue
        ip = event["source_ip"]
        current_time = event["timestamp"]
        username = event["username"]
        recent = [e for e in failures_by_ip.get(ip, [])
                  if current_time - e["timestamp"] <= timedelta(seconds=window_seconds)]
        failures_by_ip[ip] = recent
        account = (ip, username)
        account_failures = [e for e in failures_by_account.get(account, [])
                            if current_time - e["timestamp"] <= timedelta(seconds=window_seconds)]
        failures_by_account[account] = account_failures

        def make_alert(rule, failures):
            return {"rule": rule, "source_ip": ip,
                    "failed_login_count": len(failures), "window_seconds": window_seconds,
                    "first_event_time": failures[0]["timestamp"].isoformat(),
                    "last_event_time": current_time.isoformat()}

        if result == "success":
            if len(account_failures) >= success_threshold:
                alert = make_alert("success_after_failures", account_failures)
                alert["username"] = username
                yield alert
            # A success ends the failure sequence for this IP/account pair.
            failures_by_account[account] = []
            continue

        previous_users = {e["username"] for e in recent}
        recent.append(event)
        account_failures.append(event)
        if len(recent) == threshold:
            yield make_alert("failed_login_threshold", recent)
        users = {e["username"] for e in recent}
        if len(previous_users) < username_threshold <= len(users):
            alert = make_alert("multiple_usernames", recent)
            alert["usernames"] = sorted(users)
            yield alert


def scan(log_path, alerts_path, watch=False, **settings):
    # Derive IDs from the original fields so older alerts without an ID also count.
    known_alerts = set()
    if alerts_path.exists():
        with alerts_path.open("r", encoding="utf-8") as alerts_file:
            for line in alerts_file:
                if line.strip():
                    known_alerts.add(alert_id(json.loads(line)))

    events = []

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if watch and not line.endswith("\n"):
                break  # Retry an unfinished final record on the next poll.
            if line.strip():
                event = json.loads(line)
                event["timestamp"] = datetime.fromisoformat(event["timestamp"])
                events.append(event)

    events.sort(key=lambda event: event["timestamp"])

    alert_found = False
    new_alert_found = False
    for alert in detection_alerts(events, **settings):
        alert_found = True
        alert["alert_id"] = alert_id(alert)
        if alert["alert_id"] in known_alerts:
            continue

        with alerts_path.open("a", encoding="utf-8") as alerts_file:
            alerts_file.write(json.dumps(alert) + "\n")
        known_alerts.add(alert["alert_id"])

        if alert["rule"] == "failed_login_threshold":
            message = f"{alert['failed_login_count']} failed logins from {alert['source_ip']} within {alert['window_seconds']} seconds"
        elif alert["rule"] == "multiple_usernames":
            message = f"Failed logins against {len(alert['usernames'])} usernames from {alert['source_ip']} within {alert['window_seconds']} seconds"
        else:
            message = (f"Successful login for {alert['username']} from {alert['source_ip']} "
                       f"after {alert['failed_login_count']} failures within {alert['window_seconds']} seconds")
        print(f"ALERT: {message} at {alert['last_event_time']}", flush=True)

        new_alert_found = True

    if not alert_found and not watch:
        print("No suspicious login activity detected.")
    elif not new_alert_found and not watch:
        print("No new alerts. Matching activity has already been recorded.")


def main():
    parser = argparse.ArgumentParser(description="Detect suspicious login patterns with configurable thresholds.")
    parser.add_argument("--log", type=Path, default=Path(__file__).parent / "auth.log")
    parser.add_argument("--alerts", type=Path, default=Path(__file__).parent / "alerts.log")
    parser.add_argument("--watch", action="store_true", help="Keep monitoring the log until Ctrl+C.")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds (default: 1).")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logins per IP (default: 5).")
    parser.add_argument("--username-threshold", type=int, default=5, help="Distinct failed usernames per IP (default: 5).")
    parser.add_argument("--success-threshold", type=int, default=3, help="Failures before success per IP/account (default: 3).")
    parser.add_argument("--window-seconds", type=int, default=60, help="Window for all detection rules (default: 60).")
    args = parser.parse_args()
    settings = {name: getattr(args, name) for name in
                ("threshold", "username_threshold", "success_threshold", "window_seconds")}
    if any(value <= 0 for value in settings.values()):
        parser.error("Detection thresholds and --window-seconds must be positive integers")
    if not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("--interval must be a finite positive number")
    if not args.watch:
        scan(args.log, args.alerts, **settings)
        return
    print(f"Watching {args.log} every {args.interval:g}s. Stop with Ctrl+C.", flush=True)
    try:
        while True:
            try:
                scan(args.log, args.alerts, watch=True, **settings)
            except FileNotFoundError:
                if args.log.exists():
                    raise
                # The server may not have created its log yet.
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Monitoring stopped.", flush=True)


if __name__ == "__main__":
    main()
