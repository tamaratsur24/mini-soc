"""Local authentication-event lab. Run with: python lab_server.py."""

import argparse
import hmac
import json
import math
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Mini-SOC Login Lab</title>
<style>body{font:18px system-ui;background:#101827;color:#e5edf6;max-width:480px;margin:10vh auto;padding:24px}input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0 20px}button{background:#67e8b5;border:0;font-weight:bold}small{color:#b8c7da}</style>
<a href="/dashboard" style="color:#67e8b5">Open monitoring dashboard</a><h1>Mini-SOC Login Lab</h1><p>Generate real HTTP authentication events for investigation.</p>
<form action="/login" method="post"><label for="username">Username</label>
<input id="username" name="username" required maxlength="128" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password">
<button>Test login</button></form>
<small>Local lab credentials: lab_user / lab-password<br>This demo records login results; it does not create sessions.</small></html>"""


def make_server(port=8000, log_path=Path(__file__).with_name("auth.log"),
                failure_limit=5, window_seconds=60, clock=time.monotonic, host="127.0.0.1",
                alerts_path=None):
    if failure_limit <= 0 or window_seconds <= 0:
        raise ValueError("Rate limit and window must be positive")
    failures_by_ip = {}
    alerts_path = Path(alerts_path) if alerts_path is not None else Path(log_path).with_name("alerts.log")

    def monitoring_data():
        counts = {"success": 0, "failure": 0, "blocked": 0, "alerts": 0}
        invalid_records = 0

        def records(path, fields, is_alert=False):
            nonlocal invalid_records
            recent = deque(maxlen=200)
            try:
                with Path(path).open(encoding="utf-8") as source:
                    for line in source:
                        if not line.endswith("\n"):
                            break  # Writer may still be appending this record.
                        if not line.strip():
                            continue
                        try:
                            row = json.loads(line)
                            if not isinstance(row, dict):
                                raise ValueError()
                            required = ("rule", "last_event_time") if is_alert else ("timestamp", "result")
                            if any(not isinstance(row.get(key), str) for key in required):
                                raise ValueError()
                            if not is_alert and row["result"] not in ("success", "failure", "blocked"):
                                raise ValueError()
                        except (ValueError, TypeError):
                            invalid_records += 1
                            continue
                        counts["alerts" if is_alert else row["result"]] += 1
                        recent.append({key: row[key] for key in fields if key in row})
            except FileNotFoundError:
                pass
            return list(reversed(recent))

        events = records(log_path, ("timestamp", "source_ip", "username", "result"))
        alerts = records(alerts_path, ("rule", "source_ip", "username", "usernames",
                                     "failed_login_count", "window_seconds", "first_event_time",
                                     "last_event_time", "alert_id"), is_alert=True)
        return {"counts": counts, "events": events, "alerts": alerts,
                "invalid_records": invalid_records, "limit": 200,
                "updated_at": datetime.now(timezone.utc).isoformat()}

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, body, content_type="text/html; charset=utf-8", retry_after=None):
            body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if retry_after is not None:
                self.send_header("Retry-After", str(retry_after))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/dashboard":
                self.respond(200, Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8"))
                return
            if self.path == "/api/monitor":
                try:
                    data = monitoring_data()
                except OSError:
                    self.respond(503, json.dumps({"error": "Monitoring data is temporarily unavailable"}),
                                 "application/json")
                    return
                self.respond(200, json.dumps(data), "application/json")
                return
            if self.path != "/":
                self.respond(404, "Not found")
                return
            self.respond(200, PAGE)

        def do_POST(self):
            if self.path != "/login":
                self.respond(404, "Not found")
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError()
                if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                    raise ValueError()
                fields = parse_qs(self.rfile.read(size).decode("utf-8"), max_num_fields=8)
                username = fields["username"][0]
                password = fields["password"][0]
                if len(username) > 128:
                    raise ValueError()
            except (ValueError, KeyError, UnicodeError):
                self.respond(400, "Invalid login request")
                return
            now = clock()
            for ip in list(failures_by_ip):
                failures = failures_by_ip[ip]
                while failures and now - failures[0] >= window_seconds:
                    failures.popleft()
                if not failures:
                    del failures_by_ip[ip]
            ip = self.client_address[0]
            failures = failures_by_ip.get(ip, deque())
            blocked = len(failures) >= failure_limit
            success = not blocked and username == "lab_user" and hmac.compare_digest(
                password.encode("utf-8"), b"lab-password"
            )
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": self.client_address[0],
                "username": username,
                "result": "blocked" if blocked else "success" if success else "failure",
            }
            if not blocked and not success:
                failures.append(now)
                failures_by_ip[ip] = failures
            with Path(log_path).open("a", encoding="utf-8") as output:
                output.write(json.dumps(event) + "\n")
            retry_after = max(1, math.ceil(window_seconds - (now - failures[0]))) if blocked else None
            self.respond(429 if blocked else 200 if success else 401,
                         json.dumps({"result": event["result"]}), "application/json",
                         retry_after=retry_after)

        def log_message(self, format, *args):
            pass  # Authentication events are recorded without passwords or request bodies.

    return HTTPServer((host, port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1",
                        help="Bind address; use 0.0.0.0 inside Docker only.")
    parser.add_argument("--log", type=Path, default=Path(__file__).with_name("auth.log"))
    parser.add_argument("--alerts", type=Path, help="Alerts file for the monitoring dashboard.")
    parser.add_argument("--failure-limit", type=int, default=5, help="Failures per IP before limiting (default: 5).")
    parser.add_argument("--window-seconds", type=int, default=60, help="Rolling failure window (default: 60).")
    args = parser.parse_args()
    if args.failure_limit <= 0 or args.window_seconds <= 0:
        parser.error("--failure-limit and --window-seconds must be positive integers")
    with make_server(args.port, args.log, args.failure_limit, args.window_seconds,
                     host=args.host, alerts_path=args.alerts) as server:
        print(f"Login lab: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
