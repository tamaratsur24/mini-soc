import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener

from lab_server import make_server
from detect_failed_logins import detection_alerts, scan
from simulate_logins import run_scenario


class LabIntegrationTest(unittest.TestCase):
    def test_monitoring_api_live_data_and_bounded_history(self):
        with tempfile.TemporaryDirectory() as directory:
            log, alerts = Path(directory) / "auth.log", Path(directory) / "lab_alerts.log"
            server = make_server(0, log, alerts_path=alerts)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = build_opener(ProxyHandler({}))

            def get(path):
                with opener.open(f"http://127.0.0.1:{server.server_port}{path}", timeout=5) as response:
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    return response.read().decode()

            try:
                self.assertIn('lang="he"', get("/dashboard"))
                empty = json.loads(get("/api/monitor"))
                self.assertEqual(empty["events"], [])
                self.assertEqual(empty["counts"], {"success": 0, "failure": 0, "blocked": 0, "alerts": 0})
                rows = [{"timestamp": "2026-01-01T00:00:00+00:00", "username": f"user_{i}",
                         "source_ip": "127.0.0.1", "result": "failure", "password": "must-not-leak"}
                        for i in range(205)]
                rows.extend([dict(rows[0], result="success"), dict(rows[0], result="blocked")])
                log.write_text("".join(json.dumps(row) + "\n" for row in rows) +
                               'bad-json\n[]\n{"timestamp":', encoding="utf-8")
                alerts.write_text(json.dumps({"rule": "failed_login_threshold", "last_event_time": "2026-01-01T00:00:00+00:00",
                                              "failed_login_count": 5, "window_seconds": 60}) + "\n", encoding="utf-8")
                raw = get("/api/monitor")
                data = json.loads(raw)
                self.assertNotIn("must-not-leak", raw)
                self.assertEqual(data["counts"], {"success": 1, "failure": 205, "blocked": 1, "alerts": 1})
                self.assertEqual(len(data["events"]), 200)
                self.assertEqual(data["events"][0]["result"], "blocked")
                self.assertEqual(data["invalid_records"], 2)
                self.assertEqual(len(data["alerts"]), 1)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()

    def test_configurable_detection_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            log, alerts = Path(directory) / "auth.log", Path(directory) / "alerts.log"
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            events = [{"timestamp": (start + timedelta(seconds=second)).isoformat(),
                       "username": username, "result": result, "source_ip": "127.0.0.1"}
                      for second, username, result in (
                          (0, "alice", "failure"), (10, "bob", "failure"),
                          (11, "bob", "success"))]
            log.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
            command = [sys.executable, str(Path(__file__).with_name("detect_failed_logins.py")),
                       "--log", str(log), "--alerts", str(alerts), "--threshold", "2",
                       "--username-threshold", "2", "--success-threshold", "1", "--window-seconds", "10"]
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertIn("2 failed logins", result.stdout)
            self.assertIn("within 10 seconds", result.stdout)
            records = [json.loads(line) for line in alerts.read_text().splitlines()]
            self.assertEqual([a["rule"] for a in records],
                             ["failed_login_threshold", "multiple_usernames", "success_after_failures"])
            self.assertTrue(all(a["window_seconds"] == 10 for a in records))
            original = alerts.read_bytes()
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(alerts.read_bytes(), original)
            # A narrower window excludes the first failure from both IP rules.
            narrow = subprocess.run(command[:-1] + ["9"], check=True, capture_output=True, text=True)
            self.assertNotIn("2 failed logins", narrow.stdout)

    def test_invalid_cli_settings(self):
        for script, flags in (
            ("detect_failed_logins.py", ("--threshold", "--username-threshold", "--success-threshold", "--window-seconds")),
            ("lab_server.py", ("--failure-limit", "--window-seconds")),
        ):
            for flag in flags:
                for value in ("0", "-1", "1.5", "nan"):
                    with self.subTest(script=script, flag=flag, value=value):
                        result = subprocess.run([sys.executable, str(Path(__file__).with_name(script)), flag, value],
                                                capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 2)

    def test_new_http_scenarios(self):
        for scenario, expected in (
            ("multiple-usernames", ["failed_login_threshold", "multiple_usernames"]),
            ("success-after-failures", ["success_after_failures"]),
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                log, alerts = Path(directory) / "auth.log", Path(directory) / "alerts.log"
                server = make_server(0, log)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    run_scenario(server.server_port, scenario)
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                scan(log, alerts, watch=True)
                self.assertEqual([json.loads(line)["rule"] for line in alerts.read_text().splitlines()], expected)

    def test_additional_detection_rules(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def event(second, username="alice", result="failure", ip="127.0.0.1"):
            return {"timestamp": start + timedelta(seconds=second), "username": username,
                    "result": result, "source_ip": ip}

        def rules(events):
            return [a["rule"] for a in detection_alerts(events)]

        multiple = [event(i, username=f"user_{i}") for i in range(5)]
        self.assertIn("multiple_usernames", rules(multiple))
        self.assertNotIn("multiple_usernames", rules([event(i) for i in range(5)]))
        self.assertNotIn("multiple_usernames", rules(multiple[:4] + [event(61, "user_4")]))
        self.assertNotIn("multiple_usernames", rules(multiple[:4] + [event(4, "user_4", ip="127.0.0.2")]))
        failures = [event(i) for i in range(3)]
        success = failures + [event(60, result="success")]
        self.assertEqual(rules(success), ["success_after_failures"])
        for ending in (event(61, result="success"), event(3, "bob", "success"),
                       event(3, result="success", ip="127.0.0.2"), event(3, result="blocked")):
            self.assertNotIn("success_after_failures", rules(failures + [ending]))
        self.assertNotIn("success_after_failures", rules(failures[:2] + [event(3, result="success")]))
        self.assertEqual(rules(success + [event(61, result="success")]), ["success_after_failures"])
        with tempfile.TemporaryDirectory() as directory:
            log, alerts = Path(directory) / "auth.log", Path(directory) / "alerts.log"
            combined = multiple + [event(120 + i) for i in range(3)] + [event(123, result="success")]
            log.write_text("".join(json.dumps({**e, "timestamp": e["timestamp"].isoformat()}) + "\n"
                                   for e in combined), encoding="utf-8")
            scan(log, alerts, watch=True)
            original = alerts.read_bytes()
            scan(log, alerts, watch=True)
            self.assertEqual(alerts.read_bytes(), original)
            self.assertEqual(len(original.splitlines()), 3)

    def test_watch_detects_appended_events_and_waits_for_complete_line(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "auth.log"
            alerts = Path(directory) / "alerts.log"
            command = [sys.executable, str(Path(__file__).with_name("detect_failed_logins.py")),
                       "--log", str(log), "--alerts", str(alerts), "--watch", "--interval", "0.05"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertIn("Watching", process.stdout.readline())
                time.sleep(0.1)  # The watcher must tolerate a log that does not exist yet.
                start = datetime(2026, 1, 1, tzinfo=timezone.utc)
                events = [{"timestamp": (start + timedelta(seconds=i)).isoformat(),
                           "source_ip": "127.0.0.1", "username": "lab_user", "result": "failure"}
                          for i in range(5)]
                log.write_text("".join(json.dumps(e) + "\n" for e in events[:4]) +
                               json.dumps(events[4])[:20], encoding="utf-8")
                time.sleep(0.2)
                self.assertIsNone(process.poll())
                self.assertFalse(alerts.exists())
                with log.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(events[4])[20:] + "\n")
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if alerts.exists() and alerts.read_text().endswith("\n"):
                        break
                    time.sleep(0.05)
                self.assertTrue(alerts.exists())
                original = alerts.read_bytes()
                self.assertEqual(len(original.splitlines()), 1)
                time.sleep(0.2)
                self.assertEqual(alerts.read_bytes(), original)
                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                process.communicate(timeout=5)

    def test_alert_deduplication_with_new_events_and_legacy_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "auth.log"
            alerts = Path(directory) / "alerts.log"
            command = [sys.executable, str(Path(__file__).with_name("detect_failed_logins.py")),
                       "--log", str(log), "--alerts", str(alerts)]
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)

            def add_failures(offset):
                with log.open("a", encoding="utf-8") as output:
                    for index in range(5):
                        output.write(json.dumps({
                            "timestamp": (start + timedelta(seconds=offset + index)).isoformat(),
                            "source_ip": "127.0.0.1", "username": "lab_user", "result": "failure",
                        }) + "\n")

            def run():
                return subprocess.run(command, check=True, capture_output=True, text=True).stdout

            add_failures(0)
            self.assertIn("ALERT:", run())
            original = alerts.read_bytes()
            self.assertIn("No new alerts", run())
            self.assertEqual(alerts.read_bytes(), original)
            first = json.loads(original)
            self.assertEqual(len(first["alert_id"]), 64)

            # An existing alert from before IDs were introduced must also deduplicate.
            del first["alert_id"]
            alerts.write_text(json.dumps(first) + "\n", encoding="utf-8")
            legacy = alerts.read_bytes()
            self.assertIn("No new alerts", run())
            self.assertEqual(alerts.read_bytes(), legacy)

            # A later burst from the same IP is a distinct alert.
            add_failures(120)
            self.assertIn("ALERT:", run())
            records = [json.loads(line) for line in alerts.read_text().splitlines()]
            self.assertEqual(len(records), 2)
            self.assertNotEqual(records[0]["last_event_time"], records[1]["last_event_time"])
            final = alerts.read_bytes()
            self.assertIn("No new alerts", run())
            self.assertEqual(alerts.read_bytes(), final)

    def test_rate_limit_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "auth.log"
            now = [100.0]
            server = make_server(0, log, clock=lambda: now[0])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = build_opener(ProxyHandler({}))

            def login(password):
                data = urlencode({"username": "lab_user", "password": password}).encode()
                try:
                    response = opener.open(f"http://127.0.0.1:{server.server_port}/login", data, timeout=5)
                except HTTPError as error:
                    response = error
                with response:
                    return response.code, response.headers, json.loads(response.read())

            try:
                for _ in range(5):
                    self.assertEqual(login("wrong")[0], 401)
                status, headers, body = login("lab-password")
                self.assertEqual(status, 429)
                self.assertEqual(headers["Retry-After"], "60")
                self.assertEqual(body["result"], "blocked")
                now[0] = 159.0
                self.assertEqual(login("wrong")[1]["Retry-After"], "1")
                now[0] = 160.0
                self.assertEqual(login("lab-password")[0], 200)
                self.assertEqual(login("wrong")[0], 401)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
            events = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([event["result"] for event in events],
                             ["failure"] * 5 + ["blocked", "blocked", "success", "failure"])
            self.assertNotIn("password", log.read_text())
            alerts = Path(directory) / "alerts.log"
            subprocess.run([sys.executable, str(Path(__file__).with_name("detect_failed_logins.py")),
                            "--log", str(log), "--alerts", str(alerts)], check=True, capture_output=True)
            detected = [json.loads(line) for line in alerts.read_text().splitlines()]
            self.assertEqual([a["rule"] for a in detected],
                             ["failed_login_threshold", "success_after_failures"])

    def test_http_events_reach_detector(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "auth.log"
            alerts = Path(directory) / "alerts.log"
            server = make_server(0, log)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                run_scenario(server.server_port)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
            events = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([e["result"] for e in events], ["success"] + ["failure"] * 5)
            self.assertTrue(all(e["source_ip"] == "127.0.0.1" for e in events))
            self.assertNotIn("password", log.read_text())
            subprocess.run([sys.executable, str(Path(__file__).with_name("detect_failed_logins.py")),
                            "--log", str(log), "--alerts", str(alerts)], check=True, capture_output=True)
            detected = [json.loads(line) for line in alerts.read_text().splitlines()]
            self.assertEqual(len(detected), 1)
            self.assertEqual(detected[0]["failed_login_count"], 5)


if __name__ == "__main__":
    unittest.main()
