# Mini-SOC: Web Application Threat Detection Lab

## Overview
A hands-on security lab for detecting and investigating suspicious activity in a web application. The project covers application logging, centralized monitoring, detection rules, and incident investigation.

## Run with Docker Desktop

### Monitoring dashboard

After `docker compose up --build -d`, open http://127.0.0.1:8000/dashboard
(or your configured `LAB_PORT`). The login page also links to the dashboard.

The Hebrew dashboard refreshes every two seconds and shows:

- Totals for successful logins, failed logins, blocked submissions, and saved alerts.
- The latest 200 events and alerts in reverse file order.
- Event search by username/IP, result filtering, and alert-rule filtering.
- Last successful update time, empty states, and a visible error if refreshing fails.

Totals cover all valid records in the configured files; filters apply only to
the displayed recent rows. Times are shown in the browser's local timezone.
Blocked totals describe historical blocked requests, not currently blocked IPs.
The dashboard reads files and does not generate alerts: keep the detector running.
The green data status means the web API is reachable, not that the detector is healthy.
Malformed records are skipped with a warning count; incomplete final lines wait
until the next refresh. The dashboard reads full files on every refresh and is
intended for small lab logs. Log values are rendered as text, not executable HTML.

Compose reads both files from `docker-logs`. For direct Python mode, explicitly
select the same alerts file as the detector:

```powershell
python lab_server.py --log lab_auth.log --alerts lab_alerts.log
```

Without `--alerts`, the server uses `alerts.log` beside the selected event log.
The local dashboard/API has no authentication, matching this loopback-only lab;
do not expose the lab as a public service.

Docker Compose starts two containers: `server` for the login application and
`detector` for continuous monitoring. Docker Desktop must show **Engine running**.
Use Linux containers. No local Python installation is required for these services.

1. Stop the old Python server and watcher with Ctrl+C in their terminals. This
   frees port 8000 and avoids confusion between the old and container logs.
2. In a terminal in the project directory, run:

```powershell
docker compose up --build -d
```

3. Open http://127.0.0.1:8000. Credentials remain `lab_user` / `lab-password`.
4. Show monitoring output in the **watch** terminal:

```powershell
docker compose logs -f detector
```

5. In the **simulation** terminal, run the simulator inside the server container:

```powershell
docker compose exec server python simulate_logins.py
```

It targets loopback inside that same container. The existing optional scenarios
also work, for example:

```powershell
docker compose exec server python simulate_logins.py --scenario multiple-usernames
```

Wait for the rate-limit window to expire between scenarios. Defaults are five
failures/60 seconds, five usernames, and success after three failures. Docker
settings are independent of flags previously used in your Python terminals.

Logs appear in the host project directory automatically:

- `docker-logs/lab_auth.log`: login events, including blocks.
- `docker-logs/lab_alerts.log`: saved alerts and duplicate-prevention history.

Both containers share this host folder through a bind mount. The folder is
excluded from Git and the image build. Your existing root-level `lab_auth.log`
and `lab_alerts.log` are separate and are not imported or modified. Keep the
Docker alerts file to preserve duplicate prevention. Run one detector per folder.

Useful commands:

```powershell
docker compose ps
docker compose logs --tail 30 server detector
docker compose down
docker compose up -d
```

`down` stops and removes the containers; it leaves `docker-logs` on your computer.
`up -d` recreates them using the existing image and logs. Rate-limit memory resets
when the server restarts. Ctrl+C during `logs -f` only stops viewing output; the
containers remain running. After code changes, run `docker compose up --build -d`.

To change settings, set environment variables in PowerShell before `up`:

```powershell
$env:FAILURE_LIMIT = "4"
$env:RATE_WINDOW_SECONDS = "30"
$env:DETECTION_THRESHOLD = "4"
$env:DETECTION_WINDOW_SECONDS = "30"
docker compose up -d
```

Optional variables: `USERNAME_THRESHOLD` (5), `SUCCESS_THRESHOLD` (3), and
`LAB_PORT` (8000). To use port 8001, set `$env:LAB_PORT = "8001"`, rerun `up -d`,
and browse http://127.0.0.1:8001. In-container simulation still uses port 8000.

Only `127.0.0.1` on the host publishes the web port, following the
[Docker port publishing documentation](https://docs.docker.com/engine/network/port-publishing/).
The server binds to `0.0.0.0` inside its container so Docker can forward traffic;
direct Python mode still defaults to `127.0.0.1`. Docker networking may report
browser requests with a gateway IP rather than `127.0.0.1`; in-container simulation
uses `127.0.0.1`. These may therefore have separate rate-limit counters. The server
does not trust forwarded-IP headers. This remains a local learning application.

If `docker` is not recognized, open a new terminal (or restart VS Code). If needed
for the per-user Docker installation, set this for the current terminal:

```powershell
$env:PATH = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;$env:PATH"
```

If port 8000 is occupied, stop the old Python server or select another `LAB_PORT`.

## Run the local HTTP lab

Requires Python 3.10 or later. No packages or Docker installation are needed for this milestone.

In a terminal in the project directory, start the login application:

```powershell
python lab_server.py --log lab_auth.log
```

Open http://127.0.0.1:8000 in your browser. The demo credentials are
`lab_user` / `lab-password`. Each submitted login records its UTC timestamp,
source IP, username, and result. Passwords are never written to the log.
The application checks credentials but does not create a session or protected routes.

In a second terminal, generate one successful login and five failed logins:

```powershell
python simulate_logins.py
python detect_failed_logins.py --log lab_auth.log --alerts lab_alerts.log
```

Expected result: one alert for `127.0.0.1` on a fresh log. Browser login attempts
and repeated simulations also count toward the threshold. The detector replays
the complete file but skips alerts already recorded in the selected alerts file.
These commands keep the original `auth.log` and `alerts.log` unchanged.
Stop the server with Ctrl+C. To repeat with fresh data, use new log filenames
in both the server and detector commands.

In direct Python mode, the server binds only to loopback, and the simulator targets only loopback.
This is a local practice environment, not a container sandbox or production
authentication service. All local clients share the source IP `127.0.0.1`;
forwarded-IP headers are ignored. Docker mode is described below.

Run the automated HTTP-to-detection integration check:

```powershell
python -m unittest -v
```

The check uses temporary log files and an automatically assigned local port.

## Login rate limiting

The values described below are defaults; see Flexible settings to change them.

The server now enforces a rolling limit of five failed logins per source IP
within 60 seconds. The first five failures return HTTP 401. Once the limit is
reached, subsequent valid login submissions return HTTP 429 Too Many Requests,
including submissions with the correct password. The `Retry-After` response
header gives the number of seconds until the oldest failure expires.
Blocked requests do not extend the waiting period. Successful logins do not
clear earlier failures. As failures expire, new attempts become available.

Blocked submissions are logged with `result: "blocked"`; the existing detector
counts only `failure` events, so blocks do not inflate its failure count.
Requests rejected as malformed return 400 and are outside this login limit.

To try it:

1. Stop the old server with Ctrl+C and restart it with
   `python lab_server.py --log lab_auth.log` so the updated code is loaded.
2. Run `python simulate_logins.py` once against a fresh server. It still produces
   one 200 response and five 401 responses.
3. Submit another login through the browser, even with the correct credentials.
   Expect HTTP 429 and `{"result": "blocked"}` while the five failures remain
   in the window. Browser developer tools show the status and `Retry-After` header.
4. Wait until those failures expire (60 seconds after the last failure is enough)
   and try the correct credentials again. Expect HTTP 200.

The simulator expects the original 200/401 sequence and will report an error
if rerun while the IP is limited. This is expected; wait for the window to expire.
Automated tests verify blocking, the retry header, recovery at the window
boundary, event logging, and compatibility with the detector without a real wait.

This limits repeated login failures regardless of whether they are generated
manually or using AI; it does not identify AI. State is held in memory and resets
when the server restarts. It is local to this server process. All local clients
share the same IP and limit; distributed attempts from different IPs are not
covered by an account-wide rule. This is a lab control, not complete protection
against automated attacks.

## Duplicate alert prevention

Each new alert includes a deterministic `alert_id` based on its rule, IP,
failure count, window length, and first/last event timestamps. Before writing,
the detector checks existing alerts in the file selected by `--alerts`.
Older alerts without an ID are recognized from those same fields.

Run the detector twice on unchanged input:

```powershell
python detect_failed_logins.py --log lab_auth.log --alerts lab_alerts.log
python detect_failed_logins.py --log lab_auth.log --alerts lab_alerts.log
```

The second run prints `No new alerts. Matching activity has already been recorded.`
if matching activity exists, and leaves the alerts file unchanged. A later,
separate five-failure window can still produce a new alert. If no window matches,
the output remains `No suspicious login activity detected.`

Keep the alerts file to preserve this history. Deleting it or selecting a new
alerts file allows historical alerts to be generated again. Existing duplicate
rows are not removed. Run one detector at a time: simultaneous processes writing
to the same file are not synchronized. Input and existing alert records must
contain valid JSON and the expected fields.

## Flexible settings

All new settings accept positive integers. Invalid, zero, or negative values
are rejected before monitoring or serving starts. Omitting them preserves the
original defaults.

| Program | Option | Default | Effect |
| --- | --- | --- | --- |
| Detector | `--threshold` | 5 | Failed logins per IP needed for the original alert |
| Detector | `--username-threshold` | 5 | Distinct usernames with failed logins per IP |
| Detector | `--success-threshold` | 3 | Failures for the same IP/account before a success alerts |
| Detector | `--window-seconds` | 60 | Event-time window for all three detection rules |
| Server | `--failure-limit` | 5 | Failed logins per IP allowed before further attempts are blocked |
| Server | `--window-seconds` | 60 | Rolling failure window used by rate limiting |

In the **watch** terminal, stop the detector with Ctrl+C and restart it, for example:

```powershell
python detect_failed_logins.py --log lab_auth.log --alerts lab_alerts.log --watch --threshold 4 --window-seconds 30 --username-threshold 4 --success-threshold 2
```

This alerts at four IP failures, four distinct failed usernames, or a success
after two account-specific failures, within a 30-second window.

To change blocking too, stop and restart the **lab server** terminal separately:

```powershell
python lab_server.py --log lab_auth.log --failure-limit 4 --window-seconds 30
```

The first four failures are allowed to return 401; later valid login submissions
are blocked until enough failures expire from the 30-second rolling window.
This is not a fixed 30-second lockout starting at the blocked request.
Restarting the server clears its in-memory rate-limit history.

The detector and server are configured independently. If the server blocks before
the detector's threshold can be reached, that detection rule may not trigger.
The simulator still uses fixed scenarios and expects their original HTTP codes;
lower server limits may make it report unexpected 429 responses.
Use browser attempts for custom limits, or keep defaults for the documented demos.

The detector reanalyzes existing history with the new settings. A changed window
can produce new alerts for historical events. Duplicate prevention still uses
the rule, event window and affected account(s); changing a setting alone does not
force a duplicate for an otherwise identical alert. Alert records and messages
show the actual failure count and configured window. `--interval` controls only
how often watch mode polls, not the detection or blocking window.

## Continuous detection

Use three terminals in the project directory:

1. Start the application (or keep your existing server running):
   `python lab_server.py --log lab_auth.log`
2. Start the detector and leave it running:
   `python detect_failed_logins.py --log lab_auth.log --alerts lab_alerts.log --watch`
3. Generate activity: `python simulate_logins.py`.

The detector checks the log once per second and prints new alerts automatically.
Stop it with Ctrl+C. Set a different polling interval with `--interval 0.5`.
Without `--watch`, the command still performs one scan and exits.
If the server has not created the log yet, watch mode waits for it. It also waits
for a newline before processing the final record, so a partially written event
is retried on the next scan. Complete malformed records still cause an error.

At startup, existing events are analyzed too; previously saved alerts are skipped.
The watcher currently rereads and sorts the entire log on each poll, preserving
the existing event-time detection behavior even for out-of-order records. This
is suitable for small lab logs; incremental reading is a future optimization.
It is polling rather than an instantaneous notification system. Keep a single
detector writing to each alerts file. If the simulator is blocked by the server's
rate limit, wait for the failures to expire before rerunning it.

## Planned Components
- A web application with authentication and protected routes (the first milestone uses a Python login demo).
- Structured logs capturing authentication events and HTTP requests.
- A SIEM platform for log collection, analysis, and alerting.
- Python scripts for generating controlled test activity.

## Initial Detection Scenario
Detect five or more failed login attempts from the same source IP address within a rolling 60-second window.

This pattern may indicate a brute-force login attempt.

## Understanding the demo results

### Additional detection rules

| Rule | Trigger | Meaning |
| --- | --- | --- |
| `multiple_usernames` | Failed logins against at least five distinct usernames from one IP within 60 seconds | May indicate attempts across multiple accounts; repeated failures for one username do not satisfy this rule |
| `success_after_failures` | A successful login after at least three failures for the same username and IP in the preceding 60 seconds | May indicate a guessed password, or a legitimate user correcting mistakes |

The time boundary is inclusive. Blocked submissions do not count as failures or
successes. A success clears the preceding failure sequence for that IP/username
pair for `success_after_failures`; it does not reset the original IP failure rule.
New alerts include the affected `username` or sorted `usernames` list. Both rules
work in one-shot and watch modes and use duplicate prevention. Two different
rules may legitimately alert on the same events.

To demonstrate, restart the detector in the **monitoring** terminal (Ctrl+C, then):

```powershell
python detect_failed_logins.py --log lab_auth.log --alerts lab_alerts.log --watch
```

Keep the **server** terminal running. In the **simulation** terminal, choose:

```powershell
python simulate_logins.py --scenario multiple-usernames
```

This sends five failed logins with different usernames and can trigger both
`failed_login_threshold` and `multiple_usernames`.
Wait at least 60 seconds after the last failure before trying the other scenario,
so earlier failures and the server rate limit do not interfere:

```powershell
python simulate_logins.py --scenario success-after-failures
```

This sends three failures followed by a successful login for `lab_user`, triggering
`success_after_failures`. The default scenario remains unchanged. Existing log
history may also produce new-rule alerts when the updated detector starts.

### Original threshold scenario

On a fresh log, `simulate_logins.py` produces the following sequence:

| Request | HTTP response | Authentication result | Detection outcome |
| --- | --- | --- | --- |
| 1 | 200 OK | Successful login | Not counted as a failure |
| 2 | 401 Unauthorized | Failed login | 1 failure; below threshold |
| 3 | 401 Unauthorized | Failed login | 2 failures; below threshold |
| 4 | 401 Unauthorized | Failed login | 3 failures; below threshold |
| 5 | 401 Unauthorized | Failed login | 4 failures; below threshold |
| 6 | 401 Unauthorized | Failed login | 5 failures; threshold reached if all five are within 60 seconds |

The server writes each valid login attempt as a JSON Lines event containing
`timestamp`, `source_ip`, `username`, and `result`. HTTP responses describe
individual requests; the detector uses the logged authentication results to
identify a pattern across requests. A successful login does not reset the
failure count in the current implementation.

Run the detector separately to print the alert and append its JSON record to
`lab_alerts.log`. Use `--watch` for automatic repeated detection while the server runs. The IP
`127.0.0.1` is the local computer, and timestamps use UTC (`+00:00`).
Repeated failures can indicate password guessing, but an alert alone does not
prove an attack. Review the event times, usernames, and surrounding activity.

## Validation
- Successful logins should not trigger the failed-login alert.
- Five failed logins from the same IP within 60 seconds should trigger an alert.
- Failed logins outside the time window should not count toward the threshold.

## Project Status
Local HTTP login application connected to the existing file-based detector.

## Implemented Features
- Local browser login form and HTTP endpoint, with real authentication-event logging.
- Fixed local HTTP simulation and automated end-to-end verification.
- Generate simulated authentication events in JSON Lines format.
- Read authentication logs and analyze events chronologically.
- Detect five failed logins from the same IP within 60 seconds.
- Print alerts to the terminal.
- Skip already recorded alerts across sequential runs, including older records without IDs.
- Monitor the log continuously with --watch and a configurable polling interval.
- Detect failures across five distinct usernames and a success after three account-specific failures within 60 seconds.
- Limit repeated failed logins per IP, return HTTP 429 with Retry-After, and log blocked attempts.

## Manual Validation
- Failed-login sequence within 60 seconds: alert generated.
- Successful logins: ignored by the detection rule.
- Failed logins spaced 30 seconds apart: no alert.
- Three failures per IP across two IPs: no alert.
- Two additional failures for one IP: alert generated for that IP.

## Current Limitations
The detector analyzes the entire log file on each run.
Duplicate prevention depends on retaining the selected alerts file and using one detector process at a time.
Malformed JSON or missing event fields can stop the detector.
Settings are supplied at startup; changing them requires restarting the relevant process.
The server uses fixed demo credentials and has no sessions or protected routes.
Only authentication events are logged; this is not a complete HTTP access log.
Centralized log collection is not included yet. The monitoring dashboard reads local files.

## Improvement Roadmap

These are proposed next steps, not implemented features. The order prioritizes
reliable detection before adding more infrastructure.

| Priority | Improvement | Completion check |
| --- | --- | --- |
| 2 | Validate event fields and handle malformed lines with a clear diagnostic | A bad line is reported with its line number while valid events are still analyzed |
| 6 | Send structured events and alerts to a central monitoring system | Events can be searched by time, IP, username, and result, and a demo alert is visible |

Extend automated checks as each improvement is implemented. Useful cases include
the exact 60-second boundary, failures outside the window, independent IPs,
successful logins between failures, malformed events, and repeated detector runs.
Use synthetic logs for multiple-IP scenarios because the current local HTTP lab
records all clients as `127.0.0.1`.
