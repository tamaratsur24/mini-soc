"""Send a fixed login scenario to the local lab; never targets external hosts."""

import argparse
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener


def run_scenario(port=8000, scenario="threshold"):
    opener = build_opener(ProxyHandler({}))
    if scenario == "multiple-usernames":
        attempts = [(f"user_{i}", "wrong-password", 401) for i in range(5)]
    elif scenario == "success-after-failures":
        attempts = [("lab_user", "wrong-password", 401)] * 3 + [("lab_user", "lab-password", 200)]
    else:
        attempts = [("lab_user", "lab-password", 200)] + [("lab_user", "wrong-password", 401)] * 5
    for index, (username, password, expected) in enumerate(attempts, 1):
        data = urlencode({"username": username, "password": password}).encode()
        try:
            with opener.open(f"http://127.0.0.1:{port}/login", data, timeout=5) as response:
                status = response.status
        except HTTPError as error:
            status = error.code
            error.close()
        if status != expected:
            raise RuntimeError(f"Request {index}: expected {expected}, got {status}")
        print(f"Request {index}: HTTP {status}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--scenario", choices=("threshold", "multiple-usernames", "success-after-failures"),
                        default="threshold")
    args = parser.parse_args()
    run_scenario(args.port, args.scenario)
