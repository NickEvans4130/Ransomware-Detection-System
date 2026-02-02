"""Standalone CLI script to trigger a demo simulation via the dashboard API.

Usage:
    python -m src.demo.simulate                    # start demo, poll until complete
    python -m src.demo.simulate --speed 2.0        # run at 2x speed
    python -m src.demo.simulate --stop             # stop a running demo
    python -m src.demo.simulate --base-url http://host:port
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _post(url, data=None):
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read()), exc.code


def _get(url):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read()), exc.code


def main():
    parser = argparse.ArgumentParser(description="Trigger a demo simulation")
    parser.add_argument(
        "--base-url", default="http://127.0.0.1:5000",
        help="Base URL of the dashboard (default: http://127.0.0.1:5000)",
    )
    parser.add_argument(
        "--speed", type=float, default=1.0,
        help="Speed multiplier for the simulation (default: 1.0)",
    )
    parser.add_argument(
        "--stop", action="store_true",
        help="Stop a running demo instead of starting one",
    )
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    if args.stop:
        data, status = _post(base + "/api/demo/stop")
        if status == 200:
            print("Demo stopped.")
        else:
            print("Error:", data.get("error", "unknown"))
        return

    # Start the demo
    data, status = _post(base + "/api/demo/start", {"speed": args.speed})
    if status != 200:
        print("Failed to start demo:", data.get("error", "unknown"))
        sys.exit(1)

    print(f"Demo started (speed={args.speed}x). Polling status...")

    # Poll until complete
    while True:
        time.sleep(2)
        try:
            data, _ = _get(base + "/api/demo/status")
        except Exception as exc:
            print(f"  Error polling status: {exc}")
            continue

        phase = data.get("phase", "?")
        progress = data.get("progress", 0)
        running = data.get("running", False)
        print(f"  [{phase}] {progress}%")

        if not running or phase in ("complete", "stopped"):
            break

    print("Demo finished.")


if __name__ == "__main__":
    main()
