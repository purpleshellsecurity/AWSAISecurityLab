#!/usr/bin/env python3
"""
Replay an incident scenario against the deployed chat API to populate your logs with realistic
activity (normal usage + the attack). Each scenario entry becomes one POST /chat; the correlated
api_access/chat/retrieval records land in CloudWatch, and the detector fires on the malicious ones.

Usage:
    ./demo/replay.py                          # replays demo/incident_scenario.json
    ./demo/replay.py --scenario my.json       # your own scenario
    ./demo/replay.py --delay 1.0              # pace between requests (seconds)
    ./demo/replay.py --url URL --key KEY       # override the API endpoint/key

URL and key default to `terraform output`. Build your own scenarios by copying incident_scenario.json
and editing the `requests` list (any of: user, service_account, x_source_ip, session_id, prompt,
simulate_tokens).
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TF_DIR = os.path.join(HERE, "..", "terraform")
SCENARIO_DIR = os.path.join(HERE, "scenarios")
DEFAULT_SCENARIO = os.path.join(SCENARIO_DIR, "99_incident_full.json")
PASSTHROUGH = ("user", "service_account", "x_source_ip", "session_id", "prompt", "simulate_tokens")


def list_scenarios():
    print("Available scenarios (demo/scenarios/):\n")
    for fn in sorted(os.listdir(SCENARIO_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(SCENARIO_DIR, fn)) as f:
                meta = json.load(f)
            n = len(meta.get("requests", []))
            print(f"  {fn:<32} {meta.get('name','')}  ({n} requests)")
            print(f"  {'':<32} {meta.get('description','')}\n")
        except (json.JSONDecodeError, OSError):
            print(f"  {fn:<32} (could not parse)")


def tf_output(name):
    try:
        out = subprocess.run(
            ["terraform", f"-chdir={TF_DIR}", "output", "-raw", name],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        sys.exit("ERROR: terraform is not installed. See README prerequisites, or run: ./scripts/preflight.sh")
    if out.returncode != 0 or not out.stdout.strip():
        sys.exit(
            "ERROR: couldn't read the lab's API details from Terraform.\n"
            "The lab is probably not deployed yet. Deploy it first:\n"
            "    terraform -chdir=terraform apply\n"
            "Then run this again. (Check prerequisites with: ./scripts/preflight.sh)"
        )
    return out.stdout.strip()


def post(url, key, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"content-type": "application/json", "x-api-key": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default=DEFAULT_SCENARIO, help="path to a scenario JSON (default: the full incident)")
    ap.add_argument("--list", action="store_true", help="list available scenarios and exit")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--url", default=os.environ.get("API_URL"))
    ap.add_argument("--key", default=os.environ.get("API_KEY"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if args.list:
        list_scenarios()
        return 0

    url = args.url or tf_output("api_invoke_url")
    key = args.key or tf_output("api_key_value")

    with open(args.scenario) as f:
        scenario = json.load(f)
    requests = scenario["requests"]
    if args.limit:
        requests = requests[: args.limit]

    print(f"Replaying {len(requests)} requests against {url}\n")
    fired = blocked_net = blocked_doc = guardrail = 0
    for i, entry in enumerate(requests, 1):
        body = {k: entry[k] for k in PASSTHROUGH if k in entry}
        status, resp = post(url, key, body)
        fired += 1
        phase = entry.get("phase", "")
        rid = resp.get("request_id", "?")
        if status == 403:
            blocked_net += 1
            print(f"[{i:>2}] {phase:<22} {body.get('user',''):<10} -> 403 network-blocked   rid={rid}")
            continue
        ga = resp.get("guardrail_action", "none")
        rb = [d["document_name"] for d in resp.get("documents_blocked", [])]
        rr = [d["document_name"] for d in resp.get("documents_returned", [])]
        if ga == "intervened":
            guardrail += 1
        if rb:
            blocked_doc += 1
        flags = []
        if ga == "intervened":
            flags.append("GUARDRAIL")
        if rb:
            flags.append(f"BLOCKED@RETRIEVAL={rb}")
        if rr:
            flags.append(f"returned={rr}")
        print(f"[{i:>2}] {phase:<22} {body.get('user',''):<10} -> {status} {' '.join(flags)}  rid={rid}")
        time.sleep(args.delay)

    print(
        f"\nDone. {fired} requests | {blocked_net} network-blocked | "
        f"{blocked_doc} blocked-at-retrieval | {guardrail} guardrail-intervened."
    )
    print("Give the log subscription ~30-60s, then: ./demo/show_detections.sh   (or ./demo/trace.sh <body>)")


if __name__ == "__main__":
    sys.exit(main())
