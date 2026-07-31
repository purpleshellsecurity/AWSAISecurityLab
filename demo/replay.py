#!/usr/bin/env python3
"""
Replay an incident scenario against the deployed chat API to populate your logs with realistic
activity (normal usage + the attack). Each scenario entry becomes one POST /chat; the correlated
api_access/chat/retrieval records land in CloudWatch, and the detector fires on the malicious ones.

Usage:
    ./demo/replay.py                          # replays demo/scenarios/99_incident_full.json
    ./demo/replay.py --scenario my.json       # your own scenario
    ./demo/replay.py --delay 1.0              # pace between requests (seconds)
    ./demo/replay.py --url URL --key KEY       # override the API endpoint/key

URL and key default to `terraform output`. Build your own scenarios by copying a file in
demo/scenarios/ and editing the `requests` list (any of: user, service_account, x_source_ip, session_id, prompt,
simulate_tokens).
"""
# --- Imports: standard library only, so the demo runs with no pip install -------------------------
import argparse         # command-line flags (--scenario, --delay, --url, ...)
import json             # read scenario files and parse API responses
import os               # path handling + reading API_URL/API_KEY from the environment
import subprocess       # shell out to `terraform output` to discover the endpoint/key
import sys             # exit codes and error messages
import time            # inter-request delay pacing
import urllib.error     # catch HTTP errors from urllib
import urllib.request   # POST to the API (no third-party HTTP dependency)

# --- Paths (resolved relative to this file, so it works from any working directory) --------------
HERE = os.path.dirname(os.path.abspath(__file__))
TF_DIR = os.path.join(HERE, "..", "terraform")          # where `terraform output` is read from
SCENARIO_DIR = os.path.join(HERE, "scenarios")          # bundled scenario JSON files live here
DEFAULT_SCENARIO = os.path.join(SCENARIO_DIR, "99_incident_full.json")  # the full end-to-end attack
# Only these keys are forwarded from a scenario entry into the request body; anything else in the
# entry (e.g. "phase") is metadata for the replay tool, not the API.
PASSTHROUGH = ("user", "service_account", "x_source_ip", "session_id", "prompt", "simulate_tokens")


def list_scenarios():
    """Print the available bundled scenarios with their name/description and request count."""
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
            # A malformed/unreadable scenario shouldn't abort the whole listing.
            print(f"  {fn:<32} (could not parse)")


def tf_output(name):
    """Read a single Terraform output value (the API URL / key) from the terraform/ directory.
    Exits with an actionable message if terraform isn't installed or the lab isn't deployed yet."""
    try:
        out = subprocess.run(
            ["terraform", f"-chdir={TF_DIR}", "output", "-raw", name],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        sys.exit("ERROR: terraform is not installed. See README prerequisites, or run: ./scripts/preflight.sh")
    if out.returncode != 0 or not out.stdout.strip():
        # Empty/failed output almost always means `terraform apply` hasn't been run.
        sys.exit(
            "ERROR: couldn't read the lab's API details from Terraform.\n"
            "The lab is probably not deployed yet. Deploy it first:\n"
            "    terraform -chdir=terraform apply\n"
            "Then run this again. (Check prerequisites with: ./scripts/preflight.sh)"
        )
    return out.stdout.strip()


def post(url, key, body):
    """POST one JSON request to the chat API and return (http_status, parsed_json_response).
    HTTP error responses (e.g. the 403 network block) are caught so the caller still sees the body."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"content-type": "application/json", "x-api-key": key},  # API Gateway key auth
    )
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        # A 4xx/5xx (e.g. the checkpoint-1 403) is expected output, not a crash — return its body.
        return e.code, json.loads(e.read() or b"{}")


def main():
    # --- Parse CLI flags -----------------------------------------------------------------------
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default=DEFAULT_SCENARIO, help="path to a scenario JSON (default: the full incident)")
    ap.add_argument("--list", action="store_true", help="list available scenarios and exit")
    ap.add_argument("--delay", type=float, default=0.5)              # seconds to wait between requests
    ap.add_argument("--url", default=os.environ.get("API_URL"))      # override endpoint (else terraform output)
    ap.add_argument("--key", default=os.environ.get("API_KEY"))      # override api key (else terraform output)
    ap.add_argument("--limit", type=int, default=0)                  # cap number of requests (0 = all)
    args = ap.parse_args()

    if args.list:
        list_scenarios()
        return 0

    # Resolve endpoint/key: prefer explicit flags/env, otherwise pull them from Terraform outputs.
    url = args.url or tf_output("api_invoke_url")
    key = args.key or tf_output("api_key_value")

    # --- Load the scenario and optionally trim it ----------------------------------------------
    with open(args.scenario) as f:
        scenario = json.load(f)
    requests = scenario["requests"]
    if args.limit:
        requests = requests[: args.limit]

    print(f"Replaying {len(requests)} requests against {url}\n")
    # Running tallies for the end-of-run summary.
    fired = blocked_net = blocked_doc = guardrail = 0
    for i, entry in enumerate(requests, 1):
        # Build the request body from only the passthrough keys present in this entry.
        body = {k: entry[k] for k in PASSTHROUGH if k in entry}
        status, resp = post(url, key, body)
        fired += 1
        phase = entry.get("phase", "")          # human-readable label for this step (attack phase)
        rid = resp.get("request_id", "?")       # correlation id to look the request up in the logs
        # Checkpoint-1 network block returns 403 before any retrieval — record and move on.
        if status == 403:
            blocked_net += 1
            print(f"[{i:>2}] {phase:<22} {body.get('user',''):<10} -> 403 network-blocked   rid={rid}")
            continue
        # Otherwise inspect what the controls did: guardrail intervention + docs blocked/returned.
        ga = resp.get("guardrail_action", "none")
        rb = [d["document_name"] for d in resp.get("documents_blocked", [])]
        rr = [d["document_name"] for d in resp.get("documents_returned", [])]
        if ga == "intervened":
            guardrail += 1
        if rb:
            blocked_doc += 1
        # Assemble the per-request status flags shown on the console line.
        flags = []
        if ga == "intervened":
            flags.append("GUARDRAIL")
        if rb:
            flags.append(f"BLOCKED@RETRIEVAL={rb}")
        if rr:
            flags.append(f"returned={rr}")
        print(f"[{i:>2}] {phase:<22} {body.get('user',''):<10} -> {status} {' '.join(flags)}  rid={rid}")
        time.sleep(args.delay)  # pace requests so the log timeline reads naturally

    # --- Summary + next steps ------------------------------------------------------------------
    print(
        f"\nDone. {fired} requests | {blocked_net} network-blocked | "
        f"{blocked_doc} blocked-at-retrieval | {guardrail} guardrail-intervened."
    )
    print("Give the log subscription ~30-60s, then: ./demo/show_detections.sh   (or ./demo/trace.sh <body>)")


if __name__ == "__main__":
    sys.exit(main())
