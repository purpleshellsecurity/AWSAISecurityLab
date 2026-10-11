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
    ./demo/replay.py --no-auth                 # skip JWT auth (for a controls-off/baseline deploy)

Authentication:
    In HARDENED mode the API is behind a Cognito JWT authorizer. When the lab exposes a
    `cognito_client_id` Terraform output, this script automatically logs each scenario `user` in
    (Cognito USER_PASSWORD_AUTH) and sends their ID token as the Authorization header, so the
    handler derives identity/clearance from verified claims instead of the body. The demo password
    comes from $DEMO_USER_PASSWORD (default matches terraform's demo_user_password). Entries with no
    Cognito-backed `user` (e.g. the service-account machine path) are sent without a token — in
    hardened mode the authorizer then returns 401, which is the correct front-door behavior to see.
    Use --no-auth against a controls-off deployment (method authorization = NONE).

URL and key default to `terraform output`. Build your own scenarios by copying a file in
demo/scenarios/ and editing the `requests` list (any of: user, service_account, x_source_ip, session_id, prompt,
simulate_tokens).
"""
# --- Imports: standard library only, so the demo runs with no pip install -------------------------
import base64          # decode JWT metadata without logging tokens
import argparse         # command-line flags (--scenario, --delay, --url, ...)
import json             # read scenario files and parse API responses
import os               # path handling + reading API_URL/API_KEY from the environment
import subprocess       # shell out to `terraform output` to discover the endpoint/key
import sys             # exit codes and error messages
import time            # inter-request delay pacing
import urllib.error     # catch HTTP errors from urllib
import urllib.request   # POST to the API (no third-party HTTP dependency)
from detection_check import check as check_detections, DetectionQueryError

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


def tf_output(name, required=True):
    """Read a single Terraform output value from the terraform/ directory. With required=True, exits
    with an actionable message if terraform isn't installed or the lab isn't deployed. With
    required=False, returns None instead of exiting (used for the optional Cognito outputs, which are
    absent on very old deploys)."""
    try:
        out = subprocess.run(
            ["terraform", f"-chdir={TF_DIR}", "output", "-raw", name],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        if not required:
            return None
        sys.exit("ERROR: terraform is not installed. See README prerequisites, or run: ./scripts/preflight.sh")
    if out.returncode != 0 or not out.stdout.strip():
        if not required:
            return None
        # Empty/failed output almost always means `terraform apply` hasn't been run.
        sys.exit(
            "ERROR: couldn't read the lab's API details from Terraform.\n"
            "The lab is probably not deployed yet. Deploy it first:\n"
            "    terraform -chdir=terraform apply\n"
            "Then run this again. (Check prerequisites with: ./scripts/preflight.sh)"
        )
    return out.stdout.strip()


def get_token(client_id, username, password, cache):
    """Exchange a username+password for a Cognito ID token via USER_PASSWORD_AUTH, memoized per user.
    Returns the JWT string, or None if the login fails (missing user, wrong password, aws CLI absent)
    — the caller then sends the request without a token, and the hardened authorizer returns 401."""
    if username in cache:
        return cache[username]
    try:
        out = subprocess.run(
            ["aws", "cognito-idp", "initiate-auth",
             "--auth-flow", "USER_PASSWORD_AUTH",
             "--client-id", client_id,
             "--auth-parameters", f"USERNAME={username},PASSWORD={password}",
             "--query", "AuthenticationResult.IdToken", "--output", "text"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        sys.exit("ERROR: the aws CLI is required to fetch JWTs for hardened mode. Install it, or run with --no-auth.")
    token = out.stdout.strip()
    if out.returncode != 0 or not token or token == "None":
        cache[username] = None
        return None
    cache[username] = token
    return token

def altered_signature(token):
    """Change the actual signature, not the expiry/claims (which are signed)."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise ValueError("Cognito did not return a signed three-part JWT")
    last = parts[2][-1]
    # Change the first signature character to avoid base64url trailing pad ambiguity.
    signature = parts[2]
    parts[2] = ("A" if signature[0] != "A" else "B") + signature[1:]
    return ".".join(parts)


def expired_jwt_from_file(path):
    """Read a real, previously issued expired JWT; never print/store its content."""
    import stat
    import time as clock
    if not path:
        raise ValueError("Expired JWT test requires --expired-jwt-file PATH (real old Cognito ID token)")
    if os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Expired JWT file permissions must be owner-only (chmod 600)")
    with open(path, encoding="utf-8") as f:
        token = f.read().strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Expired JWT file must contain one complete three-part token")
    try:
        encoded = parts[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        expiry = claims["exp"]
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Expired JWT file contains invalid expiry metadata") from exc
    if type(expiry) not in (int, float) or expiry >= clock.time():
        raise ValueError("JWT in file is not expired; acquire an earlier Cognito ID token")
    return token


def auth_test_token(mode, client_id, username, password, cache, expired_file=None):
    """Explicit identity-boundary inputs; refuse to silently substitute missing credentials."""
    if mode == "missing":
        return None
    if mode == "malformed":
        return "malformed.jwt.not-a-signature"
    if mode == "expired":
        return expired_jwt_from_file(expired_file)
    if not client_id or not username:
        raise ValueError("JWT test needs hardened Cognito mode and a named test user")
    token = get_token(client_id, username, password, cache)
    if not token:
        raise ValueError("Cognito login failed; cannot validate JWT signature/positive control")
    if mode == "tampered":
        return altered_signature(token)
    if mode == "valid":
        return token
    raise ValueError("Unknown auth_case (allowed: missing, malformed, tampered, expired, valid)")


def post(url, key, body, token=None):
    """POST one JSON request to the chat API and return (http_status, parsed_json_response).
    HTTP error responses (e.g. the 403 network block, or a 401 from the JWT authorizer) are caught so
    the caller still sees the body. The API key is the throttling handle (always sent); the optional
    JWT is the Authorization credential the Cognito authorizer validates in hardened mode."""
    data = json.dumps(body).encode()
    headers = {"content-type": "application/json", "x-api-key": key}  # API Gateway key auth (throttling)
    if token:
        headers["Authorization"] = token  # Cognito authorizer validates this JWT at the edge
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    def parse_response(raw, headers):
        try:
            parsed = json.loads(raw or b"{}")
        except (ValueError, TypeError):
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        # The JWT authorizer can reject a request before application JSON exists.
        # Preserve headers for correlation; never log credentials or Authorization.
        if headers:
            gateway_id = headers.get("x-amzn-RequestId")
            extended_id = headers.get("x-amz-apigw-id")
            if gateway_id:
                parsed["_api_gateway_request_id"] = gateway_id
            if extended_id:
                parsed["_api_gateway_extended_id"] = extended_id
        return parsed

    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, parse_response(r.read(), r.headers)
    except urllib.error.HTTPError as e:
        return e.code, parse_response(e.read(), e.headers)


def verify_per_request_detections(requests, results, findings):
    """Compare exact finding sets for each request, including negative controls.

    Return (decision, failures). Missing evidence is INCONCLUSIVE, never PASS.
    """
    observed_by_request = {}
    for finding in findings:
        observed_by_request.setdefault(finding.get("request_id"), set()).add(
            finding.get("detection"))
    errors = []
    incomplete = False
    for idx, entry in enumerate(requests):
        if "expected_detections" not in entry:
            errors.append(f"request {idx + 1}: per-request detection contract absent (INCONCLUSIVE)")
            incomplete = True
            continue
        expected = entry["expected_detections"]
        if not isinstance(expected, list) or any(not isinstance(d, str) for d in expected):
            errors.append(f"request {idx + 1}: invalid per-request detection contract")
            incomplete = True
            continue
        request_id = results[idx].get("request_id")
        if not request_id:
            errors.append(f"request {idx + 1}: no application request ID for detection check")
            incomplete = True
            continue
        observed = observed_by_request.get(request_id, set())
        if observed != set(expected):
            errors.append(
                f"request {idx + 1} ({entry.get('phase', '-')}) detector mismatch: "
                f"expected {sorted(set(expected))}, observed {sorted(observed)}")
    if any("detector mismatch" in error for error in errors):
        return "FAIL", errors
    return ("INCONCLUSIVE" if incomplete else "PASS"), errors


def main():
    # --- Parse CLI flags -----------------------------------------------------------------------
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default=DEFAULT_SCENARIO, help="path to a scenario JSON (default: the full incident)")
    ap.add_argument("--list", action="store_true", help="list available scenarios and exit")
    ap.add_argument("--delay", type=float, default=0.5)              # seconds to wait between requests
    ap.add_argument("--url", default=os.environ.get("API_URL"))      # override endpoint (else terraform output)
    ap.add_argument("--key", default=os.environ.get("API_KEY"))      # override api key (else terraform output)
    ap.add_argument("--limit", type=int, default=0)                  # cap number of requests (0 = all)
    ap.add_argument("--no-auth", action="store_true", help="don't fetch/send JWTs (baseline / controls-off deploy)")
    ap.add_argument("--client-id", default=os.environ.get("COGNITO_CLIENT_ID"))  # override Cognito app client id
    ap.add_argument("--assert-expected", action="store_true",
                    help="fail when expected HTTP status is missing or mismatched")
    ap.add_argument("--results-json", help="write outcome evidence without tokens or prompt text")
    ap.add_argument("--no-detection-check", action="store_true", help="skip automatic CloudWatch finding check")
    ap.add_argument("--detection-timeout", type=int, default=60, help="seconds to poll for expected findings (default 60)")
    ap.add_argument("--verbose", action="store_true", help="show document names and request IDs")
    ap.add_argument("--expired-jwt-file", help="owner-only local file with an already-expired genuine Cognito ID token")
    args = ap.parse_args()

    if args.list:
        list_scenarios()
        return 0

    # Resolve endpoint/key: prefer explicit flags/env, otherwise pull them from Terraform outputs.
    url = args.url or tf_output("api_invoke_url")
    key = args.key or tf_output("api_key_value")

    # --- Resolve auth mode ---------------------------------------------------------------------
    # Hardened deploys expose a cognito_client_id output; when present (and not --no-auth) we log
    # each scenario user in and send their JWT. Absent output or --no-auth => api-key-only (baseline).
    client_id = None if args.no_auth else (args.client_id or tf_output("cognito_client_id", required=False))
    # Accept either the demo-specific var or the same TF_VAR_ the deploy used, so a single
    # `export TF_VAR_demo_user_password=...` covers both `terraform apply` and this script.
    password = (os.environ.get("DEMO_USER_PASSWORD")
                or os.environ.get("TF_VAR_demo_user_password")
                or "LabDemo#Passw0rd!")
    token_cache = {}
    mode_label = "HARDENED / Cognito" if client_id else "BASELINE / unauthenticated"

    # --- Load the scenario and optionally trim it ----------------------------------------------
    with open(args.scenario) as f:
        scenario = json.load(f)
    requests = scenario["requests"]
    if not client_id and any("auth_case" in e for e in requests):
        ap.error("auth_case tests require hardened Cognito mode; do not use --no-auth")
    if args.limit:
        requests = requests[: args.limit]

    print("\nAWS AI SECURITY LAB | REPLAY")
    print(f"Scenario: {os.path.basename(args.scenario)} | Mode: {mode_label} | Requests: {len(requests)}")
    if args.verbose:
        print(f"Endpoint: {url}")
    print("-" * 77)
    print(f"{'#':>2}  {'Principal':<18} {'HTTP':<5} {'Returned':>8} {'Blocked':>8}  Outcome")
    print("-" * 77)
    # Running tallies for the end-of-run summary.
    fired = blocked_net = blocked_doc = guardrail = jwt_unauth = 0
    results = []
    failures = []
    for i, entry in enumerate(requests, 1):
        # Build the request body from only the passthrough keys present in this entry.
        body = {k: entry[k] for k in PASSTHROUGH if k in entry}
        # In hardened mode, authenticate as this entry's user (if it maps to a Cognito account) and
        # attach the JWT. Entries with no such user go tokenless -> the authorizer 401s them.
        auth_case = entry.get("auth_case")
        try:
            if auth_case:
                token = auth_test_token(auth_case, client_id, entry.get("user"),
                                        password, token_cache, args.expired_jwt_file)
            else:
                token = get_token(client_id, entry["user"], password, token_cache) if client_id and entry.get("user") else None
        except (ValueError, OSError) as exc:
            print(f"ERROR: identity test setup failed for request {i}: {exc}", file=sys.stderr)
            return 2
        status, resp = post(url, key, body, token)
        fired += 1
        expectation_key = "expected_status_hardened" if client_id else "expected_status_baseline"
        expected_status = entry.get(expectation_key)
        results.append({
            "scenario": os.path.basename(args.scenario), "index": i,
            "phase": entry.get("phase", ""), "auth_case": auth_case,
            "mode": "hardened" if client_id else "baseline",
            "http_status": status, "expected_http_status": expected_status,
            "request_id": resp.get("request_id"),
            "api_gateway_request_id": resp.get("_api_gateway_request_id"),
            "api_gateway_extended_id": resp.get("_api_gateway_extended_id"),
            "guardrail_action": resp.get("guardrail_action"),
            "model_status": resp.get("model_status"),
            "documents_blocked": [d.get("document_name") for d in resp.get("documents_blocked", [])],
            "documents_returned": [d.get("document_name") for d in resp.get("documents_returned", [])],
        })
        expected_model_status = entry.get("expected_model_status", scenario.get("expected_model_status"))
        if expected_model_status is not None:
            observed_model_status = resp.get("model_status")
            if observed_model_status != expected_model_status:
                failures.append(
                    f"request {i}: expected model_status={expected_model_status}, "
                    f"observed {observed_model_status or 'NOT_REPORTED'} (FAIL)")
        if args.assert_expected:
            if type(expected_status) is not int:
                failures.append(f"request {i}: {expectation_key} missing or invalid (INCONCLUSIVE)")
            elif status != expected_status:
                failures.append(f"request {i}: expected HTTP {expected_status}, observed {status} (FAIL)")
        phase = entry.get("phase", "")
        rid = resp.get("request_id") or resp.get("_api_gateway_request_id") or "-"
        rid_origin = "app" if resp.get("request_id") else ("gateway" if resp.get("_api_gateway_request_id") else "unavailable")
        rb = results[-1]["documents_blocked"]
        rr = results[-1]["documents_returned"]
        ga = resp.get("guardrail_action", "none")
        if status == 401:
            jwt_unauth += 1
        if status == 403:
            blocked_net += 1  # Origin of 403 requires log correlation.
        if ga == "intervened":
            guardrail += 1
        if rb:
            blocked_doc += 1
        outcome = "OBSERVED"
        if args.assert_expected:
            if type(expected_status) is not int:
                outcome = "INCONCLUSIVE"
            elif status == expected_status:
                outcome = "HTTP MATCH"
            else:
                outcome = "HTTP MISMATCH"
        if ga == "intervened":
            outcome += " / GUARDRAIL"
        principal = body.get("user") or body.get("service_account") or "-"
        print(f"{i:>2}  {principal[:18]:<18} {status:<5} {len(rr):>8} {len(rb):>8}  {outcome}")
        if args.verbose:
            print(f"      Phase: {phase or '-'} | Request ID ({rid_origin}): {rid}")
            if rr:
                print(f"      Returned: {', '.join(str(x) for x in rr)}")
            if rb:
                print(f"      Blocked:  {', '.join(str(x) for x in rb)}")
            if resp.get("model_status"):
                print(f"      Model execution: {resp['model_status']} | Guardrail: {ga}")
            if status == 401:
                print("      JWT rejected at edge; app detectors not exercised")
            elif status == 403:
                print("      HTTP 403 origin requires correlated AWS logs")
        time.sleep(args.delay)  # pace requests so the log timeline reads naturally

    # Emit observations without credential or prompt values. HTTP status alone is NOT
    # evidence that the intended Lambda, detector, or notification path executed.
    if args.results_json:
        with open(args.results_json, "w", encoding="utf-8") as output:
            json.dump({"schema_version": 1, "requests": results,
                       "http_assertion_failures": failures}, output, indent=2)
            output.write("\n")
    for failure in failures:
        print(f"ASSERTION: {failure}", file=sys.stderr)
    print("-" * 77)
    total_returned = sum(len(x["documents_returned"]) for x in results)
    total_blocked = sum(len(x["documents_blocked"]) for x in results)
    successful = sum(x["http_status"] == 200 for x in results)
    print(f"HTTP 200: {successful}/{fired} | Documents returned: {total_returned} | "
          f"Documents blocked: {total_blocked} | Guardrail: {guardrail}")
    if args.assert_expected:
        print(f"HTTP assertions: {fired - len(failures)}/{fired} matched (HTTP only)")
    else:
        print("HTTP assertions: NOT RUN (use --assert-expected)")
    if args.results_json:
        print(f"Evidence: {args.results_json}")
    if scenario.get("expected_model_status") is not None or any("expected_model_status" in e for e in requests):
        model_mismatches = [f for f in failures if "model_status=" in f]
        print(f"Model execution assertions: {'FAIL' if model_mismatches else 'PASS'} "
              f"({len(requests) - len(model_mismatches)}/{len(requests)} matched)")
    print("Control effectiveness and notification delivery require separate evidence.")
    # Run the detector check as part of this command, not as a separate manual step.
    # Scenario expectations must be explicit; no blanket assumption that every
    # request should create an alert.
    if not args.no_detection_check:
        expected = scenario.get("expected_detections")
        request_ids = {item["request_id"] for item in results if item.get("request_id")}
        if expected is None:
            print("Detections: NOT TESTED (scenario has no expected_detections contract)")
        elif not request_ids:
            print("Detections: INCONCLUSIVE (API returned no request IDs)")
        else:
            log_group = tf_output("detector_log_group", required=False)
            if not log_group:
                print("Detections: INCONCLUSIVE (no detector log group in Terraform outputs)")
            else:
                print("Checking CloudWatch findings for this replay...", flush=True)
                decision, findings, reason = check_detections(
                    log_group, request_ids, expected,
                    timeout_seconds=args.detection_timeout)
                aggregate_decision = decision
                # Defer final success message until per-request validation completes.
                if findings:
                    for finding in findings:
                        print(f"  {finding.get('detection', '?')} | request_id={finding.get('request_id', '?')}")
                # Optional strict per-request expectation: a campaign only passes if
                # each distinct request generated exactly its declared finding set.
                # The existing aggregate check alone can pass despite alerts on benign phases.
                if decision == "PASS" and any("expected_detections" in e for e in requests):
                    per_request_decision, per_request_errors = verify_per_request_detections(
                        requests, results, findings)
                    failures.extend(per_request_errors)
                    decision = per_request_decision
                    if decision == "PASS":
                        print("Per-request detection assertions: PASS")
                print(f"Detections: {decision} — {reason}"
                      + (" (per-request assertions)" if decision != aggregate_decision else ""))
                if decision in ("FAIL", "INCONCLUSIVE"):
                    failures.append(f"detection verification: {decision} — {reason}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
