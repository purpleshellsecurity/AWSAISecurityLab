#!/usr/bin/env python3
"""Independently correlate JWT replay with API Gateway and chat Lambda logs.

Run after Terraform deploy of enhanced access-log format and a fresh
08_jwt_boundary replay. This verifier never reads or emits JWTs.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def terraform_output(name):
    proc = subprocess.run(
        ["terraform", f"-chdir={ROOT / 'terraform'}", "output", "-raw", name],
        capture_output=True, text=True, check=False)
    if proc.returncode or not proc.stdout.strip():
        raise RuntimeError(f"Terraform output unavailable: {name}")
    return proc.stdout.strip()


def fetch_records(group, request_id, region):
    # CloudWatch JSON filter for exact equality; never build shell command strings.
    pattern = "{ $.request_id = " + json.dumps(request_id) + " }"
    proc = subprocess.run(
        ["aws", "logs", "filter-log-events", "--log-group-name", group,
         "--filter-pattern", pattern, "--region", region, "--output", "json"],
        capture_output=True, text=True, check=False)
    if proc.returncode:
        raise RuntimeError(f"CloudWatch query failed for {group}: {proc.stderr.strip()[:250]}")
    try:
        events = json.loads(proc.stdout).get("events", [])
        return [json.loads(e["message"]) for e in events]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"Malformed CloudWatch response for {group}") from exc


def stage_schema_active(region):
    """Verify active REST API stage format, independently from historical log rows."""
    url = terraform_output("api_invoke_url")
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    api_id = host.split(".")[0]
    if not api_id or not host.endswith(".execute-api." + region + ".amazonaws.com"):
        raise RuntimeError("Cannot resolve REST API ID from deployed invoke URL")
    proc = subprocess.run(
        ["aws", "apigateway", "get-stage", "--rest-api-id", api_id,
         "--stage-name", "prod", "--region", region,
         "--query", "accessLogSettings.format", "--output", "text"],
        capture_output=True, text=True, check=False)
    if proc.returncode:
        raise RuntimeError("Cannot read deployed API Gateway stage logging format: " + proc.stderr.strip()[:250])
    try:
        fields = json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("API Gateway stage format is not JSON") from exc
    return all(name in fields for name in ("gateway_error_type", "gateway_error", "integration_status"))


def is_blank(value):
    return value is None or str(value).strip() in ("", "-")


def classify(cases, gateway, chat):
    """Explicitly separate HTTP assertions, integration boundary, and likely JWT cause."""
    decisions = []
    for row in cases:
        case = row["auth_case"]
        if case not in ("missing", "malformed", "tampered", "valid"):
            continue
        gid = row.get("api_gateway_request_id")
        if not gid:
            decisions.append((case, "INCONCLUSIVE", "Missing API Gateway request ID"))
            continue
        logs = gateway.get(gid, [])
        if len(logs) != 1:
            decisions.append((case, "INCONCLUSIVE", f"Expected one gateway event; observed {len(logs)}"))
            continue
        log = logs[0]
        if any(k not in log for k in ("gateway_error_type", "integration_status", "gateway_error")):
            decisions.append((case, "INCONCLUSIVE", "Historical gateway event lacks enhanced fields; stage may already be updated. Generate new replay after checking active stage schema"))
            continue
        try:
            status = int(log.get("status", -1))
        except (ValueError, TypeError):
            status = -1
        if status != row["http_status"]:
            decisions.append((case, "FAIL", "Gateway status disagrees with replay"))
            continue
        lambda_logs = chat.get(gid, [])
        if case == "valid":
            if status != 200 or not row.get("request_id") or not lambda_logs:
                decisions.append((case, "INCONCLUSIVE", "Positive control lacks correlated Lambda evidence"))
            else:
                decisions.append((case, "PASS", "Valid signed JWT reached Lambda and returned 200"))
        elif case == "tampered":
            if status != 403:
                decisions.append((case, "FAIL", "Unexpected tampered-token HTTP result"))
            elif not is_blank(log.get("integration_status")) or lambda_logs:
                decisions.append((case, "FAIL", "Tampered JWT appears to have reached integration"))
            elif is_blank(log.get("gateway_error")) and is_blank(log.get("gateway_error_type")):
                decisions.append((case, "INCONCLUSIVE", "Pre-integration deny observed, but no gateway error diagnostic"))
            else:
                decisions.append((case, "PASS", "Signature-tampered token rejected before integration; valid-token positive control required"))
        else:
            if status != 401 or not is_blank(log.get("integration_status")) or lambda_logs:
                decisions.append((case, "FAIL", "Expected pre-integration 401 rejection was not established"))
            else:
                decisions.append((case, "PASS", "401 rejected before integration"))
    # A passing tampered case requires the valid signed counterpart.
    if not any(c == "valid" and d == "PASS" for c, d, _ in decisions):
        decisions = [(c, "INCONCLUSIVE" if c == "tampered" and d == "PASS" else d,
                      "Cannot attribute to JWT without verified signed-token positive control"
                      if c == "tampered" and d == "PASS" else reason)
                     for c, d, reason in decisions]
    return decisions


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-json", required=True, help="Output of replay JWT boundary scenario")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--timeout", type=int, default=45, help="CloudWatch ingestion wait (seconds)")
    args = parser.parse_args(argv)
    evidence = json.loads(Path(args.results_json).read_text())
    cases = evidence.get("requests", [])
    if {r.get("auth_case") for r in cases} != {"missing", "malformed", "tampered", "valid"}:
        parser.error("Expected four JWT boundary cases in replay results")
    if evidence.get("http_assertion_failures"):
        print("FAIL: replay HTTP assertions failed", file=sys.stderr)
        return 1
    if not stage_schema_active(args.region):
        print("INCONCLUSIVE: current API Gateway stage does not expose required diagnostic fields", file=sys.stderr)
        return 1
    gateway_group = terraform_output("apigw_access_log_group")
    chat_group = terraform_output("chat_log_group")
    deadline = time.monotonic() + max(0, args.timeout)
    while True:
        gateway = {}
        chat = {}
        for row in cases:
            gid = row.get("api_gateway_request_id")
            if not gid:
                continue
            gateway[gid] = fetch_records(gateway_group, gid, args.region)
            chat[gid] = fetch_records(chat_group, gid, args.region)
        decisions = classify(cases, gateway, chat)
        # Poll only for unavailable evidence; fail/passed conditions are not subject to ingestion.
        if all(d == "PASS" for _, d, _ in decisions) or time.monotonic() >= deadline:
            break
        time.sleep(3)
    print("JWT GATEWAY ATTRIBUTION | independent CloudWatch verification")
    for case, decision, reason in decisions:
        print(f"{case:<12} {decision:<12} {reason}")
    print("Note: PASS is differential evidence of pre-integration rejection, not cryptographic proof from AWS internals.")
    return 0 if len(decisions) == 4 and all(d == "PASS" for _, d, _ in decisions) else 1


if __name__ == "__main__":
    sys.exit(main())
