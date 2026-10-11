#!/usr/bin/env python3
"""Read-only, request-correlated SOC evidence report. AWS CLI credentials required.

Finding logs, CloudWatch metric samples, alarm transitions, and SNS subscriber
delivery are distinct evidence classes. This script DOES NOT assert SNS delivery.
"""
import argparse
import datetime as dt
import json
import subprocess
import sys
import time

METRICS = {
    "indirect-injection": "IndirectInjection",
    "token-volume-deviation": "TokenSpike",
    "sensitive-retrieval-anomaly": "SensitiveRetrievalAnomaly",
    "service-account-external-source": "ServiceAccountExternalSource",
}


def aws(*args):
    call = subprocess.run(["aws", *args, "--region", "us-east-1", "--output", "json"],
                          capture_output=True, text=True)
    if call.returncode:
        raise RuntimeError("AWS command failed: " + call.stderr.strip()[:350])
    return json.loads(call.stdout)


def terraform_output(name):
    call = subprocess.run(
        ["terraform", "-chdir=terraform", "output", "-raw", name],
        capture_output=True,
        text=True,
    )
    if call.returncode:
        raise RuntimeError(
            "Terraform output unavailable for " + name + ": " + call.stderr.strip()[:350]
        )
    return call.stdout.strip()


def log_events(group, begin, end, pattern):
    all_records, token = [], None
    while True:
        args = ["logs", "filter-log-events", "--log-group-name", group,
                "--start-time", str(begin), "--end-time", str(end),
                "--filter-pattern", pattern]
        if token:
            args += ["--next-token", token]
        output = aws(*args)
        for event in output.get("events", []):
            try:
                record = json.loads(event["message"])
            except (ValueError, KeyError, TypeError):
                continue
            record["_log_timestamp_ms"] = event.get("timestamp")
            all_records.append(record)
        next_token = output.get("nextToken")
        if not next_token or next_token == token:
            break
        token = next_token
    return all_records


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results-json", required=True, help="replay.py --results-json file")
    p.add_argument("--detection", required=True, choices=sorted(METRICS))
    p.add_argument("--minutes", type=int, default=30, help="CloudWatch search window (default 30)")
    args = p.parse_args()
    if args.minutes < 1:
        p.error("--minutes must be positive")
    with open(args.results_json, encoding="utf-8") as f:
        replay = json.load(f)
    requests = replay.get("requests", [])
    ids = {r["request_id"] for r in requests if r.get("request_id")}
    if not ids:
        print("INCONCLUSIVE: no application request IDs in replay evidence")
        return 2

    end = int(time.time() * 1000)
    begin = end - args.minutes * 60000
    chat_group = terraform_output("chat_log_group")
    detector_group = terraform_output("detector_log_group")
    metric_namespace = terraform_output("detector_metric_namespace")
    alarm_prefix = terraform_output("detection_alarm_prefix")
    chat = log_events(chat_group, begin, end,
                      '{ $.log_type = "chat" || $.log_type = "retrieval" || $.log_type = "api_access" }')
    detector = log_events(detector_group, begin, end,
                          '{ $.event = "detection" || $.event = "delivery_error" || $.event = "detection_error" }')
    source = [r for r in chat if r.get("request_id") in ids]
    findings = [r for r in detector
                if r.get("event") == "detection" and r.get("request_id") in ids
                and r.get("detection") == args.detection]
    errors = [r for r in detector if r.get("event") in ("delivery_error", "detection_error")
              and (r.get("request_id") in ids or r.get("detection") == args.detection)]
    metric = METRICS[args.detection]
    # Query the metric as an independent measurement. Data may lag the logs.
    start_iso = dt.datetime.fromtimestamp(begin / 1000, tz=dt.timezone.utc).isoformat()
    end_iso = dt.datetime.fromtimestamp(end / 1000, tz=dt.timezone.utc).isoformat()
    samples = aws("cloudwatch", "get-metric-statistics", "--namespace", metric_namespace,
                  "--metric-name", metric, "--start-time", start_iso, "--end-time", end_iso,
                  "--period", "60", "--statistics", "Sum").get("Datapoints", [])
    # Alarm history is not specific to a request. Report state changes, never
    # claim individual finding delivery based on an ALARM transition.
    history = aws("cloudwatch", "describe-alarm-history",
                  "--alarm-name", alarm_prefix + "-" + args.detection,
                  "--history-item-type", "StateUpdate",
                  "--start-date", start_iso, "--end-date", end_iso).get("AlarmHistoryItems", [])
    report = {
        "detection": args.detection,
        "metric_namespace": metric_namespace,
        "alarm_prefix": alarm_prefix,
        "request_ids": sorted(ids),
        "source_events": [{"request_id": x.get("request_id"), "log_type": x.get("log_type"),
                           "action": x.get("action"), "sensitivity": x.get("sensitivity"),
                           "injection_in_document": x.get("injection_in_document"),
                           "high_risk_prompt": x.get("high_risk_prompt"),
                           "service_account": x.get("service_account"),
                           "internal_source": x.get("internal_source"),
                           "tokens_used": x.get("tokens_used")} for x in source],
        "correlated_findings": findings,
        "delivery_or_processing_errors": errors,
        "metric_sum_window": sum(float(x.get("Sum", 0)) for x in samples),
        "alarm_state_changes_in_window": len(history),
        "sns_endpoint_delivery": "NOT VERIFIED — check subscription and recipient independently",
        "finding_decision": "OBSERVED" if findings else "NOT OBSERVED (check timeframe/predicate)",
        "metric_decision": "OBSERVED (window, not request-attributed)" if samples else "NOT OBSERVED",
    }
    print(json.dumps(report, indent=2, default=str))
    return 0 if findings else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print("INCONCLUSIVE:", exc, file=sys.stderr)
        sys.exit(2)
