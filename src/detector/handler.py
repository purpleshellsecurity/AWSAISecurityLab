"""
Detection Lambda — implements the four detections over the chat assistant's structured logs.

Triggered by a CloudWatch Logs subscription filter on the chat log group. For each request log it:
  Service account from a non-internal source        (High)
  Sensitive retrieval anomaly                        (High)
  Indirect prompt injection / RAG poisoning          (High)
  Per-principal token-volume deviation               (Medium, rolling baseline in DynamoDB)

Each firing publishes a custom metric (drives the CloudWatch alarms -> SNS) and a detailed SNS alert.
"""

import base64
import gzip
import json
import os
import boto3

cw = boto3.client("cloudwatch")
sns = boto3.client("sns")
ddb = boto3.client("dynamodb")

NAMESPACE = os.environ.get("METRIC_NAMESPACE", "AIRagLab/Detections")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
BASELINE_TABLE = os.environ["BASELINE_TABLE"]
FACTOR = float(os.environ.get("TOKEN_DEVIATION_FACTOR", "10"))
SERVICE_ACCOUNTS = {s.strip() for s in os.environ.get("SERVICE_ACCOUNTS", "").split(",") if s.strip()}
HIGH_VOLUME_ALLOWLIST = {s.strip() for s in os.environ.get("HIGH_VOLUME_ALLOWLIST", "").split(",") if s.strip()}
SENSITIVE = {"Restricted", "Confidential"}
EWMA_ALPHA = 0.3


def emit(metric):
    cw.put_metric_data(
        Namespace=NAMESPACE,
        MetricData=[{"MetricName": metric, "Value": 1, "Unit": "Count"}],
    )


def alert(detection, severity, detail):
    finding = {"detection": detection, "severity": severity, **detail}
    print(json.dumps({"event": "detection", **finding}))
    emit({
        "service-account-external-source": "ServiceAccountExternalSource",
        "sensitive-retrieval-anomaly": "SensitiveRetrievalAnomaly",
        "token-volume-deviation": "TokenSpike",
        "indirect-injection": "IndirectInjection",
    }[detection])
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{severity}] {detection}"[:100],
        Message=json.dumps(finding, indent=2),
    )


def get_baseline(principal):
    resp = ddb.get_item(TableName=BASELINE_TABLE, Key={"principal": {"S": principal}})
    item = resp.get("Item")
    return float(item["baseline"]["N"]) if item else None


def put_baseline(principal, value):
    ddb.put_item(TableName=BASELINE_TABLE, Item={"principal": {"S": principal}, "baseline": {"N": str(value)}})


def detection_service_account_external(rec):
    # Reads the api_access layer log.
    if rec.get("service_account") in SERVICE_ACCOUNTS and rec.get("internal_source") is False:
        alert("service-account-external-source", "High", {
            "service_account": rec.get("service_account"),
            "source_ip": rec.get("source_ip"),
            "endpoint": rec.get("endpoint"),
            "tokens_used": rec.get("tokens_used"),
            "request_id": rec.get("request_id"),
        })


def detection_sensitive_retrieval(rec):
    # Reads the retrieval layer log (one record per document). Only fire when a sensitive document
    # actually REACHED the model/user — not when it was blocked or quarantined. Alerting on a doc the
    # controls already stopped is noise (an attempt, not an exposure), so we exclude
    # blocked_unauthorized / quarantined_injection.
    if rec.get("sensitivity") not in SENSITIVE:
        return
    action = rec.get("action")
    if action == "leaked_unauthorized":
        pass  # an unauthorized user actually received a sensitive doc — always an alert
    elif action == "retrieved" and rec.get("high_risk_prompt"):
        pass  # an authorized retrieval, but in a session whose prompt was flagged high-risk
    else:
        return  # blocked / quarantined / benign retrieval — nothing to alert on
    alert("sensitive-retrieval-anomaly", "High", {
        "user": rec.get("user"),
        "session_id": rec.get("session_id"),
        "document_name": rec.get("document_name"),
        "sensitivity": rec.get("sensitivity"),
        "retrieval_score": rec.get("retrieval_score"),
        "action": rec.get("action"),
        "high_risk_prompt": rec.get("high_risk_prompt"),
        "request_id": rec.get("request_id"),
    })


def detection_indirect_injection(rec):
    # Reads the retrieval layer log. Fires when a retrieved document contained injection markers
    # (indirect prompt injection / RAG poisoning) — whether it was quarantined (controls on) or
    # leaked to the model (controls off).
    if rec.get("injection_in_document"):
        alert("indirect-injection", "High", {
            "user": rec.get("user"),
            "session_id": rec.get("session_id"),
            "document_name": rec.get("document_name"),
            "action": rec.get("action"),
            "request_id": rec.get("request_id"),
        })


def detection_token_deviation(rec):
    principal = rec.get("principal")
    tokens = rec.get("tokens_used") or 0
    if not principal or principal in HIGH_VOLUME_ALLOWLIST or tokens <= 0:
        return
    baseline = get_baseline(principal)
    if baseline is None:
        put_baseline(principal, tokens)  # cold start: seed, no alert
        return
    if tokens > FACTOR * baseline:
        alert("token-volume-deviation", "Medium", {
            "principal": principal,
            "tokens_used": tokens,
            "baseline": round(baseline, 1),
            "factor": FACTOR,
            "endpoint": rec.get("endpoint"),
            "request_id": rec.get("request_id"),
        })
        return  # don't let the spike pollute the baseline
    put_baseline(principal, EWMA_ALPHA * tokens + (1 - EWMA_ALPHA) * baseline)


def lambda_handler(event, context):
    payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    for log_event in payload.get("logEvents", []):
        try:
            rec = json.loads(log_event["message"])
        except (json.JSONDecodeError, KeyError):
            continue
        # Route each correlated layer record to the detection that consumes it.
        log_type = rec.get("log_type")
        if log_type == "api_access":
            detection_service_account_external(rec)
        elif log_type == "retrieval":
            detection_sensitive_retrieval(rec)
            detection_indirect_injection(rec)
        elif log_type == "chat":
            detection_token_deviation(rec)
    return {"processed": len(payload.get("logEvents", []))}
