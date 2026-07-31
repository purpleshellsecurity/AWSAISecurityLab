"""
Detection Lambda — implements the four detections over the chat assistant's structured logs.

Triggered by a CloudWatch Logs subscription filter on the chat log group. For each request log it:
  Service account from a non-internal source        (High)
  Sensitive retrieval anomaly                        (High)
  Indirect prompt injection / RAG poisoning          (High)
  Per-principal token-volume deviation               (Medium, rolling baseline in DynamoDB)

Each firing publishes a custom metric (drives the CloudWatch alarms -> SNS) and a detailed SNS alert.
"""

# --- Imports --------------------------------------------------------------------------------------
import base64  # CloudWatch Logs delivers the payload base64-encoded
import gzip     # ...and gzip-compressed; we decompress it below
import json     # parse each log record and serialize findings
import os        # read configuration from environment variables
import boto3     # AWS SDK: CloudWatch metrics, SNS alerts, DynamoDB baseline store

# --- AWS clients (reused across warm invocations) -------------------------------------------------
cw = boto3.client("cloudwatch")   # publishes the custom detection metrics that drive the alarms
sns = boto3.client("sns")          # sends the human-readable alert for each finding
ddb = boto3.client("dynamodb")     # stores the rolling per-principal token baseline

# --- Configuration (injected by Terraform) --------------------------------------------------------
NAMESPACE = os.environ.get("METRIC_NAMESPACE", "AIRagLab/Detections")  # CloudWatch metric namespace
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]   # topic the alerts are published to (required)
BASELINE_TABLE = os.environ["BASELINE_TABLE"]  # DynamoDB table holding per-principal baselines (required)
# How many times over baseline a request's token count must be before it's flagged (default 10x).
FACTOR = float(os.environ.get("TOKEN_DEVIATION_FACTOR", "10"))
# The set of identities that are service accounts — used by the external-source detection. Only these
# should ever call the API, and only from inside the network.
SERVICE_ACCOUNTS = {s.strip() for s in os.environ.get("SERVICE_ACCOUNTS", "").split(",") if s.strip()}
# Principals exempt from the token-volume detection (e.g. known batch/reporting jobs that legitimately
# use large token volumes and would otherwise generate false positives).
HIGH_VOLUME_ALLOWLIST = {s.strip() for s in os.environ.get("HIGH_VOLUME_ALLOWLIST", "").split(",") if s.strip()}
# Classifications considered sensitive for the retrieval-anomaly detection.
SENSITIVE = {"Restricted", "Confidential"}
# EWMA smoothing factor for updating the baseline: weight on the newest observation vs. history.
EWMA_ALPHA = 0.3


# --- Alerting primitives --------------------------------------------------------------------------
def emit(metric):
    """Publish a single count of the named custom metric. The CloudWatch alarms watch these metrics
    and fan out to SNS, so emitting the metric is what ultimately trips an alarm."""
    cw.put_metric_data(
        Namespace=NAMESPACE,
        MetricData=[{"MetricName": metric, "Value": 1, "Unit": "Count"}],
    )


def alert(detection, severity, detail):
    """Record one finding three ways: (1) a structured log line for correlation/audit, (2) the custom
    metric that drives its alarm, and (3) a human-readable SNS notification."""
    finding = {"detection": detection, "severity": severity, **detail}
    # (1) Structured log line — searchable and joinable back to the request by request_id.
    print(json.dumps({"event": "detection", **finding}))
    # (2) Map the detection slug to its CloudWatch metric name and emit it.
    emit({
        "service-account-external-source": "ServiceAccountExternalSource",
        "sensitive-retrieval-anomaly": "SensitiveRetrievalAnomaly",
        "token-volume-deviation": "TokenSpike",
        "indirect-injection": "IndirectInjection",
    }[detection])
    # (3) Publish the full finding to SNS (subject is capped at 100 chars, the SNS limit).
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{severity}] {detection}"[:100],
        Message=json.dumps(finding, indent=2),
    )


# --- DynamoDB baseline store (for the token-volume detection) -------------------------------------
def get_baseline(principal):
    """Return the stored rolling token baseline for a principal, or None if we've never seen it."""
    resp = ddb.get_item(TableName=BASELINE_TABLE, Key={"principal": {"S": principal}})
    item = resp.get("Item")
    return float(item["baseline"]["N"]) if item else None


def put_baseline(principal, value):
    """Persist a principal's baseline value (DynamoDB stores numbers as strings)."""
    ddb.put_item(TableName=BASELINE_TABLE, Item={"principal": {"S": principal}, "baseline": {"N": str(value)}})


# --- Detection 1: service account calling from outside the network --------------------------------
def detection_service_account_external(rec):
    # Reads the api_access layer log.
    # A service account should only ever be used by internal automation. Seeing one authenticate from
    # a non-internal source is the signature of stolen credentials being replayed externally — exactly
    # the incident's initial access. Fire High.
    if rec.get("service_account") in SERVICE_ACCOUNTS and rec.get("internal_source") is False:
        alert("service-account-external-source", "High", {
            "service_account": rec.get("service_account"),
            "source_ip": rec.get("source_ip"),
            "endpoint": rec.get("endpoint"),
            "tokens_used": rec.get("tokens_used"),
            "request_id": rec.get("request_id"),
        })


# --- Detection 2: sensitive document actually reached a user --------------------------------------
def detection_sensitive_retrieval(rec):
    # Reads the retrieval layer log (one record per document). Only fire when a sensitive document
    # actually REACHED the model/user — not when it was blocked or quarantined. Alerting on a doc the
    # controls already stopped is noise (an attempt, not an exposure), so we exclude
    # blocked_unauthorized / quarantined_injection.
    if rec.get("sensitivity") not in SENSITIVE:
        return  # not a sensitive doc — nothing to consider
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


# --- Detection 3: indirect prompt injection / RAG poisoning ---------------------------------------
def detection_indirect_injection(rec):
    # Reads the retrieval layer log. Fires when a retrieved document contained injection markers
    # (indirect prompt injection / RAG poisoning) — whether it was quarantined (controls on) or
    # leaked to the model (controls off). Either way, poisoned content in the corpus is worth an alert
    # so responders can find and clean the source document.
    if rec.get("injection_in_document"):
        alert("indirect-injection", "High", {
            "user": rec.get("user"),
            "session_id": rec.get("session_id"),
            "document_name": rec.get("document_name"),
            "action": rec.get("action"),
            "request_id": rec.get("request_id"),
        })


# --- Detection 4: per-principal token-volume deviation --------------------------------------------
def detection_token_deviation(rec):
    # Reads the chat layer log. Compares this request's token usage to a rolling per-principal baseline;
    # a sudden spike can indicate bulk data exfiltration or abuse. Baseline is kept in DynamoDB.
    principal = rec.get("principal")
    tokens = rec.get("tokens_used") or 0
    # Skip principals we can't attribute, allow-listed high-volume jobs, and zero-token requests.
    if not principal or principal in HIGH_VOLUME_ALLOWLIST or tokens <= 0:
        return
    baseline = get_baseline(principal)
    if baseline is None:
        put_baseline(principal, tokens)  # cold start: seed, no alert
        return
    if tokens > FACTOR * baseline:
        # Spike detected — flag Medium and DON'T update the baseline (see below).
        alert("token-volume-deviation", "Medium", {
            "principal": principal,
            "tokens_used": tokens,
            "baseline": round(baseline, 1),
            "factor": FACTOR,
            "endpoint": rec.get("endpoint"),
            "request_id": rec.get("request_id"),
        })
        return  # don't let the spike pollute the baseline
    # Normal request: fold it into the baseline with an EWMA so the baseline tracks slow drift while
    # resisting single-request swings.
    put_baseline(principal, EWMA_ALPHA * tokens + (1 - EWMA_ALPHA) * baseline)


# --- Entry point ----------------------------------------------------------------------------------
def lambda_handler(event, context):
    # CloudWatch Logs subscription payload is base64-encoded, gzip-compressed JSON — decode/decompress
    # it back into the batch of log events.
    payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    for log_event in payload.get("logEvents", []):
        # Each message is one structured log line emitted by the chat Lambda. Skip anything that isn't
        # parseable JSON rather than failing the whole batch.
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
    # Return the count so the invocation's success/size is visible in Lambda metrics/logs.
    return {"processed": len(payload.get("logEvents", []))}
