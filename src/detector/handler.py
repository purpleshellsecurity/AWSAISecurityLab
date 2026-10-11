"""
Detection Lambda — implements three detections over the chat assistant's structured logs.

Triggered by a CloudWatch Logs subscription filter on the chat log group. For each request log it:
  Sensitive retrieval anomaly                        (High)
  Indirect prompt injection / RAG poisoning          (High)
  Per-principal token-volume deviation               (Medium, rolling baseline in DynamoDB)

Each firing publishes a custom metric (drives the CloudWatch alarms -> SNS) and a detailed SNS alert.
"""

# --- Imports --------------------------------------------------------------------------------------
import base64  # CloudWatch Logs delivers the payload base64-encoded
import gzip     # ...and gzip-compressed; we decompress it below
import json     # parse each log record and serialize findings
import hashlib
import time
import uuid
from botocore.exceptions import ClientError
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


def conditional_failure(error):
    return isinstance(error, ClientError) and error.response["Error"]["Code"] in {
        "ConditionalCheckFailedException", "TransactionCanceledException"
    }


def receipt_key(event_id, kind):
    """Stable, bounded DynamoDB partition key. The source event ID is supplied by CloudWatch."""
    return "evt#" + hashlib.sha256(f"{event_id}:{kind}".encode()).hexdigest()


def create_receipt(key):
    try:
        ddb.put_item(
            TableName=BASELINE_TABLE,
            Item={
                "principal": {"S": key},
                "metric_state": {"S": "pending"},
                "sns_state": {"S": "pending"},
                "expires_at": {"N": str(int(time.time()) + 7 * 86400)},
            },
            ConditionExpression="attribute_not_exists(principal)",
        )
        return True
    except ClientError as error:
        if conditional_failure(error):
            return False
        raise


def deliver_once(key, target, fn):
    """Claim one sink with a lease; successful sinks are not sent twice on event replay.

    The call to an external service cannot be atomic with DynamoDB. If the Lambda
    crashes after publishing and before acknowledging the claim, a later delivery
    after the lease expires may republish. Delivery is at-least-once, not exactly-once.
    """
    state = f"{target}_state"
    lease = f"{target}_lease"
    owner = f"{target}_owner"
    now = int(time.time())
    mine = str(uuid.uuid4())
    try:
        ddb.update_item(
            TableName=BASELINE_TABLE, Key={"principal": {"S": key}},
            UpdateExpression="SET #state = :inflight, #lease = :until, #owner = :mine",
            ConditionExpression="#state = :pending OR (#state = :inflight AND #lease < :now)",
            ExpressionAttributeNames={"#state": state, "#lease": lease, "#owner": owner},
            ExpressionAttributeValues={
                ":pending": {"S": "pending"}, ":inflight": {"S": "inflight"},
                ":until": {"N": str(now + 90)}, ":now": {"N": str(now)},
                ":mine": {"S": mine},
            },
        )
    except ClientError as error:
        if conditional_failure(error):
            return False
        raise
    try:
        fn()
    except Exception:
        ddb.update_item(
            TableName=BASELINE_TABLE, Key={"principal": {"S": key}},
            UpdateExpression="SET #state = :pending",
            ConditionExpression="#owner = :mine",
            ExpressionAttributeNames={"#state": state, "#owner": owner},
            ExpressionAttributeValues={":pending": {"S": "pending"}, ":mine": {"S": mine}},
        )
        raise
    ddb.update_item(
        TableName=BASELINE_TABLE, Key={"principal": {"S": key}},
        UpdateExpression="SET #state = :done",
        ConditionExpression="#owner = :mine",
        ExpressionAttributeNames={"#state": state, "#owner": owner},
        ExpressionAttributeValues={":done": {"S": "done"}, ":mine": {"S": mine}},
    )
    return True


def alert(detection, severity, detail, event_id=None):
    """Durable per-finding receipt and independent delivery state for metric and SNS.

    Re-delivered events only retry sinks still pending; receipt records expire after
    seven days. Full delivery recovery still requires event replay or a sweeper.
    """
    finding = {"detection": detection, "severity": severity, **detail}
    key = receipt_key(event_id, detection) if event_id else None
    if key:
        created = create_receipt(key)
        if created:
            print(json.dumps({"event": "detection", **finding}))
    else:
        print(json.dumps({"event": "detection", **finding}))
    metric = {
        "sensitive-retrieval-anomaly": "SensitiveRetrievalAnomaly",
        "token-volume-deviation": "TokenSpike",
        "indirect-injection": "IndirectInjection",
    }[detection]
    failed_targets = []
    for target, send in (
        ("metric", lambda: emit(metric)),
        ("sns", lambda: sns.publish(
            TopicArn=SNS_TOPIC_ARN, Subject=f"[{severity}] {detection}"[:100],
            Message=json.dumps(finding, indent=2))),
    ):
        try:
            if key:
                deliver_once(key, target, send)
            else:
                send()
        except Exception as error:
            print(json.dumps({
                "event": "delivery_error", "target": target, "detection": detection,
                "request_id": detail.get("request_id"), "error": type(error).__name__,
                "retry_required": True,
            }))
            failed_targets.append(target)
    if failed_targets:
        raise RuntimeError("Finding delivery incomplete: " + ",".join(failed_targets))
    if key:
        # A concurrent invocation may see the sink lease held by another worker.
        # That is NOT success: if the first worker fails, retry must remain eligible.
        receipt = ddb.get_item(
            TableName=BASELINE_TABLE,
            Key={"principal": {"S": key}},
            ConsistentRead=True,
        ).get("Item", {})
        if any(receipt.get(f"{target}_state", {}).get("S") != "done"
               for target in ("metric", "sns")):
            raise RuntimeError("Finding delivery incomplete: sink pending or leased")


# --- DynamoDB baseline store (for the token-volume detection) -------------------------------------
def get_baseline(principal):
    """Return the stored rolling token baseline for a principal, or None if we've never seen it."""
    resp = ddb.get_item(TableName=BASELINE_TABLE, Key={"principal": {"S": principal}})
    item = resp.get("Item")
    return float(item["baseline"]["N"]) if item else None


def put_baseline(principal, value):
    """Persist a principal's baseline value (DynamoDB stores numbers as strings)."""
    ddb.put_item(TableName=BASELINE_TABLE, Item={"principal": {"S": principal}, "baseline": {"N": str(value)}})


# --- Detection 1: sensitive document actually reached a user --------------------------------------
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
    }, event_id=rec.get("_event_id"))


# --- Detection 2: indirect prompt injection / RAG poisoning ---------------------------------------
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
        }, event_id=rec.get("_event_id"))


# --- Detection 3: per-principal token-volume deviation --------------------------------------------
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
        # (No `endpoint` field here: this detection reads the chat-layer record, which doesn't carry
        # one — only the api_access record does. request_id is the join key back to that layer.)
        alert("token-volume-deviation", "Medium", {
            "principal": principal,
            "tokens_used": tokens,
            "baseline": round(baseline, 1),
            "factor": FACTOR,
            "request_id": rec.get("request_id"),
        })
        return  # don't let the spike pollute the baseline
    # Normal request: fold it into the baseline with an EWMA so the baseline tracks slow drift while
    # resisting single-request swings.
    put_baseline(principal, EWMA_ALPHA * tokens + (1 - EWMA_ALPHA) * baseline)


# --- Durable, optimistic EWMA processing ----------------------------------------
def process_token_event(rec, event_id):
    principal = rec.get("principal")
    tokens = rec.get("tokens_used") or 0
    if not principal or principal in HIGH_VOLUME_ALLOWLIST or tokens <= 0:
        return
    key = receipt_key(event_id, "token-baseline")
    for attempt in range(5):
        resp = ddb.get_item(
            TableName=BASELINE_TABLE, Key={"principal": {"S": principal}},
            ConsistentRead=True,
        )
        baseline = float(resp["Item"]["baseline"]["N"]) if resp.get("Item") else None
        spike = baseline is not None and tokens > FACTOR * baseline
        ops = [{
            "Put": {
                "TableName": BASELINE_TABLE,
                "Item": {
                    "principal": {"S": key},
                    "expires_at": {"N": str(int(time.time()) + 7 * 86400)},
                    **({"spike_baseline": {"N": str(baseline)}} if spike else {}),
                },
                "ConditionExpression": "attribute_not_exists(principal)",
            }
        }]
        if baseline is None:
            ops.append({"Update": {
                "TableName": BASELINE_TABLE,
                "Key": {"principal": {"S": principal}},
                "UpdateExpression": "SET baseline = :value",
                "ConditionExpression": "attribute_not_exists(baseline)",
                "ExpressionAttributeValues": {":value": {"N": str(tokens)}},
            }})
        elif spike:
            ops.append({"ConditionCheck": {
                "TableName": BASELINE_TABLE,
                "Key": {"principal": {"S": principal}},
                "ConditionExpression": "baseline = :prior",
                "ExpressionAttributeValues": {":prior": {"N": str(baseline)}},
            }})
        else:
            value = EWMA_ALPHA * tokens + (1 - EWMA_ALPHA) * baseline
            ops.append({"Update": {
                "TableName": BASELINE_TABLE,
                "Key": {"principal": {"S": principal}},
                "UpdateExpression": "SET baseline = :value",
                "ConditionExpression": "baseline = :prior",
                "ExpressionAttributeValues": {
                    ":value": {"N": str(value)}, ":prior": {"N": str(baseline)}
                },
            }})
        try:
            ddb.transact_write_items(TransactItems=ops)
        except ClientError as error:
            if not conditional_failure(error):
                raise
            # A transaction can be canceled for reasons other than optimistic
            # contention (e.g. validation or capacity). Do not swallow those.
            reasons = error.response.get("CancellationReasons") or []
            if any(reason.get("Code") not in ("None", "ConditionalCheckFailed")
                   for reason in reasons):
                raise
            duplicate = ddb.get_item(
                TableName=BASELINE_TABLE, Key={"principal": {"S": key}},
                ConsistentRead=True,
            )
            if duplicate.get("Item"):
                # A previously processed spike may still need pending sink delivery.
                if "spike_baseline" in duplicate["Item"]:
                    spike_baseline = float(duplicate["Item"]["spike_baseline"]["N"])
                    alert("token-volume-deviation", "Medium", {
                        "principal": principal, "tokens_used": tokens,
                        "baseline": round(spike_baseline, 1), "factor": FACTOR,
                        "request_id": rec.get("request_id"),
                    }, event_id=event_id)
                return
            continue
        if spike:
            # Decision and event receipt were committed atomically in the transaction.
            alert("token-volume-deviation", "Medium", {
                "principal": principal, "tokens_used": tokens,
                "baseline": round(baseline, 1), "factor": FACTOR,
                "request_id": rec.get("request_id"),
            }, event_id=event_id)
        return
    raise RuntimeError("Token baseline contention exceeded retry budget")


# --- Entry point -----------------------------------------------------------------
def lambda_handler(event, context):
    payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    errors = 0
    for log_event in payload.get("logEvents", []):
        try:
            rec = json.loads(log_event["message"])
        except (json.JSONDecodeError, KeyError):
            continue
        log_type = rec.get("log_type")
        try:
            if log_type not in {"retrieval", "chat"}:
                continue
            event_id = log_event.get("id")
            if not event_id:
                # Fail visibly. Production subscription events include a stable event ID;
                # synthetic tests must supply one to exercise replay protection.
                raise ValueError("Missing CloudWatch log event ID")
            rec["_event_id"] = event_id
            if log_type == "retrieval":
                detection_sensitive_retrieval(rec)
                detection_indirect_injection(rec)
            else:
                process_token_event(rec, event_id)
        except Exception as error:
            print(json.dumps({
                "event": "detection_error", "log_type": log_type,
                "request_id": rec.get("request_id"), "error": type(error).__name__,
            }))
            errors += 1
    if errors:
        # The whole batch may be retried by Lambda async invocation, while
        # durable receipts suppress sinks and baselines that already succeeded.
        raise RuntimeError(f"Detector batch incomplete: {errors} record(s) failed")
    return {"processed": len(payload.get("logEvents", []))}
