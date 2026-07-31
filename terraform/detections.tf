# =============================================================================
# detections.tf — the detection & alerting pipeline
# =============================================================================
# Detection & alerting.
# The detector Lambda consumes the chat Lambda's structured logs via a subscription filter and runs
# the four detections, publishing a custom metric per detection. CloudWatch alarms on
# those metrics notify SNS. The per-principal token baseline lives in DynamoDB (rolling baseline,
# deliberately not a static threshold).
#
# The full detection wiring, end to end:
#   chat log group --(subscription filter, near-real-time)--> detector Lambda --(runs 4 detections,
#   emits a custom CloudWatch metric per hit)--> CloudWatch metric alarm per detection --(alarm/ok
#   action)--> SNS topic --> email.
# This is the "detect & respond" complement to the preventive controls (WAF/Guardrail/authz). Even
# when prevention holds, these detections surface abuse attempts so a human is alerted. The four
# detections map to the incident's attack patterns (external service-account use, sensitive-doc
# access anomalies, token-volume spikes, and indirect/RAG-borne injection).
# -----------------------------------------------------------------------------

# ---------- SNS alarm topic ----------
# The notification hub every detection alarm publishes to. KMS-encrypted because alarm payloads can
# contain principal names / request context you don't want readable by anyone with topic access.
resource "aws_sns_topic" "alarms" {
  name              = "${local.prefix}-alarms"
  kms_master_key_id = aws_kms_key.main.id
}

# Optional email subscriber. count = 0 when no address is configured, so the pipeline still stands
# up headless (metrics/alarms fire) without a dangling unconfirmed subscription.
resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---------- Rolling baseline state for Detection 3 ----------
# Stores each principal's rolling token-usage baseline. Using a learned per-principal baseline
# (rather than one global static threshold) is the whole point: it flags a caller deviating from
# ITS OWN normal, catching low-and-slow abuse a fixed number would miss and cutting false positives
# for legitimately high-volume accounts.
resource "aws_dynamodb_table" "baseline" {
  name         = "${local.prefix}-token-baseline"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal" # one baseline row per calling principal

  attribute {
    name = "principal"
    type = "S"
  }

  # Customer-managed KMS encryption at rest: the baseline reveals per-principal usage patterns, so
  # it's treated as sensitive like the logs.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }
}

# ---------- Detector Lambda ----------
# Packages src/detector/ into its deployment zip (same hash-based redeploy pattern as the chat fn).
data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../src/detector"
  output_path = "${path.module}/.build/detector.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# The detector function: invoked by CloudWatch Logs on every chat log batch, it parses the structured
# events, runs the four detections, and emits a custom metric per detection hit. Its role
# (aws_iam_role.detector) grants only what it needs: read the baseline table, put metrics, publish SNS.
resource "aws_lambda_function" "detector" {
  function_name = "${local.prefix}-detector"
  role          = aws_iam_role.detector.arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256

  # Detection tuning/config passed in as env vars so behavior can change without editing code.
  environment {
    variables = {
      # Ranges considered internal — Detection 1 flags a known service account seen from outside these.
      INTERNAL_CIDRS         = join(",", var.internal_cidrs)
      BASELINE_TABLE         = aws_dynamodb_table.baseline.name
      SNS_TOPIC_ARN          = aws_sns_topic.alarms.arn
      # How many times over its own baseline a principal's token usage must jump to trip Detection 3.
      TOKEN_DEVIATION_FACTOR = tostring(var.token_deviation_factor)
      METRIC_NAMESPACE       = "AIRagLab/Detections"
      # Service accounts that are allowed to be high-volume (Detection 3 allowlist).
      # Prevents the legitimate bulk indexer from constantly tripping the token-spike detection.
      HIGH_VOLUME_ALLOWLIST = "batch-indexer"
      # Known service accounts (Detection 2). Mirrors the incident's accounts.
      # Detection keys on these identities to spot misuse of a real service account.
      SERVICE_ACCOUNTS = "enso-rag-svc,enso-vector-svc,enso-assistant-api"
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector]
}

# Stream the chat Lambda's logs to the detector.
# Resource permission allowing CloudWatch Logs (this region only) to invoke the detector. Scoped to
# the chat log group ARN so only that log group — not an arbitrary caller — can trigger the function.
resource "aws_lambda_permission" "logs_invoke_detector" {
  statement_id  = "AllowCWLogsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "logs.${local.region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.chat.arn}:*"
}

# The subscription filter that pushes chat log events to the detector in near-real-time — this is
# what makes detection continuous rather than a periodic scan.
resource "aws_cloudwatch_log_subscription_filter" "chat_to_detector" {
  name            = "${local.prefix}-chat-to-detector"
  log_group_name  = aws_cloudwatch_log_group.chat.name
  filter_pattern  = "" # all events; the Lambda parses the structured JSON
  destination_arn = aws_lambda_function.detector.arn
  depends_on      = [aws_lambda_permission.logs_invoke_detector]
}

# ---------- Alarms (one per detection) ----------
# Maps each detection's alarm-name suffix to the CloudWatch metric name the detector emits. Driving
# the alarms from this map (for_each below) keeps the metric contract between the Lambda and the
# alarms in one place — add a detection here + in the Lambda and the alarm is created automatically.
locals {
  detections = {
    "service-account-external-source" = "ServiceAccountExternalSource" # Detection 1: known svc acct from external IP
    "sensitive-retrieval-anomaly"     = "SensitiveRetrievalAnomaly"    # Detection 2: unusual access to sensitive docs
    "token-volume-deviation"          = "TokenSpike"                   # Detection 3: token usage above learned baseline
    "indirect-injection"              = "IndirectInjection"            # Detection 4: injection payload found in retrieved content
  }
}

# One alarm per detection metric. Because the detector only publishes a metric when a detection
# actually fires, the alarm is intentionally hair-trigger: any single occurrence should page a human.
resource "aws_cloudwatch_metric_alarm" "detections" {
  for_each = local.detections

  alarm_name          = "${local.prefix}-${each.key}"
  namespace           = "AIRagLab/Detections"
  metric_name         = each.value
  statistic           = "Sum"       # count occurrences in the window
  period              = 60          # 60s evaluation window — fast alerting
  evaluation_periods  = 1           # alarm on the first breaching window (no waiting for a trend)
  threshold           = 1           # >= 1 detection event = alarm; these are high-signal events
  comparison_operator = "GreaterThanOrEqualToThreshold"
  # No data = no detections = healthy; don't alarm on the (normal) absence of hits.
  treat_missing_data  = "notBreaching"
  alarm_description   = "Detection fired: ${each.key}"
  alarm_actions       = [aws_sns_topic.alarms.arn] # notify on ALARM
  ok_actions          = [aws_sns_topic.alarms.arn] # also notify on return-to-OK, closing the loop
}
