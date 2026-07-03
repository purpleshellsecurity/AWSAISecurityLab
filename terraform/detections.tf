# Detection & alerting.
# The detector Lambda consumes the chat Lambda's structured logs via a subscription filter and runs
# the four detections, publishing a custom metric per detection. CloudWatch alarms on
# those metrics notify SNS. The per-principal token baseline lives in DynamoDB (rolling baseline,
# deliberately not a static threshold).

# ---------- SNS alarm topic ----------
resource "aws_sns_topic" "alarms" {
  name              = "${local.prefix}-alarms"
  kms_master_key_id = aws_kms_key.main.id
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---------- Rolling baseline state for Detection 3 ----------
resource "aws_dynamodb_table" "baseline" {
  name         = "${local.prefix}-token-baseline"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal"

  attribute {
    name = "principal"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }
}

# ---------- Detector Lambda ----------
data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../src/detector"
  output_path = "${path.module}/.build/detector.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

resource "aws_lambda_function" "detector" {
  function_name = "${local.prefix}-detector"
  role          = aws_iam_role.detector.arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256

  environment {
    variables = {
      INTERNAL_CIDRS         = join(",", var.internal_cidrs)
      BASELINE_TABLE         = aws_dynamodb_table.baseline.name
      SNS_TOPIC_ARN          = aws_sns_topic.alarms.arn
      TOKEN_DEVIATION_FACTOR = tostring(var.token_deviation_factor)
      METRIC_NAMESPACE       = "AIRagLab/Detections"
      # Service accounts that are allowed to be high-volume (Detection 3 allowlist).
      HIGH_VOLUME_ALLOWLIST = "batch-indexer"
      # Known service accounts (Detection 2). Mirrors the incident's accounts.
      SERVICE_ACCOUNTS = "enso-rag-svc,enso-vector-svc,enso-assistant-api"
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector]
}

# Stream the chat Lambda's logs to the detector.
resource "aws_lambda_permission" "logs_invoke_detector" {
  statement_id  = "AllowCWLogsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "logs.${local.region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.chat.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "chat_to_detector" {
  name            = "${local.prefix}-chat-to-detector"
  log_group_name  = aws_cloudwatch_log_group.chat.name
  filter_pattern  = "" # all events; the Lambda parses the structured JSON
  destination_arn = aws_lambda_function.detector.arn
  depends_on      = [aws_lambda_permission.logs_invoke_detector]
}

# ---------- Alarms (one per detection) ----------
locals {
  detections = {
    "service-account-external-source" = "ServiceAccountExternalSource"
    "sensitive-retrieval-anomaly"     = "SensitiveRetrievalAnomaly"
    "token-volume-deviation"          = "TokenSpike"
    "indirect-injection"              = "IndirectInjection"
  }
}

resource "aws_cloudwatch_metric_alarm" "detections" {
  for_each = local.detections

  alarm_name          = "${local.prefix}-${each.key}"
  namespace           = "AIRagLab/Detections"
  metric_name         = each.value
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_description   = "Detection fired: ${each.key}"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}
