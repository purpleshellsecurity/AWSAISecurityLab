# Least-privilege IAM (OWASP LLM06).
# The incident showed service accounts with broad, long-lived access. Here each Lambda assumes a
# role (short-lived STS creds) scoped to exactly the resources it needs: one Bedrock model, one
# guardrail, one corpus prefix, one secret.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------- Chat assistant role ----------
resource "aws_iam_role" "chat" {
  name               = "${local.prefix}-chat-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "chat" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.chat.arn}:*"]
  }

  statement {
    sid       = "InvokeModelViaInferenceProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = local.bedrock_invoke_resources
  }

  # Guardrail permission only exists when controls are enabled.
  dynamic "statement" {
    for_each = var.controls_enabled ? [1] : []
    content {
      sid       = "ApplyGuardrail"
      actions   = ["bedrock:ApplyGuardrail"]
      resources = [local.guardrail_arn]
    }
  }

  statement {
    sid       = "ReadCorpus"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.corpus.arn, "${aws_s3_bucket.corpus.arn}/*"]
  }

  statement {
    sid       = "ReadServiceSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.svc_creds.arn]
  }

  statement {
    sid       = "UseKms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "chat" {
  name   = "${local.prefix}-chat-policy"
  role   = aws_iam_role.chat.id
  policy = data.aws_iam_policy_document.chat.json
}

# ---------- Detector role ----------
resource "aws_iam_role" "detector" {
  name               = "${local.prefix}-detector-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "detector" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }

  statement {
    sid       = "PublishMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData does not support resource-level scoping
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["AIRagLab/Detections"]
    }
  }

  statement {
    sid       = "BaselineState"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.baseline.arn]
  }

  statement {
    sid       = "NotifyAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
  }

  statement {
    sid       = "UseKms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "detector" {
  name   = "${local.prefix}-detector-policy"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}
