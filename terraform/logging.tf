# Logging & audit baseline.
# The incident had no correlation ID, no per-request logging, and no audit trail. This file creates
# KMS-encrypted log groups, a CloudTrail, and Bedrock model-invocation logging.

# ---------- Log groups ----------
resource "aws_cloudwatch_log_group" "chat" {
  name              = "/aws/lambda/${local.prefix}-chat"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${local.prefix}-detector"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.prefix}-access"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_group" "bedrock_invocations" {
  name              = "/aws/bedrock/${local.prefix}-invocations"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

# ---------- CloudTrail (management + Bedrock data events) ----------
resource "aws_s3_bucket" "trail" {
  bucket        = "${local.prefix}-cloudtrail-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.trail.arn]
  }
  statement {
    sid     = "AWSCloudTrailWrite"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  # Capture Bedrock data-plane events so model invocations are auditable.
  advanced_event_selector {
    name = "Bedrock data events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Bedrock::Guardrail"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---------- Bedrock model-invocation logging ----------
data "aws_iam_policy_document" "bedrock_logging_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "bedrock_logging" {
  name               = "${local.prefix}-bedrock-logging"
  assume_role_policy = data.aws_iam_policy_document.bedrock_logging_assume.json
}

resource "aws_iam_role_policy" "bedrock_logging" {
  name = "write-logs"
  role = aws_iam_role.bedrock_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.bedrock_invocations.arn}:*"
    }]
  })
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_invocations.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
  }

  depends_on = [aws_iam_role_policy.bedrock_logging]
}
