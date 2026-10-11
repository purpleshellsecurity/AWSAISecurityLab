# =============================================================================
# logging.tf — the audit & observability foundation
# =============================================================================
# Logging & audit baseline.
# The incident had no correlation ID, no per-request logging, and no audit trail. This file creates
# KMS-encrypted log groups, a CloudTrail, and Bedrock model-invocation logging.
#
# Three complementary layers of evidence:
#   1. CloudWatch log groups — the application/request logs (chat, detector, API access, Bedrock I/O)
#      that the detector Lambda (detections.tf) consumes and that investigators query.
#   2. CloudTrail — the AWS control-plane/data-plane audit trail (who called which AWS API).
#   3. Bedrock model-invocation logging — the actual prompts/completions, for LLM abuse forensics.
# Everything is KMS-encrypted and retention-bounded so logs are both confidential and don't grow
# without limit. Good logging is a security control in its own right: you cannot detect or
# investigate what you never recorded.
# -----------------------------------------------------------------------------

# ---------- Log groups ----------
# All four groups follow the same secure pattern: 30-day retention (bounds storage cost + limits how
# long sensitive log data lingers) and customer-managed KMS encryption (aws_kms_key.main). Creating
# them explicitly — rather than letting Lambda/API GW auto-create them — is what guarantees the
# encryption and retention; auto-created groups default to never-expire and AWS-owned keys.

# Chat Lambda logs: the structured correlation records that carry request_id + principal + retrieval
# decisions. This is the source stream the detector subscribes to (see detections.tf).
resource "aws_cloudwatch_log_group" "chat" {
  name              = "/aws/lambda/${local.prefix}-chat"
  retention_in_days = 30                   # bounded retention: cost + data-minimization
  kms_key_id        = aws_kms_key.main.arn # encrypt logs at rest with a customer-managed key
}

# Detector Lambda logs: its own execution/diagnostic output (useful when a detection misfires).
resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${local.prefix}-detector"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

# API Gateway access logs: the per-request "who/from where/what/outcome" line (format defined in
# api_gateway.tf). The API-layer half of the end-to-end trace.
resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.prefix}-access"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

# Bedrock model-invocation logs: the raw prompt/response text (populated by the config at the bottom
# of this file). Critical for LLM forensics — lets you see exactly what a suspected injection sent.
resource "aws_cloudwatch_log_group" "bedrock_invocations" {
  name              = "/aws/bedrock/${local.prefix}-invocations"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

# ---------- CloudTrail (management + Bedrock data events) ----------
# Destination bucket for CloudTrail log files. force_destroy = true is a LAB convenience (lets
# `terraform destroy` empty and delete it); in production you would retain and lock these logs.
resource "aws_s3_bucket" "trail" {
  bucket        = "${local.prefix}-cloudtrail-${local.account_id}"
  force_destroy = true
}

# Encrypt delivered trail objects with the lab CMK by default (the trail also sets kms_key_id, so
# log files are SSE-KMS end to end). The audit trail is the record an attacker most wants to read
# or tamper with — it gets the same CMK boundary as every other data store in the lab, not the
# weaker SSE-S3 default it would otherwise land under.
resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

# Versioning on the audit bucket: tamper-evidence for the evidence. An overwrite or delete of a
# trail object leaves the prior version recoverable — complementing the trail's own digest-file
# validation below.
resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bounded retention, mirroring the 30-day cap on the log groups: the lab's log stores should not
# grow without limit (cost + data minimization). 90 days of trail history is plenty for lab
# forensics; production audit trails typically retain far longer (often to Glacier).
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire-trail-objects"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Belt-and-suspenders public-access block: guarantees the audit log bucket can never be exposed
# publicly via ACL or bucket policy — audit logs are exactly what an attacker would want to read/delete.
resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# The exact bucket policy CloudTrail requires to deliver logs — scoped to the CloudTrail service
# principal only, and only to this account's log prefix. This is the standard least-privilege grant
# that lets the service write while keeping everyone else out.
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
    # Restrict writes to this account's log path only.
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    # Require the canonical ACL so the bucket owner retains full control of delivered objects.
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

# The trail itself. Records AWS API activity to the bucket above. log_file_validation gives you
# tamper-evidence (digest files) so you can prove logs weren't altered — essential for audit integrity.
resource "aws_cloudtrail" "main" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false # single-region: lab scope; prod audit trails are usually multi-region
  enable_log_file_validation    = true  # tamper-evident digest files
  # Encrypt delivered log files with the lab CMK (requires the AllowCloudTrailEncrypt statement in
  # the key policy, kms.tf). Reading the audit trail then needs kms:Decrypt on the CMK — the same
  # independent second gate that protects the corpus.
  kms_key_id = aws_kms_key.main.arn

  # GOTCHA worth knowing: when ANY advanced_event_selector is used, management events are only
  # recorded if a selector explicitly asks for them. A trail with only a Data selector records no
  # control-plane activity at all — "who changed IAM / read the secret" would be silently absent.
  # So the trail declares BOTH selectors:

  # Management events: the control-plane audit record (who called which AWS API — IAM changes,
  # secret reads, KMS grants). This is the half investigators reach for first.
  advanced_event_selector {
    name = "Management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # Bedrock DATA events (opt-in, extra cost): the actual resource-level operations — here, use of
  # the Guardrail — giving an audit record of guardrail activity to correlate with the invocation
  # logs below.
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
# Trust policy letting the Bedrock service assume the logging role (service principal only).
data "aws_iam_policy_document" "bedrock_logging_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
  }
}

# Role Bedrock assumes to deliver prompt/response logs to CloudWatch.
resource "aws_iam_role" "bedrock_logging" {
  name               = "${local.prefix}-bedrock-logging"
  assume_role_policy = data.aws_iam_policy_document.bedrock_logging_assume.json
}

# Least-privilege inline policy: only the two log-write actions, scoped to the single Bedrock log
# group. Bedrock can write invocation logs and nothing else.
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

# Account-level config that turns on model-invocation logging. This captures the actual model I/O —
# the ground truth for investigating prompt injection / data-leak attempts.
#
# BLAST-RADIUS WARNING: this is a per-account/per-region SINGLETON, like aws_api_gateway_account.
# Applying it ADOPTS (and overwrites) any invocation-logging config the account already had, and
# `terraform destroy` REMOVES it — turning off Bedrock invocation logging for everything else in
# this account/region. Fine in a dedicated lab account; in a shared account, check what exists
# before deploying and re-enable the original config after teardown.
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  count = var.manage_account_region_singletons ? 1 : 0

  logging_config {
    # Log text prompts/completions only. Embeddings and images are disabled to minimize the volume
    # and sensitivity of captured data (data minimization) — text is what matters for LLM abuse review.
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_invocations.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
  }

  # The role's write permission must exist before Bedrock is told to log, or delivery fails.
  depends_on = [aws_iam_role_policy.bedrock_logging]
}
