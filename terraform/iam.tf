# =============================================================================
# iam.tf - Least-privilege identities for the two Lambdas (OWASP LLM06:
# Excessive Agency)
# =============================================================================
# This file provisions the IAM roles and inline policies for the chat-assistant
# Lambda and the detector Lambda. It is the "who can do what" backbone of the
# lab's security model.
#
# The lesson it teaches:
#   The incident featured service accounts with broad, long-lived access - the
#   definition of excessive agency. The fix modeled here: each Lambda ASSUMES a
#   role, so it runs on short-lived STS credentials rather than static keys, and
#   each role is scoped to exactly the resources that function needs and nothing
#   more (one model, one guardrail, one corpus, one secret, one key, one table,
#   one topic). Read each statement below asking "why is this the minimum?"

# data.aws_iam_policy_document.lambda_assume: the TRUST policy shared by both
# roles. It answers "who is allowed to become this role?" - here, only the AWS
# Lambda service. This is the front door: without an appropriate trust policy a
# role can't be assumed at all. Scoping the principal to lambda.amazonaws.com
# stops arbitrary users/services from assuming these roles.
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
# aws_iam_role.chat: the identity the customer-facing chat Lambda runs as. Every
# Bedrock call, corpus read, and secret fetch the app makes is authorized
# through THIS role, so its permission policy (below) is the primary blast-radius
# boundary if the app is ever compromised via prompt injection.
resource "aws_iam_role" "chat" {
  name               = "${local.prefix}-chat-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# data.aws_iam_policy_document.chat: the PERMISSION policy for the chat role -
# the complete list of what the chat Lambda may do. Notice every statement names
# a specific resource ARN; there are no "*" resource grants except where the AWS
# API literally forbids scoping. This is least-privilege in practice.
data "aws_iam_policy_document" "chat" {
  # Logs: write-only access to its OWN log group (scoped to the chat log group
  # ARN). It can create streams and put events but cannot read or delete logs -
  # so a compromised app can't tamper with its own audit trail.
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.chat.arn}:*"]
  }

  # InvokeModel: permission to call Bedrock - but ONLY the specific inference
  # profile and foundation-model ARNs computed in main.tf. The app cannot invoke
  # any other model in the account, capping both cost and data exposure.
  statement {
    sid       = "InvokeModelViaInferenceProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = local.bedrock_invoke_resources
  }

  # ApplyGuardrail: permission to run the prompt/response through the Bedrock
  # Guardrail. Wrapped in a dynamic block so the grant only exists when
  # controls_enabled = true - in the "vulnerable" mode there is no guardrail to
  # apply, and the policy correctly omits the permission rather than dangling a
  # grant to a non-existent resource.
  dynamic "statement" {
    for_each = var.controls_enabled ? [1] : []
    content {
      sid       = "ApplyGuardrail"
      actions   = ["bedrock:ApplyGuardrail"]
      resources = [local.guardrail_arn]
    }
  }

  # ReadCorpus: read-only S3 access to exactly the corpus bucket (list) and its
  # objects (get). No write/delete - the retrieval app can read documents but
  # cannot modify or poison the corpus. Note: this grants object read at the
  # bucket level; per-document entitlement is enforced in application logic via
  # manifest.json, which is the retrieval-layer authorization lesson.
  statement {
    sid       = "ReadCorpus"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.corpus.arn, "${aws_s3_bucket.corpus.arn}/*"]
  }

  # NOTE - deliberately absent: a secretsmanager:GetSecretValue grant. The
  # service-account secret (secrets.tf) exists to teach WHERE credentials
  # belong (the vault, not the corpus), but the handler never reads it - and a
  # role should never hold a permission its code cannot exercise. An unused
  # standing grant on the internet-facing role is exactly the LLM06
  # excessive-agency pattern this file teaches against: if prompt injection
  # ever compromises the handler, an unused grant is pure attacker capability.
  # Ship the policy that matches how the code actually calls its APIs.

  # UseKms: the decrypt path. Without this the app couldn't read the
  # KMS-encrypted S3 objects or secret even with the permissions above - KMS is
  # the independent second gate. Scoped to only the lab's single CMK, and only
  # Decrypt / GenerateDataKey (no key administration).
  statement {
    sid       = "UseKms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

# aws_iam_role_policy.chat: attaches the permission policy above to the chat
# role as an inline policy (lifecycle-bound to the role, so it can't be left
# orphaned).
resource "aws_iam_role_policy" "chat" {
  name   = "${local.prefix}-chat-policy"
  role   = aws_iam_role.chat.id
  policy = data.aws_iam_policy_document.chat.json
}

# ---------- Detector role ----------
# aws_iam_role.detector: the identity the detection/monitoring Lambda runs as.
# It is deliberately a SEPARATE role from the chat Lambda - separation of duties
# means the app that talks to users has no detector permissions, and the
# detector has no model-invoke or corpus-read permissions. Neither can be pivoted
# into the other's capabilities if compromised.
resource "aws_iam_role" "detector" {
  name               = "${local.prefix}-detector-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# data.aws_iam_policy_document.detector: the detector's permission policy -
# scoped to what a monitoring function needs: emit metrics, keep its baseline
# state, and raise alarms. Notably it has NO Bedrock, S3-corpus, or secret
# access at all.
data "aws_iam_policy_document" "detector" {
  # Logs: same write-only, own-log-group pattern as the chat role.
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }

  # PutMetricData is one of the AWS actions that does NOT support resource-level
  # ARNs, so "*" is unavoidable - but the condition constrains it to the single
  # custom namespace AIRagLab/Detections. This is the correct pattern when a
  # resource ARN can't be used: narrow the grant with a condition key instead of
  # leaving a bare "*".
  statement {
    sid       = "PublishMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData does not support resource-level scoping
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = [local.detections_namespace]
    }
  }

  # BaselineState: read/write only the one DynamoDB table that stores per-
  # principal token baselines for anomaly detection. No table create/delete, and
  # no access to any other table.
  statement {
    sid       = "BaselineState"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.baseline.arn]
  }

  # NotifyAlarms: publish to exactly the one SNS alarm topic. This is how a
  # detection becomes a notification - and it's scoped so the detector can't spam
  # arbitrary topics.
  statement {
    sid       = "NotifyAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
  }

  # UseKms: needed to publish to the KMS-encrypted SNS topic (GenerateDataKey)
  # and read any encrypted state (Decrypt). Scoped to the single lab CMK.
  statement {
    sid       = "UseKms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

# aws_iam_role_policy.detector: binds the detector permission policy to the
# detector role.
resource "aws_iam_role_policy" "detector" {
  name   = "${local.prefix}-detector-policy"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}
