# =============================================================================
# kms.tf - The customer-managed encryption key (CMK) for the whole lab
# =============================================================================
# This file provisions one KMS Customer-Managed Key and a friendly alias. That
# single key encrypts-at-rest the RAG corpus (S3), CloudWatch logs, the SNS
# alarm topic, and the service-account secret. It addresses the incident's "no
# encryption/audit baseline" gap.
#
# Why a CUSTOMER-managed key (CMK) instead of the default AWS-managed key?
#   - You control and can audit the key policy (who may use it), enable
#     automatic annual rotation, and revoke access by editing one policy.
#   - The key policy is a second, independent authorization layer: even a
#     principal with S3 or Secrets permissions cannot read the plaintext unless
#     the KMS key policy (or a grant) also lets them Decrypt. This is
#     defense-in-depth for data confidentiality.

# aws_kms_key.main: the CMK itself. Its "policy" is the root of trust for every
# encrypted resource in the lab - it defines exactly which principals and AWS
# services may use the key, and for what.
resource "aws_kms_key" "main" {
  description = "${local.prefix} CMK for corpus, logs, secrets"
  # A short deletion window means a destroyed key is only pending-deletion for 7
  # days (min allowed is 7). Long enough to recover from an accidental destroy,
  # short enough for a disposable lab. In production you often want the full 30.
  deletion_window_in_days = 7
  # Automatic yearly key rotation. AWS generates new cryptographic material
  # while keeping the same key ID, so old ciphertext stays readable. Rotating
  # limits the amount of data protected by any single key version - a core
  # key-management best practice and a common compliance requirement.
  enable_key_rotation = true

  # The KEY POLICY is the primary access control for a KMS key. Unlike most AWS
  # resources, a key's own policy - not just IAM - governs who can use it. Each
  # statement below deliberately grants the narrowest access each consumer needs.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Statement 1: give the account root full administrative control of the
        # key. This is the AWS-recommended baseline that prevents you from
        # locking yourself out of your own key and lets IAM policies delegate
        # key usage. It grants management of the key, not a blanket data-read
        # path for application roles (those are scoped separately in iam.tf).
        Sid       = "EnableRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # Statement 2: let the CloudWatch Logs service in THIS region use the
        # key so log groups can be encrypted at rest.
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        # The Condition is the important least-privilege control here: it
        # confines the Logs service to using this key ONLY for log groups in
        # this account/region (the encryption-context ArnLike check). Without
        # it, the "logs" service principal could be lured into using the key for
        # a log group in another account - the "confused deputy" problem.
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"
          }
        }
      },
      {
        # Statement 3: allow SNS to encrypt the alarm topic and decrypt to
        # deliver notifications. Scoped to only the two actions SNS needs -
        # GenerateDataKey to encrypt a published message, Decrypt to send it.
        Sid       = "AllowSNS"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        # Same confused-deputy control as the Logs statement above: the SNS
        # service may only use this key on behalf of THIS account, so a topic in
        # another account can't be pointed at our CMK.
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        # Statement 4: allow the CloudWatch ALARMS service to publish to the
        # KMS-encrypted SNS topic. This is distinct from CloudWatch Logs
        # (statement 2) and easy to miss: alarm actions are executed by the
        # cloudwatch.amazonaws.com service principal, which must be able to
        # generate a data key against the topic's CMK or every alarm -> SNS
        # delivery fails SILENTLY (the alarm still changes state in-console,
        # the notification just never sends). A guardrail that can't be seen
        # firing is unverifiable - the delivery path needs this grant.
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        # Statement 5: allow CloudTrail to encrypt the audit-trail log files it
        # delivers (logging.tf sets kms_key_id on the trail). The encryption-
        # context condition confines the grant to trails in this account - the
        # same confused-deputy pattern as the Logs statement.
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      }
    ]
  })
}

# aws_kms_alias.main: a human-friendly, stable name (alias/ai-rag-lab...) that
# points at the key. Aliases matter operationally - resources and people can
# reference the alias while the underlying key can be rotated/replaced, and a
# stable alias makes audit logs far easier to read than raw key UUIDs.
resource "aws_kms_alias" "main" {
  name          = "alias/${local.prefix}"
  target_key_id = aws_kms_key.main.key_id
}
