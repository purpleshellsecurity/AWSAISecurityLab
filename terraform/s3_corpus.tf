# =============================================================================
# s3_corpus.tf - The RAG document store and its data-protection controls
# =============================================================================
# This file provisions the S3 bucket that holds the RAG corpus (the documents
# the assistant retrieves from) plus the full stack of bucket-hardening
# controls, and uploads the corpus content.
#
# The lesson it teaches:
#   In the incident, restricted documents were retrievable by the wrong users
#   and the only authorization check happened at RESPONSE time (too late - the
#   content had already been pulled). The corrected design here layers controls:
#     - the bucket is private (public access blocked four ways),
#     - encrypted at rest with the lab CMK,
#     - versioned (tamper/deletion recovery),
#     - TLS-only in transit,
#   and the classification/entitlement model ships WITH the corpus as
#   manifest.json so the Lambda can authorize each document BEFORE returning it.
# These resources cover the infrastructure half; the per-document authz is
# application logic driven by that manifest.

# aws_s3_bucket.corpus: the bucket itself. Its name embeds the account ID to be
# globally unique. force_destroy=true lets `terraform destroy` empty and remove
# it cleanly - fine for a disposable lab, but a control you would NOT enable on a
# production data bucket, where you want deletion to fail if data still exists.
resource "aws_s3_bucket" "corpus" {
  bucket        = "${local.prefix}-corpus-${local.account_id}"
  force_destroy = true
}

# aws_s3_bucket_public_access_block: the single most important S3 anti-leak
# control. All four flags = true is defense-in-depth against the classic "public
# S3 bucket" data breach - it blocks public ACLs and public bucket policies both
# at set-time (block_*) and at evaluation-time (ignore_* / restrict_*), so even
# a future misconfiguration that tries to make an object or the bucket public is
# neutralized.
resource "aws_s3_bucket_public_access_block" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  # Reject any attempt to attach a public ACL to the bucket or its objects.
  block_public_acls = true
  # Reject any bucket policy that would grant public access.
  block_public_policy = true
  # Ignore any public ACLs that somehow already exist (belt-and-suspenders).
  ignore_public_acls = true
  # Restrict access so only AWS principals (not anonymous) can reach the bucket,
  # even if a public policy slipped through.
  restrict_public_buckets = true
}

# aws_s3_bucket_server_side_encryption_configuration: encryption at rest. Forces
# every object to be encrypted with the lab's customer-managed KMS key, so
# reading corpus content requires KMS Decrypt permission on that key (the
# independent second gate discussed in kms.tf / iam.tf).
resource "aws_s3_bucket_server_side_encryption_configuration" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    apply_server_side_encryption_by_default {
      # aws:kms (not the weaker AES256/SSE-S3) so encryption is governed by our
      # auditable, rotatable CMK and its key policy.
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    # bucket_key_enabled cuts KMS API calls (and cost) by using an S3 bucket-level
    # data key, without weakening the encryption guarantee.
    bucket_key_enabled = true
  }
}

# aws_s3_bucket_versioning: keeps prior versions of every object. This is a
# data-integrity and recovery control - it protects against accidental or
# malicious overwrite/deletion (including corpus poisoning or ransomware-style
# tampering), because the previous good version can always be restored.
resource "aws_s3_bucket_versioning" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Expire superseded (noncurrent) versions after 30 days. Versioning above is the recovery control;
# this bounds its cost and data-retention tail - old copies of corpus documents (which include
# sensitive material by design) should not accumulate indefinitely.
resource "aws_s3_bucket_lifecycle_configuration" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# aws_s3_bucket_policy.corpus: enforce encryption IN TRANSIT. The public-access
# block and SSE cover the bucket's exposure and data-at-rest; this policy closes
# the in-transit gap.
resource "aws_s3_bucket_policy" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # Explicit Deny on all S3 actions whenever the connection is not TLS
      # (aws:SecureTransport = false). A Deny always overrides any Allow, so this
      # guarantees no one - not even a permitted principal - can read or write
      # corpus data over plaintext HTTP. This is a standard CIS/compliance
      # baseline control.
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.corpus.arn,
        "${aws_s3_bucket.corpus.arn}/*"
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# aws_s3_object.corpus_files: uploads every file under ../corpus (the documents
# plus manifest.json) into the bucket. The manifest is the entitlement/
# classification data that lets the app authorize retrieval per-document - the
# core corrective control from the incident.
resource "aws_s3_object" "corpus_files" {
  for_each = fileset("${path.module}/../corpus", "**")

  bucket = aws_s3_bucket.corpus.id
  key    = each.value
  source = "${path.module}/../corpus/${each.value}"
  # source_hash (not etag): with SSE-KMS the object's S3 ETag is not the content MD5, so an `etag`
  # set to filemd5() shows perpetual drift. source_hash triggers re-upload on content change without
  # comparing against the KMS-mangled ETag.
  source_hash = filemd5("${path.module}/../corpus/${each.value}")

  # Server-side encryption is enforced by the bucket default - BUT only for objects uploaded after
  # that configuration exists. Terraform is otherwise free to upload these objects in parallel with
  # (or before) the SSE/public-access-block resources on a first apply, and an object that lands
  # early keeps its weaker SSE-S3 encryption forever (it is never re-encrypted). The explicit
  # depends_on removes the race so the CMK gate genuinely covers every corpus object.
  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.corpus,
    aws_s3_bucket_public_access_block.corpus,
  ]
}
