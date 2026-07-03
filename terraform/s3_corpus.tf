# RAG document store. In the incident, restricted docs were retrievable by the wrong users and
# the only check happened at response time. Here the bucket is private + KMS-encrypted, and the
# classification/entitlement model travels with the corpus (manifest.json) so the Lambda can
# authorize per document BEFORE returning content.

resource "aws_s3_bucket" "corpus" {
  bucket        = "${local.prefix}-corpus-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "corpus" {
  bucket                  = aws_s3_bucket.corpus.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Deny any non-TLS access to the corpus.
resource "aws_s3_bucket_policy" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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

# Upload every file in ../corpus (documents + manifest.json) into the bucket.
resource "aws_s3_object" "corpus_files" {
  for_each = fileset("${path.module}/../corpus", "**")

  bucket = aws_s3_bucket.corpus.id
  key    = each.value
  source = "${path.module}/../corpus/${each.value}"
  # source_hash (not etag): with SSE-KMS the object's S3 ETag is not the content MD5, so an `etag`
  # set to filemd5() shows perpetual drift. source_hash triggers re-upload on content change without
  # comparing against the KMS-mangled ETag.
  source_hash = filemd5("${path.module}/../corpus/${each.value}")

  # Note: server-side encryption is enforced by the bucket default above.
}
