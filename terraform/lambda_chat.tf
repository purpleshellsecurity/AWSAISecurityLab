# =============================================================================
# lambda_chat.tf — the RAG chat assistant compute layer
# =============================================================================
# The chat assistant Lambda: identity check -> retrieval-layer authorization -> Bedrock + Guardrail
# -> structured correlation log. This is where the core RAG-abuse fix lives (authorize per document
# classification BEFORE returning content).
#
# Where this fits in the lab's defense-in-depth story:
#   client -> WAF (waf.tf) -> API Gateway (api_gateway.tf) -> THIS Lambda -> Bedrock + Guardrail
#            (bedrock_guardrail.tf), with every hop emitting logs (logging.tf) that the detector
#            Lambda (detections.tf) inspects for abuse.
# The Lambda is the last place a request can be authorized against the *content* it is asking for.
# Network/API controls can stop the wrong caller from reaching the app, but only the application,
# which knows the caller's identity AND the classification of each retrieved document, can enforce
# "this principal may not read Restricted material." That per-document authorization check is the
# central remediation this lab teaches.
# -----------------------------------------------------------------------------

# Packages src/chat/ into a deployment zip at plan/apply time. Terraform hashes the archive
# (source_code_hash below) so a code change to the handler triggers a new Lambda deployment —
# important in a security lab so the running code always matches the reviewed source.
data "archive_file" "chat" {
  type        = "zip"
  source_dir  = "${path.module}/../src/chat"
  output_path = "${path.module}/.build/chat.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# The chat assistant function itself. It runs the whole request path: authenticate the caller,
# retrieve corpus documents from S3, authorize each by classification, call Bedrock with a Guardrail
# attached, and emit a structured correlation log. Its permissions come from aws_iam_role.chat
# (defined elsewhere) — least privilege here limits blast radius if the app is ever exploited.
resource "aws_lambda_function" "chat" {
  function_name = "${local.prefix}-chat"
  # The execution role is the Lambda's identity to the rest of AWS. Whatever this role can do,
  # a compromised handler can do — so it should grant only the specific S3/Bedrock actions
  # the app needs, nothing broader (see iam.tf for why there is no Secrets Manager grant).
  role    = aws_iam_role.chat.arn
  runtime = "python3.12"
  handler = "handler.lambda_handler"
  # A bounded timeout caps how long a single abusive/looping request can consume resources
  # (cost + concurrency exhaustion are real DoS vectors for LLM apps — cf. LLM04 unbounded consumption).
  timeout     = 30
  memory_size = 256

  filename = data.archive_file.chat.output_path
  # Tying the deployed artifact to the archive's hash guarantees the running function matches the
  # audited source; drift would silently ship un-reviewed code.
  source_code_hash = data.archive_file.chat.output_base64sha256

  # Configuration is injected as environment variables rather than hard-coded, so the same code
  # runs as the vulnerable baseline or the remediated build depending on CONTROLS_ENABLED.
  environment {
    variables = {
      CORPUS_BUCKET = aws_s3_bucket.corpus.id
      MODEL_ID      = var.bedrock_model_id
      # Guardrail id/version are passed in so the handler can attach the model-layer control
      # (bedrock_guardrail.tf) on every InvokeModel call. Empty when controls are disabled.
      GUARDRAIL_ID      = local.guardrail_id
      GUARDRAIL_VERSION = local.guardrail_version
      # Ranges the app treats as internal; used to flag/deny the "service account from external IP"
      # pattern at the application layer.
      INTERNAL_CIDRS = join(",", var.internal_cidrs)
      # Master toggle: false = intentionally vulnerable baseline, true = remediated. Lets students
      # A/B the same deployment against the same attacks.
      CONTROLS_ENABLED = tostring(var.controls_enabled)
    }
  }

  # Ensure the log group (with KMS encryption + retention, logging.tf) exists before the function,
  # so no logs land in an auto-created, unencrypted, never-expiring default group.
  depends_on = [aws_cloudwatch_log_group.chat]
}

# Resource-based permission that lets API Gateway (and only API Gateway) invoke this function.
# Without it the integration would get AccessDenied. The tightly-scoped source_arn is the security
# control: it restricts invocation to this specific REST API's execution ARN, so an unrelated API
# or account cannot call the function even if it learns the function name.
resource "aws_lambda_permission" "apigw_invoke_chat" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.chat.function_name
  principal     = "apigateway.amazonaws.com"
  # "/*/*" = any stage / any method on THIS api's execution ARN — scoped to this API, not "*".
  source_arn = "${aws_api_gateway_rest_api.this.execution_arn}/*/*"
}
